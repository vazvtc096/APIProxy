"""日志保留策略：usage_logs / audit_log 定期归档清理，防表无限膨胀。

设计（对齐 pg_backup 的调度模式）：
- daemon 线程每小时检查一次，到达配置的 hour 点（默认凌晨 4 点）且当天
  尚未执行时批量删除 N 天前的旧日志；启动时当天从未执行过则补跑一次。
- 分批删除（默认每批 5000 行，循环到清完或达到单表单天上限），避免大事务
  长时间锁表影响在线请求。
- enabled / days / hour 每轮重读 configs.RETENTION（管理端 WebUI 保存即热生效）。
- 表与时间列：usage_logs.created_at、audit_log.created_at（均为 TIMESTAMP）。

config.yaml:
    retention:
      enabled: true
      hour: 4            # 每天几点执行（服务器本地时间）
      usage_days: 90     # usage_logs 保留天数（0 = 不清理）
      audit_days: 180    # audit_log 保留天数（0 = 不清理）
      batch: 5000        # 单批删除行数
"""
import logging
import threading
import time
from datetime import datetime

from . import db
from . import configs

logger = logging.getLogger(__name__)

_marker_day = {'day': None}   # 当天已执行标记（进程内）


def _cleanup_table(table: str, days: int, batch: int, max_rows: int = 200000) -> int:
    """分批删除 table 中 days 天前的行，返回删除总行数。

    用 id IN (SELECT ... LIMIT batch) 子查询兼容 SQLite 与 PG
    （PG 不支持 DELETE ... LIMIT）；时间条件用 datetime('now', ?)——
    db 抽象层在 PG 上自动翻译为 CURRENT_TIMESTAMP ± interval，SQLite 原生支持。
    """
    if days <= 0:
        return 0
    total = 0
    modifier = f'-{int(days)} days'
    while total < max_rows:
        conn = db.get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    f"DELETE FROM {table} WHERE id IN "
                    f"(SELECT id FROM {table} WHERE created_at < datetime('now', ?) LIMIT ?)",
                    (modifier, int(batch)))
                conn.commit()
                deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        except Exception as e:
            logger.error(f"retention cleanup {table} failed: {e}")
            return total
        finally:
            try:
                conn.close()
            except Exception:
                pass
        total += deleted
        if deleted < batch:
            break
    return total


def run_cleanup(cfg: dict = None) -> dict:
    """执行一轮清理，返回 {table: deleted_rows}。cfg 缺省读 configs.RETENTION。"""
    cfg = cfg or getattr(configs, 'RETENTION', {}) or {}
    batch = max(100, int(cfg.get('batch', 5000)))
    result = {}
    for table, key in (('usage_logs', 'usage_days'), ('audit_log', 'audit_days')):
        days = int(cfg.get(key, 0))
        if days > 0:
            n = _cleanup_table(table, days, batch)
            result[table] = n
            if n:
                logger.info(f"retention: {table} 清理 {n} 行（>{days} 天）")
    return result


def _loop():
    """每小时检查一次；到点且当天未执行则清理；启动当天从未执行则补跑。"""
    while True:
        try:
            cfg = getattr(configs, 'RETENTION', {}) or {}
            if cfg.get('enabled', True):
                now = datetime.now()
                hour = max(0, min(23, int(cfg.get('hour', 4))))
                if now.hour >= hour or _marker_day['day'] is None:
                    run_cleanup(cfg)
                    _marker_day['day'] = now.strftime('%Y-%m-%d')
        except Exception as e:
            logger.error(f"retention 调度异常: {e}")
        time.sleep(3600)


def start_retention_loop():
    """拉起日志清理调度线程（幂等；enabled=false 时线程空转，WebUI 打开即热生效）。"""
    cfg = getattr(configs, 'RETENTION', {}) or {}
    threading.Thread(target=_loop, daemon=True, name='LogRetention').start()
    logger.info(f"retention scheduler started (enabled={bool(cfg.get('enabled', True))}, "
                f"daily at {cfg.get('hour', 4)}:00, usage {cfg.get('usage_days', 90)}d, "
                f"audit {cfg.get('audit_days', 180)}d)")
