"""PostgreSQL 定时备份：pg_dump 落盘 + 保留期清理。

设计：
- 仅 DB_TYPE=postgres 时启用；SQLite 部署直接跳过（文件型数据库复制文件即可）。
- 连接参数解析自 DATABASE_URL（postgresql://user:pass@host:port/dbname），
  密码经 PGPASSWORD 环境变量传给 pg_dump，不出现在命令行参数里。
- pg_dump 优先取 PATH；找不到时探测 Windows 常见安装路径
  （C:\\Program Files\\PostgreSQL\\<ver>\\bin\\pg_dump.exe）。
- 输出 plain SQL（可用 psql 直接恢复），文件名 backups/db_backup_YYYYMMDD_HHMMSS.sql。
- 保留期：清理 keep_days 天前的备份文件（仅删除 backups 目录内匹配
  db_backup_*.sql 的文件，best-effort，删除失败只记日志）。
- 调度：daemon 线程每小时检查一次，到达配置的 hour 点（默认凌晨 3 点）
  且当天尚未备份时执行；服务启动时若当天从未备份过则立即补跑一次。

恢复：
    psql "postgresql://user:pass@host:5432/dbname" -f backups/db_backup_XXX.sql
（恢复到空库时先 createdb；大库建议先 DROP 再建。）

config.yaml:
    db_backup:
      enabled: true
      hour: 3          # 每天几点备份（服务器本地时间）
      keep_days: 14    # 备份保留天数
      dir: backups     # 备份输出目录（相对项目根）
"""
import logging
import os
import subprocess
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

from . import configs

logger = logging.getLogger(__name__)

_marker_day = {'day': None}   # 当天已备份标记（进程内）


def _find_pg_dump() -> str | None:
    """定位 pg_dump 可执行文件。"""
    import shutil
    found = shutil.which('pg_dump')
    if found:
        return found
    # Windows 常见安装路径（含 PG 13~18）
    for ver in (18, 17, 16, 15, 14, 13):
        cand = rf"C:\Program Files\PostgreSQL\{ver}\bin\pg_dump.exe"
        if os.path.isfile(cand):
            return cand
    return None


def _parse_db_url(url: str) -> dict:
    """解析 DATABASE_URL -> {host, port, user, password, dbname}（组件做 URL 解码）。"""
    from urllib.parse import unquote
    u = urlparse(url)
    return {
        'host': unquote(u.hostname or '') or '127.0.0.1',
        'port': u.port or 5432,
        'user': unquote(u.username or ''),
        'password': unquote(u.password or ''),
        'dbname': unquote((u.path or '').lstrip('/')) or 'postgres',
    }


def run_backup(backup_dir: str = None, keep_days: int = None) -> str:
    """执行一次备份，返回备份文件路径；失败抛异常。"""
    if (getattr(configs, 'DB_TYPE', 'sqlite') or 'sqlite').lower() != 'postgres':
        raise RuntimeError('db_backup 仅支持 postgres 后端（当前 DB_TYPE 非 postgres）')
    cfg = getattr(configs, 'DB_BACKUP', {}) or {}
    backup_dir = backup_dir or cfg.get('dir') or 'backups'
    keep_days = keep_days if keep_days is not None else int(cfg.get('keep_days', 14))

    pg_dump = _find_pg_dump()
    if not pg_dump:
        raise RuntimeError('未找到 pg_dump（PATH 与常见安装路径均无），请安装 PostgreSQL 客户端工具')

    url = getattr(configs, 'DATABASE_URL', '') or ''
    if not url:
        raise RuntimeError('DATABASE_URL 未配置，无法解析备份目标')
    conn = _parse_db_url(url)

    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), backup_dir)
    os.makedirs(base_dir, exist_ok=True)
    out_path = os.path.join(base_dir, f"db_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql")

    env = dict(os.environ)
    if conn['password']:
        env['PGPASSWORD'] = conn['password']

    cmd = [
        pg_dump,
        '-h', conn['host'], '-p', str(conn['port']),
        '-U', conn['user'],
        '-d', conn['dbname'],
        '--no-owner', '--no-privileges',
        '-f', out_path,
    ]
    t0 = time.time()
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=1800)
    if result.returncode != 0:
        raise RuntimeError(f"pg_dump 失败 (rc={result.returncode}): {result.stderr[:500]}")
    size = os.path.getsize(out_path) if os.path.isfile(out_path) else 0
    if size == 0:
        raise RuntimeError('pg_dump 退出码为 0 但输出文件为空')
    logger.info(f"db_backup 完成: {out_path} ({size / 1024:.1f} KB, "
                f"{time.time() - t0:.1f}s)")

    _cleanup_old(base_dir, keep_days)
    return out_path


def _cleanup_old(base_dir: str, keep_days: int):
    """删除 keep_days 天前的备份文件（best-effort）。"""
    if keep_days <= 0:
        return
    cutoff = time.time() - keep_days * 86400
    removed = 0
    try:
        for name in os.listdir(base_dir):
            if not (name.startswith('db_backup_') and name.endswith('.sql')):
                continue
            path = os.path.join(base_dir, name)
            try:
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    removed += 1
            except OSError as e:
                logger.warning(f"db_backup 清理失败 {name}: {e}")
    except OSError as e:
        logger.warning(f"db_backup 清理扫描失败: {e}")
    if removed:
        logger.info(f"db_backup 清理: 删除 {removed} 个过期备份（>{keep_days} 天）")


def _loop():
    """每小时检查一次；到点且当天未备份则执行；启动时当天从未备份则补跑。

    enabled / hour 每轮重读 configs.DB_BACKUP（管理端 WebUI 保存即热生效）。
    """
    while True:
        now = datetime.now()
        today = now.strftime('%Y-%m-%d')
        try:
            cfg = getattr(configs, 'DB_BACKUP', {}) or {}
            if not cfg.get('enabled', True):
                time.sleep(3600)
                continue
            hour = max(0, min(23, int(cfg.get('hour', 3))))
            base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    cfg.get('dir') or 'backups')
            has_today = False
            if os.path.isdir(base_dir):
                for name in os.listdir(base_dir):
                    if name.startswith(f"db_backup_{now.strftime('%Y%m%d')}") and name.endswith('.sql'):
                        has_today = True
                        break
            if not has_today and (now.hour >= hour or _marker_day['day'] is None):
                logger.info(f"db_backup 触发（hour={hour}）")
                try:
                    run_backup()
                    _marker_day['day'] = today
                except Exception as e:
                    logger.error(f"db_backup 执行失败: {e}")
        except Exception as e:
            logger.error(f"db_backup 调度异常: {e}")
        time.sleep(3600)


def start_backup_loop():
    """拉起备份调度线程（幂等；仅 postgres 后端）。

    enabled=false 时线程照常拉起但每轮检查会跳过——这样管理端 WebUI
    把 enabled 打开后无需重启即可在下一个整点检查生效。
    """
    if (getattr(configs, 'DB_TYPE', 'sqlite') or 'sqlite').lower() != 'postgres':
        logger.info("db_backup skipped: DB_TYPE is not postgres")
        return
    cfg = getattr(configs, 'DB_BACKUP', {}) or {}
    threading.Thread(target=_loop, daemon=True, name='DBBackup').start()
    logger.info(f"db_backup scheduler started (enabled={bool(cfg.get('enabled', True))}, "
                f"daily at {cfg.get('hour', 3)}:00, keep {cfg.get('keep_days', 14)} days)")
