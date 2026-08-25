"""日志审计服务器（统一审计收口 + 查询 / 导出）。

定位：全站安全与合规事件的「统一收口」。其他子系统（WAF/IDS、上网行为管理、
堡垒机、认证服务器）产生的审计事件统一写入 audit_log 表，本模块负责：
  - 存储：audit_log(...) 写入（支持集群内 Worker→LB 转发）。
  - 查询：按分类/类型/严重度/IP/用户/时间窗过滤。
  - 导出：JSON / CSV。
  - 外发（可选）：syslog(UDP) 或 HTTPS(SIEM)，由 AUDIT_SYSLOG_TARGET 配置。
  - 保留：AUDIT_RETENTION_DAYS 到期清理（audit_prune）。

与堡垒机关系：堡垒机把特权操作同时写入自身表，并调用本模块 audit_log() 做
统一收口，使「日志审计服务器」成为单一可信审计源。

注意：写入走 async_db_query（兼容 sqlite / postgres）。节点间转发仅当
AUDIT_FORWARD_TO_LB 且本节点为 Worker 时生效，目标为 LB 的 /internal/audit。
"""
import json
import logging
import socket
import urllib.request

from . import configs
from .core_db import async_db_query

logger = logging.getLogger(__name__)


# ============================================================================
# 配置读取
# ============================================================================
def _enabled() -> bool:
    return bool(getattr(configs, "AUDIT_ENABLED", True))


def _retention_days() -> int:
    return int(getattr(configs, "AUDIT_RETENTION_DAYS", 90))


def _forward_to_lb() -> bool:
    return bool(getattr(configs, "AUDIT_FORWARD_TO_LB", False))


def _syslog_target() -> str:
    return str(getattr(configs, "AUDIT_SYSLOG_TARGET", "") or "")


def _node_id() -> str:
    try:
        from .cluster import NODE_ID_HEX
        return NODE_ID_HEX
    except Exception:
        return "local"


# ============================================================================
# 写入
# ============================================================================
async def audit_log(category: str, event_type: str, severity: str,
                    details: str, user_uid: str = "", user_name: str = "",
                    client_ip: str = "", node_id: str = "") -> None:
    """写入一条统一审计事件。

    category: 子系统（waf / ids / web_filter / bastion / auth / system …）
    event_type: 具体事件名
    severity: low / medium / high / critical
    """
    if not _enabled():
        return
    try:
        nid = node_id or _node_id()
        await async_db_query(
            "INSERT INTO audit_log "
            "(category, event_type, severity, user_uid, user_name, client_ip, node_id, details) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (category, event_type, severity, user_uid or "", user_name or "",
             client_ip or "", nid, (details or "")[:4000])
        )
        # 集群内 Worker→LB 转发（集中存储）
        if _forward_to_lb() and nid not in ("local",):
            try:
                from .cluster import cluster
                if getattr(cluster, "role", "worker") == "worker" and cluster.lb_info:
                    _forward_to_lb_node({
                        "category": category, "event_type": event_type,
                        "severity": severity, "user_uid": user_uid,
                        "user_name": user_name, "client_ip": client_ip,
                        "node_id": nid, "details": details,
                    })
            except Exception as e:
                logger.debug(f"audit forward to LB skipped: {e}")
        # 可选外发 syslog/SIEM
        tgt = _syslog_target()
        if tgt:
            _send_external(tgt, category, event_type, severity, details, client_ip)
    except Exception as e:
        logger.error(f"audit_log write failed: {e}")


def _forward_to_lb_node(event: dict) -> None:
    """把审计事件转发给 LB 的 /internal/audit（节点间共享密钥）。"""
    import json as _json
    try:
        from .cluster import cluster
        from .core_console import _internal_secret
        host = (cluster.lb_info or {}).get("host")
        port = getattr(configs, "CLUSTER_LB_PORT", 8000)
        if not host:
            return
        body = _json.dumps(event).encode()
        req = urllib.request.Request(
            f"http://{host}:{port}/internal/audit",
            data=body,
            headers={"Content-Type": "application/json", "X-Internal-Secret": _internal_secret()},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.debug(f"audit forward failed: {e}")


def _send_external(target: str, category, event_type, severity, details, client_ip) -> None:
    """可选外发：syslog://host:port（UDP RFC3164）或 https://...（POST JSON）。"""
    try:
        if target.startswith("syslog://"):
            host, _, port = target[len("syslog://"):].partition(":")
            port = int(port) if port else 514
            msg = (f"<134>APIProxy AUDIT: cat={category} type={event_type} "
                   f"sev={severity} ip={client_ip} {details}")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(msg.encode("utf-8", "ignore"), (host, port))
            s.close()
        elif target.startswith("http://") or target.startswith("https://"):
            body = json.dumps({
                "category": category, "event_type": event_type,
                "severity": severity, "client_ip": client_ip, "details": details,
            }).encode()
            req = urllib.request.Request(target, data=body,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.debug(f"audit external send failed: {e}")


# ============================================================================
# 查询
# ============================================================================
async def query(limit: int = 50, category: str = "", event_type: str = "",
                severity: str = "", client_ip: str = "", user: str = "",
                days: int = 0) -> list:
    """按条件查询审计日志（audit_log）。"""
    if not _enabled():
        return []
    sql = "SELECT id, category, event_type, severity, user_uid, user_name, " \
          "client_ip, node_id, details, created_at FROM audit_log WHERE 1=1"
    args = []
    if category:
        sql += " AND category=?"; args.append(category)
    if event_type:
        sql += " AND event_type=?"; args.append(event_type)
    if severity:
        sql += " AND severity=?"; args.append(severity)
    if client_ip:
        sql += " AND client_ip=?"; args.append(client_ip)
    if user:
        sql += " AND (user_uid=? OR user_name=?)"; args += [user, user]
    if days and days > 0:
        sql += " AND created_at > datetime('now', ?)"; args.append(f"-{days} day")
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    try:
        rows = await async_db_query(sql, tuple(args))
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"audit query failed: {e}")
        return []


async def stats(days: int = 7) -> dict:
    """统计最近 N 天的审计事件量（按分类 / 严重度）。"""
    if not _enabled():
        return {}
    try:
        by_cat = await async_db_query(
            "SELECT category, COUNT(*) AS c FROM audit_log "
            "WHERE created_at > datetime('now', ?) GROUP BY category",
            (f"-{days} day",))
        by_sev = await async_db_query(
            "SELECT severity, COUNT(*) AS c FROM audit_log "
            "WHERE created_at > datetime('now', ?) GROUP BY severity",
            (f"-{days} day",))
        total = await async_db_query(
            "SELECT COUNT(*) AS c FROM audit_log "
            "WHERE created_at > datetime('now', ?)", (f"-{days} day",))
        return {
            "days": days,
            "total": (total[0].get("c") if total else 0),
            "by_category": {r["category"]: r["c"] for r in by_cat},
            "by_severity": {r["severity"]: r["c"] for r in by_sev},
        }
    except Exception as e:
        logger.error(f"audit stats failed: {e}")
        return {}


# ============================================================================
# 导出 / 清理
# ============================================================================
def export_rows(rows: list, fmt: str = "json") -> str:
    """把审计行序列化为 JSON 或 CSV 文本。"""
    if fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        cols = ["id", "category", "event_type", "severity", "user_uid",
                "user_name", "client_ip", "node_id", "details", "created_at"]
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})
        return buf.getvalue()
    return json.dumps(rows, ensure_ascii=False, indent=2, default=str)


async def prune_old(days: int = 0) -> int:
    """清理超过保留期的审计（返回删除行数）。"""
    days = days or _retention_days()
    if days <= 0:
        return 0
    try:
        await async_db_query(
            "DELETE FROM audit_log WHERE created_at < datetime('now', ?)",
            (f"-{days} day",))
        return days
    except Exception as e:
        logger.error(f"audit prune failed: {e}")
        return 0


def audit_status() -> dict:
    return {
        "enabled": _enabled(),
        "retention_days": _retention_days(),
        "forward_to_lb": _forward_to_lb(),
        "syslog_target": _syslog_target() or "(none)",
        "node_id": _node_id(),
    }
