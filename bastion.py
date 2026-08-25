"""堡垒机（特权访问管理 PAM，可选组件）。

定位：APIProxy 对外提供运维/管理能力的「唯一受控入口」。所有特权操作
（Console 运维命令、管理路由访问）在此被强制留痕，形成不可篡改的操作审计，
并支持（可选）高危命令审批工作流与会话回放。

与既有体系的关系：
  - 认证/授权仍由 core_auth / core_session / Console 密钥负责。
  - 本模块只做「事后留痕 + 事前审批」，不替代鉴权。
  - 审计事件同时写入 audit_log（经 audit_server），由日志审计服务器统一收口。

关键能力：
  1) 会话记录：首次对某 operator 记录特权操作时开一个堡垒机会话，
     该会话聚合其全部命令，供回放（bastion_replay）。
  2) 命令审计：每条 Console 命令记录 operator/目标/命令/参数/结果/风险。
  3) 管理路由审计：/admin、/api/admin 等管理端点的访问被记录。
  4) 审批工作流（默认关）：命中 BASTION_RISK_COMMANDS 的高危命令在执行前
     必须存在已批准的工单，否则自动建单并拒绝执行（避免运维被阻断需显式开启）。

接口：
  pre_check_approval(command, operator) -> dict | None
  record_command(operator, command, args, target, result, node_id) -> None
  record_admin_access(operator, path, method, status, client_ip) -> None
  request_approval / approve_ticket / deny_ticket / pending_approvals
  list_sessions / get_session_audit
"""
import logging
import time
import uuid

from . import configs
from .core_db import _get_conn

logger = logging.getLogger(__name__)


# ============================================================================
# 配置读取
# ============================================================================
def _enabled() -> bool:
    return bool(getattr(configs, "BASTION_ENABLED", True))


def _record_admin_routes() -> bool:
    return bool(getattr(configs, "BASTION_RECORD_ADMIN_ROUTES", True))


def _approval_enabled() -> bool:
    return bool(getattr(configs, "BASTION_APPROVAL_ENABLED", False))


def _risk_commands() -> list:
    rc = getattr(configs, "BASTION_RISK_COMMANDS", None)
    if isinstance(rc, (list, tuple)):
        return [str(c).strip().lower() for c in rc]
    if isinstance(rc, str):
        return [c.strip().lower() for c in rc.split(",") if c.strip()]
    return []


# 进程内会话缓存：operator -> session_id（同一进程内同一 operator 复用同一会话）
_SESSIONS = {}


def _node_id() -> str:
    try:
        from .cluster import NODE_ID_HEX
        return NODE_ID_HEX
    except Exception:
        return "local"


def _conn():
    return _get_conn()


def _ensure_session(operator: str, remote_ip: str = "") -> str:
    """获取（或新建）operator 的堡垒机会话 id。"""
    op = operator or "unknown"
    sid = _SESSIONS.get(op)
    if sid:
        return sid
    sid = "bst_" + uuid.uuid4().hex[:16]
    try:
        conn = _conn()
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO bastion_sessions "
                "(session_id, operator, remote_ip, command_count) VALUES (?,?,?,0)",
                (sid, op, remote_ip))
        _SESSIONS[op] = sid
    except Exception as e:
        logger.error(f"bastion ensure_session failed: {e}")
    return sid


# ============================================================================
# 审批工作流
# ============================================================================
def requires_approval(command: str) -> bool:
    if not _approval_enabled():
        return False
    return (command or "").strip().lower() in _risk_commands()


def pre_check_approval(command: str, operator: str) -> dict | None:
    """执行前检查：若命令需审批，自动建单并返回「拒绝执行」结果（含 ticket_id）。

    若已存在针对该 operator/command 的「已批准」工单，则视为放行（返回 None）。
    返回 None 表示放行；返回 dict 表示需审批、本次拒绝执行。
    """
    if not requires_approval(command):
        return None
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT ticket_id FROM bastion_approvals "
            "WHERE operator=? AND command=? AND status='approved' ORDER BY id DESC LIMIT 1",
            (operator or "unknown", command)).fetchone()
        if row:
            return None  # 已有已批准工单，放行
    except Exception:
        pass
    ticket = request_approval(operator, command, [])
    return {
        "success": False,
        "output": f"命令 {command} 属高危操作，需审批。已生成工单 {ticket}（bastion_approve {ticket} 通过后重试）",
        "data": {"approval_required": True, "ticket_id": ticket},
    }


def request_approval(operator: str, command: str, args: list) -> str:
    ticket = "apr_" + uuid.uuid4().hex[:12]
    try:
        conn = _conn()
        with conn:
            conn.execute(
                "INSERT INTO bastion_approvals "
                "(ticket_id, operator, command, args, status) VALUES (?,?,?,?, 'pending')",
                (ticket, operator or "unknown", command,
                 " ".join(str(a) for a in (args or []))))
    except Exception as e:
        logger.error(f"bastion request_approval failed: {e}")
    return ticket


def approve_ticket(ticket_id: str, reviewer: str, note: str = "") -> bool:
    try:
        conn = _conn()
        with conn:
            cur = conn.execute(
                "UPDATE bastion_approvals SET status='approved', reviewer=?, note=?, "
                "decided_at=CURRENT_TIMESTAMP WHERE ticket_id=? AND status='pending'",
                (reviewer or "unknown", note or "", ticket_id))
            return cur.rowcount > 0
    except Exception as e:
        logger.error(f"bastion approve_ticket failed: {e}")
        return False


def deny_ticket(ticket_id: str, reviewer: str, note: str = "") -> bool:
    try:
        conn = _conn()
        with conn:
            cur = conn.execute(
                "UPDATE bastion_approvals SET status='denied', reviewer=?, note=?, "
                "decided_at=CURRENT_TIMESTAMP WHERE ticket_id=? AND status='pending'",
                (reviewer or "unknown", note or "", ticket_id))
            return cur.rowcount > 0
    except Exception as e:
        logger.error(f"bastion deny_ticket failed: {e}")
        return False


def pending_approvals() -> list:
    try:
        conn = _conn()
        rows = conn.execute(
            "SELECT ticket_id, operator, command, args, created_at FROM bastion_approvals "
            "WHERE status='pending' ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"bastion pending_approvals failed: {e}")
        return []


# ============================================================================
# 记录
# ============================================================================
def record_command(operator: str, command: str, args: list,
                   target: str, result: dict, remote_ip: str = "") -> None:
    """记录一条 Console 特权命令（含结果），并归入 operator 的堡垒机会话。"""
    if not _enabled():
        return
    try:
        sid = _ensure_session(operator, remote_ip)
        ok = 1 if (result or {}).get("success", False) else 0
        risk = "high" if command in _risk_commands() else "normal"
        conn = _conn()
        with conn:
            conn.execute(
                "INSERT INTO bastion_audit "
                "(session_id, node_id, operator, target, command, args, result_ok, output, risk) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (sid, _node_id(), operator or "unknown", target or "self",
                 command, " ".join(str(a) for a in (args or [])),
                 ok, (result or {}).get("output", "")[:2000], risk))
            conn.execute(
                "UPDATE bastion_sessions SET command_count = command_count + 1 "
                "WHERE session_id=?", (sid,))
    except Exception as e:
        logger.error(f"bastion record_command failed: {e}")


def record_admin_access(operator: str, path: str, method: str,
                         status: int, client_ip: str) -> None:
    """记录一次管理路由访问（/admin、/api/admin 等）。"""
    if not _enabled() or not _record_admin_routes():
        return
    try:
        sid = _ensure_session(operator or client_ip or "unknown", client_ip)
        conn = _conn()
        with conn:
            conn.execute(
                "INSERT INTO bastion_audit "
                "(session_id, node_id, operator, target, command, args, result_ok, output, risk) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (sid, _node_id(), operator or client_ip or "unknown", "admin-route",
                 method or "GET", path[:500], 1 if status < 400 else 0,
                 f"admin access status={status}", "normal"))
    except Exception as e:
        logger.error(f"bastion record_admin_access failed: {e}")


# ============================================================================
# 查询 / 回放（供 Console）
# ============================================================================
def list_sessions(limit: int = 20) -> list:
    try:
        conn = _conn()
        rows = conn.execute(
            "SELECT session_id, operator, remote_ip, started_at, command_count "
            "FROM bastion_sessions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"bastion list_sessions failed: {e}")
        return []


def get_session_audit(session_id: str) -> list:
    try:
        conn = _conn()
        rows = conn.execute(
            "SELECT id, created_at, operator, target, command, args, result_ok, output, risk "
            "FROM bastion_audit WHERE session_id=? ORDER BY id ASC", (session_id,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"bastion get_session_audit failed: {e}")
        return []


def bastion_status() -> dict:
    return {
        "enabled": _enabled(),
        "record_admin_routes": _record_admin_routes(),
        "approval_enabled": _approval_enabled(),
        "risk_commands": _risk_commands(),
        "open_sessions": len(_SESSIONS),
        "node_id": _node_id(),
    }
