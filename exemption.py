"""
豁免密钥（Exemption Key）模块
允许用户申请临时豁免人机验证，管理员审核通过后生成 exemption key，
凭 key 可在 10 分钟内、从申请 IP 一次性通过注册的人机验证。

密钥规格：与 API Key 同等 —— ex- 前缀 + 48 位十六进制（24 字节熵）
安全特性：
  - 一次性使用（验证后标记为 used）
  - IP 绑定（只能在申请时的 IP 使用）
  - 10 分钟硬过期
  - 申请速率限制（每 IP 每分钟 1 次）
  - 全流程审计日志
"""
import asyncio
import json
import logging
import secrets
import time
from typing import Tuple, Optional
from .db import get_conn
from .core import _get_client_ip

# 配置
EXEMPTION_KEY_PREFIX = "ex-"
EXEMPTION_VALIDITY_SECONDS = 600  # 10 分钟
EXEMPTION_REQUEST_RATE_LIMIT = 60  # 每 IP 申请间隔（秒）
EXEMPTION_REASON_MAX_LENGTH = 500

# SSE 事件通知：request_id -> list of asyncio.Queue
# 管理员审核通过/拒绝时，通知所有正在监听该申请的前端连接
_event_listeners: dict[int, list] = {}


def _notify_listeners(request_id: int, event: dict) -> None:
    """通知所有监听该申请的 SSE 连接（审核结果回调）"""
    queues = _event_listeners.get(request_id, [])
    for q in queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


def register_listener(request_id: int):
    """注册一个 SSE 监听器，返回 asyncio.Queue（前端连接时调用）"""
    q = asyncio.Queue(maxsize=10)
    if request_id not in _event_listeners:
        _event_listeners[request_id] = []
    _event_listeners[request_id].append(q)
    return q


def unregister_listener(request_id: int, q) -> None:
    """注销 SSE 监听器（前端断开连接时调用）"""
    if request_id in _event_listeners:
        _event_listeners[request_id] = [x for x in _event_listeners[request_id] if x is not q]
        if not _event_listeners[request_id]:
            del _event_listeners[request_id]


def _hash_key(key: str) -> str:
    """对 exemption key 做 SHA256 哈希存储（不存明文）"""
    import hashlib
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def _generate_key() -> str:
    """生成高熵豁免密钥：ex- + 48位十六进制（24字节熵）"""
    return EXEMPTION_KEY_PREFIX + secrets.token_hex(24)


def init_exemption_table() -> None:
    """初始化豁免请求表（应用启动时调用）"""
    conn = get_conn()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS exemption_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_ip TEXT NOT NULL,
                requester_ua TEXT,
                device_fingerprint TEXT,
                reason TEXT,
                status TEXT DEFAULT 'pending',
                exemption_key_hash TEXT UNIQUE,
                approved_by TEXT,
                approved_at REAL,
                expires_at REAL,
                used_at REAL,
                used_by TEXT,
                used_ip TEXT,
                reject_reason TEXT,
                created_at REAL DEFAULT (strftime('%s','now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exemption_status ON exemption_requests(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exemption_key ON exemption_requests(exemption_key_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exemption_ip ON exemption_requests(requester_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exemption_created ON exemption_requests(created_at)")


def request_exemption(requester_ip: str, requester_ua: str = "",
                      device_fingerprint: str = "", reason: str = "") -> Tuple[bool, str, Optional[int]]:
    """提交豁免申请

    Returns:
        (success, message, request_id)
    """
    if not requester_ip:
        return False, "无法获取客户端 IP", None

    reason = (reason or "").strip()[:EXEMPTION_REASON_MAX_LENGTH]

    conn = get_conn()
    with conn:
        # 速率限制：检查该 IP 最近一次申请时间
        row = conn.execute(
            "SELECT created_at FROM exemption_requests WHERE requester_ip = ? ORDER BY created_at DESC LIMIT 1",
            (requester_ip,)
        ).fetchone()
        if row:
            elapsed = time.time() - row['created_at']
            if elapsed < EXEMPTION_REQUEST_RATE_LIMIT:
                wait = int(EXEMPTION_REQUEST_RATE_LIMIT - elapsed)
                return False, f"申请过于频繁，请 {wait} 秒后再试", None

        # 检查是否已有 pending 的申请
        pending = conn.execute(
            "SELECT id FROM exemption_requests WHERE requester_ip = ? AND status = 'pending'",
            (requester_ip,)
        ).fetchone()
        if pending:
            return False, "您已有一个待审核的申请，请等待管理员处理", pending['id']

        # 创建申请
        cursor = conn.execute(
            """INSERT INTO exemption_requests
               (requester_ip, requester_ua, device_fingerprint, reason, status)
               VALUES (?, ?, ?, ?, 'pending')""",
            (requester_ip, requester_ua[:500], device_fingerprint[:256], reason)
        )
        request_id = cursor.lastrowid
        conn.commit()

    logging.info(f"豁免申请已提交: id={request_id}, ip={requester_ip}")
    return True, "申请已提交，请等待管理员审核", request_id


def list_pending(limit: int = 50) -> list:
    """管理员：获取待审核列表"""
    conn = get_conn()
    with conn:
        rows = conn.execute(
            """SELECT id, requester_ip, requester_ua, device_fingerprint, reason, created_at
               FROM exemption_requests WHERE status = 'pending'
               ORDER BY created_at ASC LIMIT ?""",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def list_all(status: str = None, limit: int = 100) -> list:
    """管理员：获取所有申请（可按状态过滤）"""
    conn = get_conn()
    with conn:
        if status:
            rows = conn.execute(
                """SELECT * FROM exemption_requests WHERE status = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (status, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM exemption_requests ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def approve_request(request_id: int, admin_name: str) -> Tuple[bool, str, Optional[str]]:
    """管理员：批准申请，生成 exemption key

    Returns:
        (success, message, exemption_key)
    """
    conn = get_conn()
    with conn:
        row = conn.execute(
            "SELECT * FROM exemption_requests WHERE id = ?",
            (request_id,)
        ).fetchone()
        if not row:
            return False, "申请不存在", None
        if row['status'] != 'pending':
            return False, f"该申请状态为 {row['status']}，无法重复审核", None

        # 生成 key（只存哈希，不存明文）
        exemption_key = _generate_key()
        key_hash = _hash_key(exemption_key)
        now = time.time()
        expires_at = now + EXEMPTION_VALIDITY_SECONDS

        conn.execute(
            """UPDATE exemption_requests
               SET status = 'approved', exemption_key_hash = ?, approved_by = ?,
                   approved_at = ?, expires_at = ?
               WHERE id = ?""",
            (key_hash, admin_name, now, expires_at, request_id)
        )
        conn.commit()

    logging.info(f"豁免申请已批准: id={request_id}, admin={admin_name}, expires={expires_at}")

    # SSE 回调：通知所有正在监听该申请的前端连接
    _notify_listeners(request_id, {
        'type': 'approved',
        'request_id': request_id,
        'exemption_key': exemption_key,
        'expires_at': expires_at,
        'validity_seconds': EXEMPTION_VALIDITY_SECONDS,
    })

    return True, "申请已批准", exemption_key


def reject_request(request_id: int, admin_name: str, reason: str = "") -> Tuple[bool, str]:
    """管理员：拒绝申请"""
    conn = get_conn()
    with conn:
        row = conn.execute(
            "SELECT status FROM exemption_requests WHERE id = ?",
            (request_id,)
        ).fetchone()
        if not row:
            return False, "申请不存在"
        if row['status'] != 'pending':
            return False, f"该申请状态为 {row['status']}，无法重复审核"

        conn.execute(
            """UPDATE exemption_requests
               SET status = 'rejected', approved_by = ?, reject_reason = ?, approved_at = ?
               WHERE id = ?""",
            (admin_name, reason[:500], time.time(), request_id)
        )
        conn.commit()

    logging.info(f"豁免申请已拒绝: id={request_id}, admin={admin_name}, reason={reason}")

    # SSE 回调：通知所有正在监听该申请的前端连接
    _notify_listeners(request_id, {
        'type': 'rejected',
        'request_id': request_id,
        'reason': reason,
    })

    return True, "申请已拒绝"


def verify_exemption_key(key: str, client_ip: str,
                         username: str = "") -> Tuple[bool, str]:
    """验证豁免 key（注册时调用）

    验证规则：
      1. key 格式正确
      2. key 存在且状态为 approved
      3. 未过期
      4. 未被使用过
      5. 当前 IP 与申请 IP 一致

    验证通过后立即标记为 used（一次性）。

    Returns:
        (success, message)
    """
    if not key or not isinstance(key, str):
        return False, "豁免密钥为空"

    key = key.strip()

    # 格式检查
    if not key.startswith(EXEMPTION_KEY_PREFIX):
        return False, "豁免密钥格式错误"
    key_part = key[len(EXEMPTION_KEY_PREFIX):]
    if len(key_part) != 48 or not all(c in "0123456789abcdef" for c in key_part):
        return False, "豁免密钥格式错误"

    key_hash = _hash_key(key)
    now = time.time()

    conn = get_conn()
    with conn:
        row = conn.execute(
            "SELECT * FROM exemption_requests WHERE exemption_key_hash = ?",
            (key_hash,)
        ).fetchone()

        if not row:
            return False, "豁免密钥不存在"
        if row['status'] != 'approved':
            return False, f"豁免密钥状态异常（{row['status']}）"
        if row['expires_at'] and now > row['expires_at']:
            return False, "豁免密钥已过期"
        if row['used_at']:
            return False, "豁免密钥已被使用"

        # IP 绑定检查
        if row['requester_ip'] and client_ip and row['requester_ip'] != client_ip:
            logging.warning(
                f"豁免密钥 IP 不匹配: key_hash={key_hash[:16]}, "
                f"request_ip={row['requester_ip']}, current_ip={client_ip}"
            )
            return False, "豁免密钥与当前 IP 不匹配（只能在申请时的 IP 使用）"

        # 验证通过，标记为已使用（一次性）
        conn.execute(
            """UPDATE exemption_requests
               SET status = 'used', used_at = ?, used_by = ?, used_ip = ?
               WHERE id = ?""",
            (now, username[:64] if username else '', client_ip, row['id'])
        )
        conn.commit()

    logging.info(
        f"豁免密钥验证通过: id={row['id']}, ip={client_ip}, "
        f"user={username}, remaining={int(row['expires_at'] - now)}s"
    )
    return True, "豁免验证通过"


def get_request_status(request_id: int, requester_ip: str = None) -> Optional[dict]:
    """用户查询自己的申请状态"""
    conn = get_conn()
    with conn:
        row = conn.execute(
            "SELECT id, status, reason, created_at, approved_at, expires_at, reject_reason "
            "FROM exemption_requests WHERE id = ?",
            (request_id,)
        ).fetchone()
        if not row:
            return None
        # 安全：如果提供了 IP，只允许查询自己的申请
        if requester_ip and row['requester_ip'] != requester_ip:
            return None
        return dict(row)


def cleanup_expired() -> int:
    """清理过期的 approved 但未使用的申请（标记为 expired），返回清理数量"""
    conn = get_conn()
    now = time.time()
    with conn:
        cursor = conn.execute(
            """UPDATE exemption_requests SET status = 'expired'
               WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at < ?""",
            (now,)
        )
        count = cursor.rowcount
        conn.commit()
    if count:
        logging.info(f"清理过期豁免密钥: {count} 个")
    return count
