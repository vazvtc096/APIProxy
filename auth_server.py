"""认证服务器（集中式认证 / 令牌自省）。

定位：对外的「认证权威面」。复用 core_session / core_auth 已有的会话与鉴权能力，
对外暴露标准化的令牌自省、会话校验、吊销接口；集群模式下 Worker 可把会话校验
委托给 LB 的认证服务器（/internal/auth/verify），避免各自依赖本地库。

能力：
  - introspect(token)：RFC 7662 风格的自省，支持会话 id（sessions 表）。
    返回 {active, user, uid, scopes}；过期/不存在返回 {active:false}。
  - verify_session(session_id)：供集群内部校验，返回 (active, user_name)。
  - revoke_session(session_id)：吊销指定会话。

注意：本模块不新建登录流程，只做「校验/吊销/自省」这一层集中化。
"""
import logging

from . import configs
from .core_db import async_db_query

logger = logging.getLogger(__name__)


# ============================================================================
# 配置读取
# ============================================================================
def _enabled() -> bool:
    return bool(getattr(configs, "AUTH_SERVER_ENABLED", True))


def _introspection_enabled() -> bool:
    return bool(getattr(configs, "AUTH_SERVER_INTROSPECTION", True))


# ============================================================================
# 校验 / 自省 / 吊销
# ============================================================================
async def _lookup_session(session_id: str) -> dict | None:
    if not session_id:
        return None
    try:
        rows = await async_db_query(
            "SELECT session_id, user_name, user_uid, expires_at FROM sessions "
            "WHERE session_id=?", (session_id,))
        if not rows:
            return None
        return dict(rows[0])
    except Exception as e:
        logger.error(f"auth_server lookup_session failed: {e}")
        return None


async def introspect(token: str) -> dict:
    """RFC 7662 风格令牌自省：返回标准化结果。"""
    if not _enabled() or not _introspection_enabled():
        return {"active": False, "error": "introspection disabled"}
    row = await _lookup_session(token)
    if not row:
        return {"active": False}
    # 过期判定
    exp = row.get("expires_at")
    if exp:
        try:
            from datetime import datetime
            if datetime.now() > datetime.fromisoformat(str(exp)):
                return {"active": False, "reason": "expired"}
        except Exception:
            pass
    return {
        "active": True,
        "user": row.get("user_name"),
        "uid": row.get("user_uid"),
        "scopes": ["session"],
        "token_type": "session",
    }


async def verify_session(session_id: str):
    """集群内部校验：返回 (active: bool, user_name: str|None)。"""
    if not _enabled():
        return (False, None)
    row = await _lookup_session(session_id)
    if not row:
        return (False, None)
    exp = row.get("expires_at")
    if exp:
        try:
            from datetime import datetime
            if datetime.now() > datetime.fromisoformat(str(exp)):
                return (False, None)
        except Exception:
            pass
    return (True, row.get("user_name"))


async def revoke_session(session_id: str) -> bool:
    """吊销会话（从 sessions 表删除）。"""
    if not session_id:
        return False
    try:
        await async_db_query("DELETE FROM sessions WHERE session_id=?", (session_id,))
        return True
    except Exception as e:
        logger.error(f"auth_server revoke_session failed: {e}")
        return False


async def list_sessions(limit: int = 20) -> list:
    try:
        rows = await async_db_query(
            "SELECT session_id, user_name, user_uid, ip_address, expires_at, last_active_at "
            "FROM sessions ORDER BY last_active_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"auth_server list_sessions failed: {e}")
        return []


def auth_status() -> dict:
    return {
        "enabled": _enabled(),
        "introspection_enabled": _introspection_enabled(),
    }
