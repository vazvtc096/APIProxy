"""管理员权限与用户检查：is_admin、封禁检查、请求 ID 生成。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
import uuid

from quart import session, jsonify

from .core_db import async_db_query
from .core_rate_limit import _check_rate_limit


async def _is_admin() -> bool:
    """检查当前登录用户是否是管理员"""
    if 'user' not in session:
        return False
    username = session['user']
    users = await async_db_query(
        "SELECT is_admin FROM users WHERE user_name = ?",
        (username,)
    )
    if not users:
        return False
    return bool(users[0].get('is_admin', 0))


async def _require_admin():
    """要求管理员权限，否则返回 None 表示未通过"""
    # 限流检查
    allowed, remaining = _check_rate_limit('admin')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429

    if not await _is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403
    return None  # None 表示通过


def _generate_request_id() -> str:
    """生成充值请求 ID"""
    return 'rr_' + uuid.uuid4().hex[:16]


async def _get_user_by_uid(uid: str) -> dict | None:
    """通过 UID 查找用户"""
    users = await async_db_query(
        "SELECT * FROM users WHERE uid = ?",
        (uid,)
    )
    return users[0] if users else None


async def _is_user_banned(user_data: dict) -> tuple[bool, str]:
    """检查用户是否被封禁
    返回：(是否封禁, 封禁原因/到期时间)
    """
    if not user_data.get('is_banned'):
        return False, ''

    ban_reason = user_data.get('ban_reason', '') or '账号已被封禁'
    ban_expire = user_data.get('ban_expire_at')

    if ban_expire:
        # 检查是否已过期
        import datetime
        try:
            expire_time = datetime.datetime.fromisoformat(str(ban_expire))
            now = datetime.datetime.now()
            if now > expire_time:
                return False, ''
        except:
            pass
        return True, f"{ban_reason}（到期: {ban_expire}）"

    return True, ban_reason  # 永久封禁
