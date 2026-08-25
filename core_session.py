"""会话管理：创建、验证、删除、清理（同步 + 异步包装）。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
from .core_db import _get_conn

SESSION_EXPIRE_DAYS = 7


def _init_sessions_table():
    """初始化会话表"""
    def _init():
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    user_name TEXT NOT NULL,
                    user_uid TEXT,
                    user_agent TEXT,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_active_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            # 创建索引
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_name)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
            conn.commit()
    _init()


def _create_session_sync(username: str, user_uid: str = None, user_agent: str = None, ip: str = None) -> str:
    """创建新会话（同步版本）
    Returns:
        session_id (str)
    """
    import uuid
    import datetime

    session_id = uuid.uuid4().hex
    expires_at = (datetime.datetime.now() + datetime.timedelta(days=SESSION_EXPIRE_DAYS)).strftime('%Y-%m-%d %H:%M:%S')

    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sessions (session_id, user_name, user_uid, user_agent, ip_address, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session_id, username, user_uid, user_agent, ip, expires_at))
        conn.commit()

    # Redis 缓存（可选加速；失败静默忽略，不影响会话创建）
    try:
        from . import cache_store
        r = cache_store.get_cache()
        if r is not None:
            r.setex(f"sess:{session_id}", SESSION_EXPIRE_DAYS * 86400, username)
    except Exception:
        pass

    return session_id


def _validate_session_sync(session_id: str) -> tuple[bool, str]:
    """验证会话是否有效（同步版本）
    Returns:
        (is_valid: bool, username: str)
    """
    if not session_id:
        return False, None

    # Redis 缓存优先（加速；miss 则回退 SQLite）
    try:
        from . import cache_store
        r = cache_store.get_cache()
        if r is not None:
            cached = r.get(f"sess:{session_id}")
            if cached:
                return True, cached
    except Exception:
        pass

    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT user_name, expires_at FROM sessions WHERE session_id = ?
        """, (session_id,))
        row = cur.fetchone()

        if not row:
            return False, None

        username, expires_at = row

        # 检查是否过期
        if expires_at and expires_at < now:
            # 过期了，删除
            cur.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            return False, None

        # 更新最后活跃时间
        cur.execute("""
            UPDATE sessions SET last_active_at = CURRENT_TIMESTAMP WHERE session_id = ?
        """, (session_id,))
        conn.commit()

    # 回填 Redis 缓存
    try:
        from . import cache_store
        r = cache_store.get_cache()
        if r is not None:
            r.setex(f"sess:{session_id}", SESSION_EXPIRE_DAYS * 86400, username)
    except Exception:
        pass

    return True, username


def _delete_session_sync(session_id: str):
    """删除会话（同步版本）"""
    # Redis 缓存删除（可选；失败静默忽略）
    try:
        from . import cache_store
        r = cache_store.get_cache()
        if r is not None:
            r.delete(f"sess:{session_id}")
    except Exception:
        pass

    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()


def _get_user_sessions_sync(username: str) -> list:
    """获取用户的所有活跃会话（同步版本）"""
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT session_id, user_agent, ip_address, created_at, last_active_at, expires_at
            FROM sessions
            WHERE user_name = ? AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY last_active_at DESC
        """, (username, now))
        rows = cur.fetchall()

    return [dict(row) for row in rows]


def _get_user_session_count_sync(username: str) -> int:
    """获取用户活跃会话数量（同步版本）"""
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) as cnt FROM sessions
            WHERE user_name = ? AND (expires_at IS NULL OR expires_at > ?)
        """, (username, now))
        row = cur.fetchone()

    return row['cnt'] if row else 0


def _kick_oldest_session_sync(username: str) -> bool:
    """踢掉用户最旧的会话（同步版本）
    Returns:
        True if kicked
    """
    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        # 找到最旧的会话（按 last_active_at 升序，第一个就是最旧的）
        cur.execute("""
            SELECT session_id FROM sessions
            WHERE user_name = ?
            ORDER BY last_active_at ASC
            LIMIT 1
        """, (username,))
        row = cur.fetchone()

        if row:
            cur.execute("DELETE FROM sessions WHERE session_id = ?", (row['session_id'],))
            conn.commit()
            return True

    return False


def _cleanup_expired_sessions_sync():
    """清理所有过期会话（同步版本）"""
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        conn.commit()
        return cur.rowcount


async def _create_session(username: str, user_uid: str = None, user_agent: str = None, ip: str = None) -> str:
    """创建新会话（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_create_session_sync, username, user_uid, user_agent, ip)


async def _validate_session(session_id: str) -> tuple[bool, str]:
    """验证会话是否有效（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_validate_session_sync, session_id)


async def _delete_session(session_id: str):
    """删除会话（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_delete_session_sync, session_id)


async def _get_user_sessions(username: str) -> list:
    """获取用户的所有活跃会话（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_get_user_sessions_sync, username)


async def _get_user_session_count(username: str) -> int:
    """获取用户活跃会话数量（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_get_user_session_count_sync, username)


async def _kick_oldest_session(username: str) -> bool:
    """踢掉用户最旧的会话（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_kick_oldest_session_sync, username)
