"""请求频率限制（限流）：Redis 优先，SQLite 回退。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
import logging
import time

from quart import session

from .core_db import _get_conn
from .core_http import _get_client_ip

RATE_LIMITS = {
    'login': {'window': 60, 'max': 5},
    'register': {'window': 60, 'max': 3},
    'chat': {'window': 60, 'max': 60},
    'recharge': {'window': 60, 'max': 5},
    'admin': {'window': 60, 'max': 30},
    'password_reset': {'window': 60, 'max': 5},
    # 社交功能限流：原 __main__.py 在模块级用 RATE_LIMITS['post'] = ... 追加，
    # 重构后合并进统一定义，避免依赖模块加载顺序。
    'post': {'window': 60, 'max': 10},
    'friend': {'window': 60, 'max': 20},
    'transfer': {'window': 60, 'max': 10},
}


def _init_rate_limit_table():
    """创建限流计数表"""
    conn = _get_conn()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    ts REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_ck ON rate_limits(category, key, ts)")
    finally:
        conn.close()


def _cleanup_rate_limits_sync():
    """清理过期限流记录（全局），防止 rate_limits 表无限增长"""
    import time as _t
    conn = _get_conn()
    try:
        with conn:
            # 删除 24 小时前的所有记录
            conn.execute("DELETE FROM rate_limits WHERE ts < ?", (_t.time() - 86400,))
            conn.commit()
    finally:
        conn.close()


def _get_rate_limit_key(category: str) -> str:
    """获取限流标识（优先用用户ID，其次用 IP）"""
    if 'user' in session:
        return f"user:{session['user']}"
    # 获取客户端 IP（兼容反向代理 / Cloudflare）
    return f"ip:{_get_client_ip()}"


def _check_rate_limit(category: str) -> tuple[bool, int]:
    """检查是否超过限流（Redis 优先，SQLite 回退）
    返回：(是否允许, 剩余可用次数)
    """
    if category not in RATE_LIMITS:
        return True, 999
    config = RATE_LIMITS[category]
    key = _get_rate_limit_key(category)
    window = config['window']
    max_req = config['max']

    # Redis 优先：原子 INCR + EXPIRE，支持多实例共享计数
    try:
        from . import cache_store
        r = cache_store.get_cache()
        if r is not None:
            return _check_rate_limit_redis(r, category, key, window, max_req)
    except Exception as e:
        logging.error(f"Redis rate limit failed, fallback: {e}")

    # Redis 不可用 -> C 本地滑动窗口（进程内，单实例语义等价于 SQLite 回退且更快）。
    # 多实例下 Redis 才是分布式计数真相源，所以此路径仅在 Redis 不可用时介入，
    # 不会放宽度量（单实例下本地即全局）。配置 NATIVE_LOCAL_RATE_LIMIT=False 可关闭。
    try:
        from . import configs
        if getattr(configs, "NATIVE_LOCAL_RATE_LIMIT", True):
            from .native import native_available, sliding_window_allow
            if native_available:
                allow = sliding_window_allow(f"{category}:{key}", window, max_req)
                return (bool(allow), (max_req - 1) if allow else 0)
    except Exception:
        pass

    return _check_rate_limit_sqlite(category, key, window, max_req)


def _check_rate_limit_redis(r, category, key, window, max_req):
    """Redis 原子限流（INCR + EXPIRE）。"""
    redis_key = f"rl:{category}:{key}"
    count = r.incr(redis_key)
    if count == 1:
        r.expire(redis_key, int(window))
    if count > max_req:
        return False, 0
    return True, max_req - count


def _check_rate_limit_sqlite(category, key, window, max_req):
    """SQLite 限流（原实现，Redis 不可用时的回退）。

    用 db.transaction 在 SQLite 下获取写锁（BEGIN IMMEDIATE），保证
    DELETE→COUNT→INSERT 串行执行，避免并发计数竞态导致限流失效；
    PostgreSQL 下由事务 + 行锁保证。调用方无需关心后端差异。
    """
    from . import db
    try:
        now = time.time()
        with db.transaction() as conn:
            cur = conn.cursor()
            # 清理当前标识的过期记录
            cur.execute(
                "DELETE FROM rate_limits WHERE category=? AND key=? AND ts < ?",
                (category, key, now - window)
            )
            # 计数
            cur.execute(
                "SELECT COUNT(*) FROM rate_limits WHERE category=? AND key=?",
                (category, key)
            )
            count = cur.fetchone()[0]
            if count >= max_req:
                return False, 0
            cur.execute(
                "INSERT INTO rate_limits (category, key, ts) VALUES (?, ?, ?)",
                (category, key, now)
            )
            return True, max_req - count - 1
    except Exception as e:
        logging.error(f"Rate limit check failed: {e}")
        return True, 999  # 失败时放行，避免误封正常用户


def _get_rate_limit_retry_after(category: str) -> int:
    """返回限流恢复剩余秒数（用于 Retry-After 响应头，符合 RFC 6585）"""
    if category not in RATE_LIMITS:
        return 60
    config = RATE_LIMITS[category]
    key = _get_rate_limit_key(category)

    # Redis 优先：TTL 即恢复剩余秒数
    try:
        from . import cache_store
        r = cache_store.get_cache()
        if r is not None:
            ttl = r.ttl(f"rl:{category}:{key}")
            if ttl > 0:
                return int(ttl)
            return config['window']
    except Exception:
        pass

    now = time.time()
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT MIN(ts) FROM rate_limits WHERE category=? AND key=? AND ts >= ?",
            (category, key, now - config['window'])
        )
        row = cur.fetchone()
        oldest = row[0] if row and row[0] is not None else None
        if oldest is None:
            return config['window']
        return max(1, int(oldest + config['window'] - now))
    except Exception:
        return config['window']
    finally:
        conn.close()
