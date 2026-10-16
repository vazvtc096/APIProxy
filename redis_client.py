"""Redis 客户端（可选）。

未配置 REDIS_URL 时 `get_redis()` 返回 None，调用方回退到 SQLite 实现；
配置了但连接失败同样返回 None 并告警，保证限流/缓存降级不中断服务。

测试隔离：pytest 环境下默认拒绝连接真实 Redis（避免测试读写真实实例、
并因连接超时拖慢用例）；确需测试 Redis 时设 APIPROXY_TEST_ALLOW_REDIS=1。
"""

import logging
import os
import threading

from .configs import REDIS_URL

logger = logging.getLogger(__name__)

_redis = None
_lock = threading.Lock()
_tried = False


def get_redis():
    """返回 Redis 连接，或 None（未配置 / 连接失败）。

    懒加载 + 单例：首次调用才建立连接，之后复用；连接失败后不再重试
    （避免每次请求都卡在连接超时），可随进程重启恢复。
    """
    global _redis, _tried
    if not REDIS_URL:
        return None
    # 测试隔离安全网：pytest 运行期默认不连真实 Redis（含 --noconftest 直接跑的用例），
    # 可用 APIPROXY_TEST_ALLOW_REDIS=1 显式放行。
    if os.environ.get("PYTEST_CURRENT_TEST") and os.environ.get("APIPROXY_TEST_ALLOW_REDIS") != "1":
        return None
    if _redis is not None:
        return _redis
    if _tried:
        return None

    with _lock:
        if _redis is not None or _tried:
            return _redis
        _tried = True
        try:
            import redis
            client = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
                retry_on_timeout=False,
            )
            client.ping()
            _redis = client
            logger.info("Redis connected: %s", _mask_url(REDIS_URL))
        except Exception as e:
            _redis = None
            logger.warning("Redis 不可用，回退 SQLite：%s", e)
    return _redis


def _mask_url(url: str) -> str:
    """隐藏 Redis URL 中的密码（日志脱敏）。"""
    if "@" in url:
        scheme, rest = url.split("://", 1)
        if ":" in rest.split("@")[0]:
            host = rest.split("@")[1]
            return f"{scheme}://***@{host}"
    return url
