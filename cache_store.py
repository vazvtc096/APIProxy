"""统一缓存层（替代裸 Redis 依赖）。

后端优先级：
  1. redis   —— 配置了 REDIS_URL 时，使用真实 Redis（多实例共享计数 / 会话缓存）。
  2. proxy   —— 未配置 Redis 且本节点是集群 Worker 时，把缓存请求经 HTTP 代理到
               LB 节点的内置简易 KV 服务（/internal/cache）。即「把 LB 当成
               简易 Redis」：LB 在内存中维护 KV，所有 Worker 经 HTTP 共享同一份
               缓存，集群内限流 / 会话校验依旧是共享的。
  3. memory  —— 未配置 Redis 且本节点是 LB / 单机部署时，使用本地内存 KV
               （单进程，支持 TTL）。

所有后端提供与 redis-py 子集兼容的接口：
  get / set / setex / delete / exists / incr / expire / ttl / keys / flush / ping
调用方（会话缓存、限流）无需关心底层是 Redis、LB 还是本地内存。
"""

import fnmatch
import json
import logging
import threading
import time
import urllib.error
import urllib.request

from . import configs

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# 后端实现
# --------------------------------------------------------------------------- #
class _MemoryBackend:
    """本地内存 KV，支持 TTL（懒过期）。"""

    def __init__(self):
        self._data = {}          # key -> (value:str, expire_at:float|None)
        self._l = threading.Lock()

    def set(self, key, value, ttl=None):
        with self._l:
            self._data[key] = (str(value), time.time() + ttl if ttl else None)

    def get(self, key):
        with self._l:
            item = self._data.get(key)
            if not item:
                return None
            val, exp = item
            if exp and exp < time.time():
                self._data.pop(key, None)
                return None
            return val

    def setex(self, key, ttl, value):
        self.set(key, value, ttl)

    def delete(self, *keys):
        with self._l:
            for k in keys:
                self._data.pop(k, None)

    def exists(self, key):
        return 1 if self.get(key) is not None else 0

    def incr(self, key):
        # 内存后端 incr 不自动过期，调用方负责 expire（与 redis 行为一致）
        with self._l:
            item = self._data.get(key)
            cur = 0
            if item:
                val, exp = item
                if exp and exp < time.time():
                    item = None
                else:
                    try:
                        cur = int(val)
                    except (TypeError, ValueError):
                        cur = 0
            cur += 1
            new_exp = item[1] if item else None
            self._data[key] = (str(cur), new_exp)
            return cur

    def expire(self, key, ttl):
        with self._l:
            item = self._data.get(key)
            if item:
                self._data[key] = (item[0], time.time() + ttl)

    def ttl(self, key):
        with self._l:
            item = self._data.get(key)
            if not item:
                return -2
            exp = item[1]
            if not exp:
                return -1
            left = int(exp - time.time())
            return left if left > 0 else -2

    def keys(self, pattern="*"):
        with self._l:
            now = time.time()
            out = []
            for k, (_, exp) in list(self._data.items()):
                if exp and exp < now:
                    continue
                if _match(pattern, k):
                    out.append(k)
            return out

    def flush(self):
        with self._l:
            self._data.clear()

    def ping(self):
        return True


class _ProxyBackend:
    """Worker → LB 的 HTTP 代理后端（把 LB 当 Redis 用）。"""

    def __init__(self):
        self._memory = _MemoryBackend()  # 仅在 LB 不可达时的本地兜底

    def _lb_base(self):
        try:
            from .cluster import cluster
            info = getattr(cluster, "lb_info", None)
            host = None
            if info and info.get("host"):
                host = info["host"]
            else:
                host = getattr(cluster, "_lb_connect_host", None)
            if not host:
                host = getattr(configs, "CLUSTER_LB_HOST", None) or "127.0.0.1"
            return f"http://{host}:{configs.CLUSTER_LB_PORT}"
        except Exception:
            return f"http://127.0.0.1:{configs.CLUSTER_LB_PORT}"

    def _call(self, op, key=None, value=None, ttl=None):
        body = json.dumps({"op": op, "key": key, "value": value, "ttl": ttl}).encode()
        req = urllib.request.Request(
            self._lb_base() + "/internal/cache",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Internal-Secret": _internal_secret(),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read().decode()).get("result")

    def get(self, key):
        try:
            return self._call("get", key)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            return self._memory.get(key)
        except Exception:
            return self._memory.get(key)

    def set(self, key, value, ttl=None):
        try:
            self._call("set", key, value, ttl)
        except Exception:
            self._memory.set(key, value, ttl)

    def setex(self, key, ttl, value):
        self.set(key, value, ttl)

    def delete(self, *keys):
        for k in keys:
            try:
                self._call("delete", k)
            except Exception:
                self._memory.delete(k)

    def exists(self, key):
        try:
            return 1 if self._call("exists", key) else 0
        except Exception:
            return self._memory.exists(key)

    def incr(self, key):
        # 单调用完成 incr + 首次写入过期（服务端原子），避免竞态
        try:
            return self._call("incr", key)
        except Exception:
            return self._memory.incr(key)

    def expire(self, key, ttl):
        try:
            self._call("expire", key, ttl)
        except Exception:
            self._memory.expire(key, ttl)

    def ttl(self, key):
        try:
            return self._call("ttl", key) or -2
        except Exception:
            return self._memory.ttl(key)

    def keys(self, pattern="*"):
        try:
            return self._call("keys", None, pattern) or []
        except Exception:
            return self._memory.keys(pattern)

    def flush(self):
        try:
            self._call("flush")
        except Exception:
            self._memory.flush()

    def ping(self):
        try:
            self._call("ping")
            return True
        except Exception:
            return False


# LB 节点的权威内存存储（/internal/cache 与本地 CacheStore 共享同一实例）
LB_CACHE = _MemoryBackend()


def _match(pattern, key):
    if not pattern or pattern in ("*", ""):
        return True
    return fnmatch.fnmatch(key, pattern)


def _internal_secret() -> str:
    """节点间内部 API 共享密钥：优先 CLUSTER_SECRET，缺省回退 RCON_SECRET。

    两者皆空时返回空串——此时内网视为可信（与现有安全姿态一致），但跨节点
    /internal/* 接口仅接受来自本机回环或同密钥的请求。
    """
    return getattr(configs, "CLUSTER_SECRET", "") or getattr(configs, "RCON_SECRET", "")


def _get_redis():
    """懒加载真实 Redis（复用 redis_client 的连接语义）。"""
    try:
        from . import redis_client
        return redis_client.get_redis()
    except Exception:
        return None


class CacheStore:
    """对外统一缓存接口。后端在每次调用时按需解析（集群角色可能启动后才确定）。"""

    def __init__(self):
        self._proxy = _ProxyBackend()

    def _backend(self):
        r = _get_redis()
        if r is not None:
            return r
        # 未配置 Redis：集群 Worker 代理到 LB，否则本地内存
        if getattr(configs, "CLUSTER_ENABLED", False):
            try:
                from .cluster import cluster
                if getattr(cluster, "role", None) == "worker":
                    return self._proxy
            except Exception:
                pass
        return LB_CACHE

    def get(self, key):
        return self._backend().get(key)

    def set(self, key, value, ttl=None):
        self._backend().set(key, value, ttl)

    def setex(self, key, ttl, value):
        self._backend().setex(key, ttl, value)

    def delete(self, *keys):
        self._backend().delete(*keys)

    def exists(self, key):
        return self._backend().exists(key)

    def incr(self, key):
        return self._backend().incr(key)

    def expire(self, key, ttl):
        self._backend().expire(key, ttl)

    def ttl(self, key):
        return self._backend().ttl(key)

    def keys(self, pattern="*"):
        return self._backend().keys(pattern)

    def flush(self):
        b = self._backend()
        if b is LB_CACHE or isinstance(b, _ProxyBackend) or isinstance(b, _MemoryBackend):
            b.flush()
        else:
            logger.warning("Cache: flush 对真实 Redis 后端已忽略（避免误清空共享实例）")

    def ping(self):
        return self._backend().ping()


_store = CacheStore()


def get_cache() -> CacheStore:
    """返回进程级统一缓存实例（LB 即简易 Redis 的入口）。"""
    return _store


# --------------------------------------------------------------------------- #
# JSON 便捷封装（供业务层直接缓存结构化数据，无需手动序列化）
# --------------------------------------------------------------------------- #
def cache_set_json(key: str, value, ttl: int = None) -> None:
    """把任意可 JSON 序列化的值写入缓存（utf-8 安全）。"""
    try:
        _store.set(key, json.dumps(value, ensure_ascii=False), ttl)
    except (TypeError, ValueError) as e:
        logger.warning(f"Cache: cache_set_json 序列化失败 key={key}: {e}")


def cache_get_json(key: str):
    """读取并反序列化；未命中 / 损坏 / 过期均返回 None。"""
    raw = _store.get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def cache_delete_pattern(pattern: str) -> int:
    """按 glob 模式批量删除缓存键（memory / proxy 后端均支持）。返回删除条数。"""
    try:
        keys = _store.keys(pattern)
    except Exception as e:
        logger.warning(f"Cache: keys({pattern}) 失败：{e}")
        return 0
    if not keys:
        return 0
    try:
        _store.delete(*keys)
    except Exception as e:
        logger.warning(f"Cache: delete({pattern}) 失败：{e}")
        return 0
    return len(keys)


# --------------------------------------------------------------------------- #
# LB 内部缓存 HTTP 接口（供 Worker 代理调用）
# --------------------------------------------------------------------------- #
def _serve_cache_op(op, key, value, ttl):
    """在 LB 的内存存储上执行一个缓存操作，返回可被 JSON 序列化的值。"""
    if op == "get":
        return LB_CACHE.get(key)
    if op == "set":
        LB_CACHE.set(key, value, ttl)
        return True
    if op == "delete":
        LB_CACHE.delete(key)
        return True
    if op == "exists":
        return LB_CACHE.exists(key) == 1
    if op == "incr":
        # 原子自增；首次写入时若带 ttl 则设置过期（供限流窗口使用）
        cur = LB_CACHE.incr(key)
        if ttl and cur == 1:
            LB_CACHE.expire(key, ttl)
        return cur
    if op == "expire":
        LB_CACHE.expire(key, ttl)
        return True
    if op == "ttl":
        return LB_CACHE.ttl(key)
    if op == "keys":
        return LB_CACHE.keys(value or "*")
    if op == "flush":
        LB_CACHE.flush()
        return True
    if op == "ping":
        return True
    raise ValueError(f"unknown cache op: {op}")


# --------------------------------------------------------------------------- #
# Quart 蓝图：LB 暴露的简易 Redis HTTP 接口
# --------------------------------------------------------------------------- #
def _cache_bp():
    from quart import Blueprint, request, jsonify

    bp = Blueprint("cache_internal", __name__)

    @bp.route("/internal/cache", methods=["POST"])
    async def _cache_handler():
        # 仅 LB / 单机节点对外提供缓存服务；Worker 不应被当作缓存源
        if getattr(configs, "CLUSTER_ENABLED", False):
            try:
                from .cluster import cluster
                if getattr(cluster, "role", None) == "worker":
                    return jsonify({"error": "workers do not serve cache"}), 403
            except Exception:
                pass
        secret = request.headers.get("X-Internal-Secret", "")
        expected = _internal_secret()
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        is_local = client_ip.startswith("127.") or client_ip == "::1" or client_ip == "localhost"
        if expected and secret != expected:
            return jsonify({"error": "invalid internal secret"}), 403
        if not expected and not is_local:
            return jsonify({"error": "cache endpoint requires loopback when no shared secret"}), 403
        try:
            payload = await request.get_json(force=True, silent=True) or {}
            op = payload.get("op")
            if not op:
                return jsonify({"error": "missing op"}), 400
            result = _serve_cache_op(op, payload.get("key"),
                                     payload.get("value"), payload.get("ttl"))
            return jsonify({"result": result}), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": f"cache error: {e}"}), 500

    return bp


cache_bp = _cache_bp()
