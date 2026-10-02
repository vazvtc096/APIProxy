# -*- coding: utf-8 -*-
"""多上游 API Key 管理。

- 从 configs.UPSTREAMS 构建 AsyncOpenAI 客户端注册表（自定义名称）。
- select_upstream(model, requested_name)：按 启用 / 未禁用该模型 / 优先级 选择最合适的上游；
  若模型不在某上游已拉取的模型目录中则跳过（目录缺失时退化为只看 disabled_models）。
- refresh_models()：异步拉取各上游 /models 并合并，得到统一模型列表与「每个模型可由哪些上游服务」。
- startup_refresh()：供应用启动时调用一次。
"""
import logging
import asyncio
import time
from openai import AsyncOpenAI

from . import configs

# 名称 -> AsyncOpenAI 客户端（主 key；兼容旧引用：get_client / 健康探测 / playground）
_CLIENTS = {}
# 名称 -> [(key_id, client), ...] 密钥池（api_key + api_keys 逐把构建）
_KEY_CLIENTS = {}
# key_id -> 冷却截止时间戳（认证类失败冷却，期内轮换跳过该把 key）
_KEY_COOLDOWN: dict = {}
_KEY_COOLDOWN_SECONDS = 600
_KEY_RR = {"n": 0}   # 全局轮换计数（跨上游共享即可，目的只是打散）
# 名称 -> 该上游支持模型集合（拉取成功后填充；None 表示尚未拉取 = 未知）
_UPSTREAM_MODELS = {}
# 模型 -> 可服务该模型的上游名称列表（按优先级升序）
_MODEL_UPSTREAMS = {}
# 合并后的全部模型 id（已排序去重）
_ALL_MODELS = []
_LAST_REFRESH = 0.0
_REFRESH_TTL = 300  # 秒
_CACHE_LOCK = asyncio.Lock()


def _build_clients():
    """根据配置重建客户端注册表（幂等）。

    密钥池：api_key 为主 key，api_keys（逗号/换行分隔）为备用 key；
    每把 key 独立构建一个 AsyncOpenAI 客户端，请求时按轮换挑一把
    （认证类失败的单把 key 进入短冷却，见 report_upstream_error）。
    """
    _KEY_CLIENTS.clear()
    for u in configs.UPSTREAMS:
        name = u["name"]
        keys = _upstream_keys(u)
        if not keys:
            # 没有密钥的上游不参与代理（但仍可在目录里占位？这里直接跳过）
            continue
        pool = []
        for i, key in enumerate(keys):
            kid = f"{name}#k{i}" if len(keys) > 1 else name
            try:
                client = AsyncOpenAI(api_key=key, base_url=u["base_url"] or None)
                client._apiproxy_key_id = kid
                pool.append((kid, client))
            except Exception as e:
                logging.error(f"Failed to build upstream client '{name}' (key#{i}): {e}")
        if not pool:
            continue
        _KEY_CLIENTS[name] = pool
        _CLIENTS[name] = pool[0][1]   # 主 key 客户端（兼容旧引用）


def _upstream_keys(u: dict) -> list:
    """合并主 key 与备用 key 列表（去重、保序）。"""
    keys = [u.get("api_key") or ""]
    extra = u.get("api_keys") or []
    if isinstance(extra, str):
        extra = [x for x in extra.replace("\n", ",").split(",")]
    for k in extra:
        k = (k or "").strip()
        if k:
            keys.append(k)
    out, seen = [], set()
    for k in keys:
        k = (k or "").strip()
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _key_pool(name: str) -> list:
    return _KEY_CLIENTS.get(name) or []


def pick_client(name: str):
    """为一次请求挑选该上游的客户端（密钥池轮换；认证失败冷却的 key 跳过）。

    全部 key 都在冷却中时仍返回主 key 客户端（尽力而为，与上游健康
    冷却「降权不是拉黑」的语义一致）。
    """
    pool = _key_pool(name)
    if not pool:
        return _CLIENTS.get(name)
    if len(pool) == 1:
        return pool[0][1]
    now = time.time()
    alive = [(kid, c) for kid, c in pool if _KEY_COOLDOWN.get(kid, 0) <= now]
    if not alive:
        return pool[0][1]
    _KEY_RR["n"] = (_KEY_RR["n"] + 1) % len(alive)
    return alive[_KEY_RR["n"]][1]


_AUTH_ERR_MARKERS = ('401', '403', 'invalid_api_key', 'invalid api key',
                     'incorrect api key', 'unauthorized', 'authentication',
                     'api key not valid', 'permission')


def report_upstream_error(client, err) -> bool:
    """上游调用失败时上报：认证类错误 -> 该把 key 进入冷却。

    client 即请求时用到的实例（自带 _apiproxy_key_id），无需额外传 key 身份。
    返回是否触发了 key 冷却。
    """
    kid = getattr(client, '_apiproxy_key_id', None)
    if not kid:
        return False
    msg = str(err or '').lower()
    if not any(m in msg for m in _AUTH_ERR_MARKERS):
        return False
    _KEY_COOLDOWN[kid] = time.time() + _KEY_COOLDOWN_SECONDS
    logging.warning(f"upstream key '{kid}' auth failure, cooldown {_KEY_COOLDOWN_SECONDS}s")
    return True


def report_upstream_ok(client):
    """上游调用成功：清除该把 key 的冷却（可能只是上游抖动后恢复了）。"""
    kid = getattr(client, '_apiproxy_key_id', None)
    if kid and kid in _KEY_COOLDOWN:
        _KEY_COOLDOWN.pop(kid, None)


def key_pool_snapshot() -> dict:
    """供管理端查看的密钥池状态（key_id -> {cooled, cooldown_remaining}）。"""
    now = time.time()
    out = {}
    for name, pool in _KEY_CLIENTS.items():
        out[name] = [{
            'key_id': kid,
            'cooled': _KEY_COOLDOWN.get(kid, 0) > now,
            'cooldown_remaining': max(0.0, _KEY_COOLDOWN.get(kid, 0) - now),
        } for kid, _c in pool]
    return out


def get_client(name: str):
    return _CLIENTS.get(name)


def upstream_models(name: str):
    """该上游已知的模型目录（set/list）；目录未知返回 None"""
    return _UPSTREAM_MODELS.get(name)


def iter_candidates(model: str, requested_name: str = None) -> list:
    """按优先级升序返回可用候选 [(client, name, priority), ...]。

    过滤规则与 select_upstream 一致：启用 + 未禁用该模型 +（已知目录则须包含该模型）。
    供 select_upstream 与 routing.build_chain（负载均衡/故障转移）复用。
    """
    candidates = []
    for u in configs.UPSTREAMS:
        if not u["enabled"]:
            continue
        if model in u["disabled_models"]:
            continue
        if requested_name and u["name"] != requested_name:
            continue
        # 已知目录且该上游明确不含此模型 -> 跳过
        cat = _UPSTREAM_MODELS.get(u["name"])
        if cat is not None and model not in cat:
            continue
        client = pick_client(u["name"])
        if client is not None:
            candidates.append((client, u["name"], u.get("priority", 0)))
    candidates.sort(key=lambda x: x[2])
    return candidates


def select_upstream(model: str, requested_name: str = None):
    """选择服务该模型的上游客户端。

    返回 (AsyncOpenAI 客户端, 上游名称) 或 None（无可用上游）。
    - requested_name 非空：仅在该名称的上游中挑选（仍要求启用且未禁用该模型）。
    - 否则：启用 + 未禁用该模型 + （已知目录则须包含该模型）中优先级最高者。
    """
    cands = iter_candidates(model, requested_name)
    if not cands:
        return None
    return cands[0][0], cands[0][1]


def upstream_supports_vision(upstream_name: str) -> bool:
    """上游是否声明支持多模态（视觉）输入。

    上游条目可选键 vision: true 声明（config.yaml 或未来 DB 扩展）；
    未声明一律视为纯文本上游——modality 预检测将拒绝携带图片/音频的请求。
    """
    for u in configs.UPSTREAMS:
        if u.get("name") == upstream_name:
            return bool(u.get("vision", False))
    return False


async def refresh_models(force: bool = False) -> list:
    """拉取各上游模型目录并合并。返回合并后的模型 id 列表。

    网络拉取在缓存锁外执行（带超时），避免单个上游 /models 挂起时
    永久占用锁、阻塞所有后续 /v1/models 请求；结果在锁内原子发布。
    """
    global _ALL_MODELS, _LAST_REFRESH
    now = time.time()

    # 1. 持锁：读缓存命中即返回；未命中则构建客户端并快照上游配置（无网络 IO，快速释放）
    async with _CACHE_LOCK:
        if not force and _ALL_MODELS and (now - _LAST_REFRESH) < _REFRESH_TTL:
            return _ALL_MODELS
        if not _CLIENTS:
            _build_clients()
        upstreams_snapshot = list(configs.UPSTREAMS)

    # 2. 锁外：逐个拉取上游模型目录（带超时，任一上游挂掉不阻塞其他上游，也不持有缓存锁）
    model_to_ups = {}
    fetched_catalog = {}
    for u in upstreams_snapshot:
        name = u["name"]
        client = _CLIENTS.get(name)
        if client is None:
            continue
        try:
            resp = await asyncio.wait_for(client.models.list(), timeout=30)
            raw = getattr(resp, "data", None) or []
            ids = [getattr(m, "id", None) for m in raw]
            ids = [i for i in ids if i]
            fetched_catalog[name] = set(ids)
            for mid in ids:
                model_to_ups.setdefault(mid, []).append(u)
            logging.info(f"Upstream '{name}' reported {len(ids)} models")
        except Exception as e:
            # 拉取失败：标记 None，发布时用 setdefault 保留历史目录
            fetched_catalog[name] = None
            logging.warning(f"Failed to list models from upstream '{name}': {e}")

    # 每个模型的可服务上游按优先级排序
    for mid, ups in model_to_ups.items():
        ups.sort(key=lambda x: x["priority"])
        model_to_ups[mid] = [x["name"] for x in ups]

    # 3. 持锁：原子发布结果（仅赋值，无网络 IO，不会长时间占用锁）
    async with _CACHE_LOCK:
        for name, ids in fetched_catalog.items():
            if ids is not None:
                _UPSTREAM_MODELS[name] = ids              # 成功覆盖
            else:
                _UPSTREAM_MODELS.setdefault(name, None)  # 失败保留历史目录
        _MODEL_UPSTREAMS.clear()
        _MODEL_UPSTREAMS.update(model_to_ups)
        _ALL_MODELS = sorted(model_to_ups.keys())
        _LAST_REFRESH = now
        return _ALL_MODELS


def list_all_models() -> list:
    """返回合并后的模型 id 列表（可能为空，若尚未刷新或上游均无目录）。"""
    return list(_ALL_MODELS)


def model_upstreams(model: str) -> list:
    """返回可服务该模型的上游名称（按优先级）。"""
    return list(_MODEL_UPSTREAMS.get(model, []))


async def startup_refresh():
    """应用启动时调用：从 DB 加载上游（若无则保留 config.yaml）、构建客户端并拉取一次模型目录。"""
    reload_upstreams_from_db()
    try:
        await refresh_models(force=True)
    except Exception as e:
        logging.warning(f"startup upstream model refresh failed: {e}")


def reload_upstreams_from_db():
    """从 DB 的 upstreams 表加载上游配置，覆盖 configs.UPSTREAMS 并重建客户端注册表。

    - DB 表不存在或为空：保留 configs.UPSTREAMS（即 config.yaml 配置）不变，返回 0。
    - 否则：以 DB 为准重写 configs.UPSTREAMS 并重建 _CLIENTS。
    返回加载到的上游数量（-1 表示读取失败）。
    代理路径 select_upstream 遍历 configs.UPSTREAMS，故无需改动代理代码即可热更新。
    """
    try:
        from . import db
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name, base_url, api_key, api_keys, priority, enabled, disabled_models "
                "FROM upstreams ORDER BY priority ASC, name ASC"
            )
            rows = cur.fetchall()
        finally:
            conn.close()
    except Exception as e:
        logging.warning(f"reload_upstreams_from_db: 读取 DB 失败，保留当前配置：{e}")
        return -1
    if not rows:
        return 0
    ups = []
    for r in rows:
        dm = r["disabled_models"] or ""
        if isinstance(dm, str):
            disabled = [x.strip() for x in dm.split(",") if x.strip()]
        elif isinstance(dm, list):
            disabled = [str(x).strip() for x in dm if str(x).strip()]
        else:
            disabled = []
        ak = r["api_keys"] if "api_keys" in r.keys() else None
        if isinstance(ak, str):
            extra_keys = [x.strip() for x in ak.replace("\n", ",").split(",") if x.strip()]
        elif isinstance(ak, list):
            extra_keys = [str(x).strip() for x in ak if str(x).strip()]
        else:
            extra_keys = []
        ups.append({
            "name": r["name"],
            "base_url": r["base_url"] or "",
            "api_key": r["api_key"] or "",
            "api_keys": extra_keys,
            "priority": int(r["priority"] if r["priority"] is not None else 100),
            "enabled": bool(int(r["enabled"] if r["enabled"] is not None else 1)),
            "disabled_models": disabled,
        })
    configs.UPSTREAMS = ups
    _CLIENTS.clear()
    _build_clients()
    logging.info(f"reload_upstreams_from_db: 已从 DB 加载 {len(ups)} 个上游")
    return len(ups)
