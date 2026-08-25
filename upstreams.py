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

# 名称 -> AsyncOpenAI 客户端
_CLIENTS = {}
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
    """根据配置重建客户端注册表（幂等）。"""
    for u in configs.UPSTREAMS:
        name = u["name"]
        if not u.get("api_key"):
            # 没有密钥的上游不参与代理（但仍可在目录里占位？这里直接跳过）
            continue
        try:
            _CLIENTS[name] = AsyncOpenAI(
                api_key=u["api_key"],
                base_url=u["base_url"] or None,
            )
        except Exception as e:
            logging.error(f"Failed to build upstream client '{name}': {e}")


def get_client(name: str):
    return _CLIENTS.get(name)


def select_upstream(model: str, requested_name: str = None):
    """选择服务该模型的上游客户端。

    返回 (AsyncOpenAI 客户端, 上游名称) 或 None（无可用上游）。
    - requested_name 非空：仅在该名称的上游中挑选（仍要求启用且未禁用该模型）。
    - 否则：启用 + 未禁用该模型 + （已知目录则须包含该模型）中优先级最高者。
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
        candidates.append(u)
    if not candidates:
        return None
    if requested_name:
        # 指定上游：取第一个匹配（已通过上面的过滤）
        best = candidates[0]
    else:
        candidates.sort(key=lambda x: x["priority"])
        best = candidates[0]
    client = _CLIENTS.get(best["name"])
    if client is None:
        return None
    return client, best["name"]


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
                "SELECT name, base_url, api_key, priority, enabled, disabled_models "
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
        ups.append({
            "name": r["name"],
            "base_url": r["base_url"] or "",
            "api_key": r["api_key"] or "",
            "priority": int(r["priority"] if r["priority"] is not None else 100),
            "enabled": bool(int(r["enabled"] if r["enabled"] is not None else 1)),
            "disabled_models": disabled,
        })
    configs.UPSTREAMS = ups
    _CLIENTS.clear()
    _build_clients()
    logging.info(f"reload_upstreams_from_db: 已从 DB 加载 {len(ups)} 个上游")
    return len(ups)
