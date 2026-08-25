"""启动 / 运行时接口自检（目标 4.1）。

对全部 GET 路由做冒烟探测（经 Quart test_client），结果写入统一缓存
（默认 10 分钟 TTL），供 /api/health/* 与页面不稳定提示使用。

支持黑白名单（SELFTEST_BLACKLIST / SELFTEST_WHITELIST，前缀匹配）：
  - 白名单非空时，仅探测命中白名单前缀的端点；
  - 黑名单中的前缀一律跳过。

状态分级：
  ok   2xx / 3xx（含未登录的 302/401/403，属正常客户端行为）
  warn 4xx（多为鉴权类，非服务故障）
  fail 5xx / 连接异常（真实服务故障）
"""
import json
import logging
import time

from . import configs

logger = logging.getLogger(__name__)

CACHE_KEY = "selftest:results"


def _list_field(raw) -> list:
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in str(raw or "").split(",") if x.strip()]


def _is_skipped(path: str) -> bool:
    wl = _list_field(getattr(configs, "SELFTEST_WHITELIST", ""))
    bl = _list_field(getattr(configs, "SELFTEST_BLACKLIST", ""))
    if wl:
        return not any(path.startswith(w) for w in wl)
    for b in bl:
        if path.startswith(b):
            return True
    return False


async def run_endpoint_selftest(app=None) -> dict:
    """对全部 GET 路由做冒烟自检，结果写入缓存并返回。"""
    from .app import app as _default_app
    app = app or _default_app

    results = {
        "run_at": int(time.time()),
        "endpoints": [],
        "summary": {"total": 0, "ok": 0, "warn": 0, "fail": 0, "skip": 0},
    }

    try:
        async with app.test_client() as client:
            for rule in list(app.url_map.iter_rules()):
                if "GET" not in rule.methods:
                    continue
                path = rule.rule
                # 带路径参数的路由（如 /user/<uid>）无法凭空构造，跳过避免噪声
                if "<" in path:
                    continue
                # 静态资源与显式黑白名单
                if path.startswith("/static") or _is_skipped(path):
                    results["summary"]["skip"] += 1
                    results["endpoints"].append(
                        {"path": path, "status": None, "state": "skipped",
                         "note": "static or black/white list"})
                    continue
                try:
                    resp = await client.get(path)
                    code = resp.status_code
                    note = ""
                except Exception as e:  # noqa: BLE001 - 探测任何异常都记为 fail
                    code = 0
                    note = str(e)[:200]
                if code == 0:
                    state = "fail"
                elif 200 <= code < 400:
                    state = "ok"
                elif 400 <= code < 500:
                    state = "warn"
                else:
                    state = "fail"
                results["summary"][state] = results["summary"].get(state, 0) + 1
                results["summary"]["total"] += 1
                results["endpoints"].append(
                    {"path": path, "status": code, "state": state, "note": note})
    except Exception as e:  # noqa: BLE001
        logger.error("selftest runner failed: %s", e)
        results["error"] = str(e)

    _write_cache(results)
    return results


def _write_cache(results: dict) -> None:
    try:
        from . import cache_store
        cache_store.get_cache().setex(CACHE_KEY, configs.SELFTEST_CACHE_TTL, json.dumps(results))
    except Exception as e:  # noqa: BLE001
        logger.warning("selftest cache write failed: %s", e)


def get_cached_results() -> dict:
    """读取最近一次自检结果（优先缓存，10 分钟内直接返回）。"""
    try:
        from . import cache_store
        raw = cache_store.get_cache().get(CACHE_KEY)
        if raw is None:
            return {"endpoints": [], "summary": {}, "cached": False}
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")
        data = json.loads(raw) if isinstance(raw, str) else raw
        data["cached"] = True
        return data
    except Exception:  # noqa: BLE001
        return {"endpoints": [], "summary": {}, "cached": False}


def has_failures() -> bool:
    return bool(get_cached_results().get("summary", {}).get("fail"))
