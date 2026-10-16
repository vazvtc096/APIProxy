"""Prometheus 指标暴露与 HTTP 请求追踪。

提供 /metrics 端点（供 Prometheus 抓取），并记录基础 HTTP 指标：
    apiproxy_http_requests_total          按 method/route/status 的请求计数
    apiproxy_http_request_duration_seconds 按 method/route 的延迟直方图
    apiproxy_http_requests_in_progress    当前进行中的请求数

注意：route 标签用路由模板（如 /api/user/<uid>）而非原始 path，
避免把用户 UID / 帖子 ID 等高基数维度打爆时序库。
"""

import time

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

HTTP_REQUESTS_TOTAL = Counter(
    "apiproxy_http_requests_total",
    "HTTP 请求总数",
    ["method", "route", "status"],
)
HTTP_REQUEST_DURATION = Histogram(
    "apiproxy_http_request_duration_seconds",
    "HTTP 请求延迟（秒）",
    ["method", "route"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
HTTP_REQUESTS_IN_PROGRESS = Gauge(
    "apiproxy_http_requests_in_progress",
    "当前进行中的请求数",
)

# 进程级业务指标：上游延迟、令牌消耗、费用、上游错误。
# 由 core_tasks 的代理转发逻辑埋点，供容量规划与告警。
UPSTREAM_DURATION = Histogram(
    "apiproxy_upstream_duration_seconds",
    "上游 API 调用延迟（秒）",
    ["model", "upstream"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)
TOKENS_TOTAL = Counter(
    "apiproxy_tokens_total",
    "令牌消耗总数",
    ["model", "type"],
)
COST_TOTAL = Counter(
    "apiproxy_cost_total",
    "费用金额总计",
    ["model"],
)
UPSTREAM_ERRORS = Counter(
    "apiproxy_upstream_errors_total",
    "上游 API 错误总数",
    ["model", "upstream"],
)


def _route_label(request) -> str:
    """用路由模板作标签，404/无匹配时回退到原始 path。"""
    rule = getattr(request, "url_rule", None)
    if rule is not None and rule.rule:
        return rule.rule
    return request.path or "/"


def upstream_latency_summary() -> list:
    """从 UPSTREAM_DURATION 直方图提取每 (model, upstream) 的请求量与延迟分位。

    直方图是进程生命周期累计值（重启清零），分位由累计桶插值估算：
    P 值落在某桶内时按桶内线性插值；超出最大有限桶（应极罕见，>60s）
    时以最大有限桶为下界估算。返回按请求量降序的列表：
      [{model, upstream, count, avg_ms, p50_ms, p95_ms, p99_ms}, ...]
    """
    import math

    # {(model, upstream): {'buckets': [(le, cum)], 'count': n, 'sum': s}}
    data: dict = {}
    try:
        metrics = UPSTREAM_DURATION.collect()
    except Exception:
        return []
    for metric in metrics:
        for sample in metric.samples:
            labels = sample.labels or {}
            key = (labels.get("model", ""), labels.get("upstream", ""))
            d = data.setdefault(key, {"buckets": [], "count": 0, "sum": 0.0})
            name = sample.name
            if name.endswith("_bucket"):
                le_raw = labels.get("le")
                if le_raw is None:
                    continue
                le = math.inf if le_raw == "+Inf" else float(le_raw)
                d["buckets"].append((le, float(sample.value)))
            elif name.endswith("_count"):
                d["count"] = int(sample.value)
            elif name.endswith("_sum"):
                d["sum"] = float(sample.value)

    out = []
    for (model, upstream), d in data.items():
        count = d["count"]
        if count <= 0 or not d["buckets"]:
            continue
        cum = sorted(d["buckets"])
        finite_max = max((le for le, _ in cum if le != math.inf), default=1.0)

        def _quantile(q: float) -> float:
            target = q * count
            prev_le, prev_c = 0.0, 0.0
            for le, c in cum:
                if c >= target:
                    if le == math.inf:
                        le = finite_max
                    span = c - prev_c
                    if span <= 0:
                        return prev_le
                    frac = (target - prev_c) / span
                    return prev_le + (le - prev_le) * frac
                prev_le = le if le != math.inf else finite_max
                prev_c = c
            return finite_max

        out.append({
            "model": model,
            "upstream": upstream,
            "count": count,
            "avg_ms": round((d["sum"] / count) * 1000, 1),
            "p50_ms": round(_quantile(0.50) * 1000, 1),
            "p95_ms": round(_quantile(0.95) * 1000, 1),
            "p99_ms": round(_quantile(0.99) * 1000, 1),
        })
    out.sort(key=lambda x: -x["count"])
    return out


def _metrics_authorized() -> tuple:
    """校验 /metrics 访问权限：配置令牌则必须匹配，否则仅放行回环/私网来源。

    指标暴露了用量、费用、上游错误率等业务信息，经 Cloudflare 隧道时
    get_client_ip() 会还原真实公网 IP，故公网抓取一律被拒。
    """
    import hmac

    from quart import request

    from .. import configs
    from ..cloudflare import is_private_client

    token = (getattr(configs, "METRICS_TOKEN", "") or "").strip()
    if token:
        auth = (request.headers.get("Authorization") or "").strip()
        if auth[:7].lower() == "bearer ":
            presented = auth[7:].strip()
        else:
            presented = (request.args.get("token") or "").strip()
        if hmac.compare_digest(presented, token):
            return True, ""
        return False, "invalid metrics token"

    if not getattr(configs, "METRICS_ALLOW_PRIVATE", True):
        return False, "metrics endpoint disabled"

    if is_private_client():
        return True, ""
    return False, "metrics endpoint restricted to internal networks"


def setup_metrics(app):
    """注册 /metrics 端点与请求追踪钩子。"""
    from quart import Response, g, request

    @app.before_request
    async def _metrics_start():
        g._metrics_start = time.perf_counter()
        HTTP_REQUESTS_IN_PROGRESS.inc()

    @app.after_request
    async def _metrics_end(response):
        route = _route_label(request)
        start = getattr(g, "_metrics_start", time.perf_counter())
        duration = time.perf_counter() - start
        HTTP_REQUESTS_TOTAL.labels(
            request.method, route, str(response.status_code)
        ).inc()
        HTTP_REQUEST_DURATION.labels(request.method, route).observe(duration)
        HTTP_REQUESTS_IN_PROGRESS.dec()
        return response

    @app.route("/metrics", methods=["GET"])
    async def metrics():
        ok, err = _metrics_authorized()
        if not ok:
            return Response(err + "\n", status=403, mimetype="text/plain")
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app
