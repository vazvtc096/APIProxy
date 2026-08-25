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
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app
