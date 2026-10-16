"""健康检查端点。

GET /health: 返回服务状态、版本、运行时间、数据库连接状态。
无需认证，可被负载均衡 / 容器编排调用。

接口自检（目标 4.1）：
  GET /api/health/summary    最近一次自检摘要（仅计数）
  GET /api/health/endpoints  完整端点列表与状态（含完整路由表 → 默认仅内网）
  GET /health/ui             人类可读的状态页（纯 HTML，含完整路由表 → 默认仅内网）
"""
import time
import sqlite3
from quart import Blueprint, jsonify, request

from .. import configs
from .. import selftest
from ..cloudflare import is_private_client

health_bp = Blueprint("health", __name__)

_START_TIME = time.time()


def _detail_allowed() -> bool:
    """健康自检明细是否允许当前请求读取。

    回传完整路由表属侦察面，默认仅回环/私网可见（经隧道时 get_client_ip()
    还原真实公网 IP，故公网请求被正确拒绝）。置 configs.HEALTH_DETAIL_INTERNAL_ONLY
    为 False 可放开。
    """
    if not getattr(configs, "HEALTH_DETAIL_INTERNAL_ONLY", True):
        return True
    try:
        return is_private_client()
    except Exception:
        return False

try:
    from importlib.metadata import version as _pkg_version
    _VERSION = _pkg_version("apiproxy") if _pkg_version("apiproxy") else "dev"
except Exception:
    _VERSION = "dev"


@health_bp.route("/health", methods=["GET"])
async def health_check():
    """健康检查：检查应用进程存活 + 数据库连接。"""
    uptime = round(time.time() - _START_TIME, 2)

    db_ok = False
    db_error = None
    try:
        from .. import db
        conn = db.get_conn()
        conn.execute("SELECT 1")
        conn.close()
        db_ok = True
    except Exception as e:
        db_error = str(e)

    status = "ok" if db_ok else "degraded"

    return jsonify({
        "status": status,
        "version": _VERSION,
        "uptime": uptime,
        "checks": {
            "database": {
                "status": "ok" if db_ok else "error",
                "error": db_error,
            },
        },
    }), 200 if db_ok else 503


@health_bp.route("/ready", methods=["GET"])
async def readiness_check():
    """就绪探针：检查所有依赖是否就绪（比 /health 存活探针更严格）。

    - 数据库为硬依赖：不可用则整体 not_ready（503）。
    - Redis 为软依赖：未配置记为 disabled；配置但不可用记为 degraded，
      不阻断就绪（有 SQLite 回退），供容器编排判断是否可接流量。
    """
    checks = {}
    ready = True

    # 数据库（硬依赖）
    try:
        from .. import db
        conn = db.get_conn()
        conn.execute("SELECT 1")
        conn.close()
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"
        ready = False

    # Redis（软依赖）
    try:
        from ..configs import REDIS_URL
        if not REDIS_URL:
            checks["redis"] = "disabled"
        else:
            from ..redis_client import get_redis
            r = get_redis()
            if r is None:
                checks["redis"] = "degraded"
            else:
                try:
                    r.ping()
                    checks["redis"] = "ok"
                except Exception as e:
                    checks["redis"] = f"error: {e}"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    status = "ready" if ready else "not_ready"
    return jsonify({"status": status, "checks": checks}), 200 if ready else 503


# --------------------------------------------------------------------------- #
# 接口自检结果（目标 4.1）
# --------------------------------------------------------------------------- #
@health_bp.route("/api/health/summary", methods=["GET"])
async def health_summary():
    data = selftest.get_cached_results()
    return jsonify({
        "summary": data.get("summary", {}),
        "run_at": data.get("run_at"),
        "cached": data.get("cached", False),
    }), 200


@health_bp.route("/api/health/endpoints", methods=["GET"])
async def health_endpoints():
    if not _detail_allowed():
        return jsonify({"error": "health detail is restricted to internal networks"}), 403
    return jsonify(selftest.get_cached_results()), 200


@health_bp.route("/health/ui", methods=["GET"])
async def health_ui():
    if not _detail_allowed():
        return ("health detail is restricted to internal networks", 403,
                {"Content-Type": "text/plain; charset=utf-8"})
    data = selftest.get_cached_results()
    s = data.get("summary", {})
    rows = []
    for e in data.get("endpoints", []):
        mark = {"ok": "OK", "warn": "WARN", "fail": "FAIL", "skipped": "SKIP"}.get(
            e.get("state"), "?")
        rows.append(
            "<tr><td>{mark}</td><td>{path}</td><td>{status}</td><td>{note}</td></tr>".format(
                mark=mark, path=e.get("path", ""), status=e.get("status", ""),
                note=(e.get("note") or "").replace("<", "&lt;")))
    html = f"""<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>APIProxy 接口健康</title></head>
<body>
<h1>APIProxy 接口自检</h1>
<p>上次运行：{data.get('run_at')} | 缓存：{data.get('cached', False)}</p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>状态</th><th>端点</th><th>HTTP</th><th>说明</th></tr>
{''.join(rows)}
</table>
<p>total={s.get('total')} ok={s.get('ok')} warn={s.get('warn')} fail={s.get('fail')} skip={s.get('skip')}</p>
</body>
</html>"""
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}
