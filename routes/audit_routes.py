"""日志审计服务器路由。

  GET  /api/audit/query    按条件查询审计（Debug Console 密钥保护）
  GET  /api/audit/export   导出审计（JSON/CSV，Debug Console 密钥保护）
  GET  /api/audit/stats    最近 N 天审计统计
  POST /internal/audit     节点间转发收口（X-Internal-Secret）
"""
from quart import Blueprint, request, jsonify, Response

from .. import audit_server
from ..core_console import internal_secret_ok
from ..core_debug_console import _verify_debug_console_key

audit_bp = Blueprint("audit", __name__)


async def _check_internal_secret() -> bool:
    """节点间共享密钥；未配置时回退【真实对端回环】。

    注意：不使用客户端可控的 X-Forwarded-For 判定回环（可被伪造冒充内部节点）。
    """
    return internal_secret_ok(request.headers.get("X-Internal-Secret", ""))


@audit_bp.route("/api/audit/query", methods=["GET"])
async def audit_query():
    if not await _verify_debug_console_key(request.headers.get("X-Debug-Console-Key", "")):
        return jsonify({"error": "Invalid Debug Console/Console key"}), 403
    try:
        def _i(name, d=0):
            try:
                return int(request.args.get(name, d))
            except Exception:
                return d
        rows = await audit_server.query(
            limit=_i("limit", 50),
            category=request.args.get("category", ""),
            event_type=request.args.get("event_type", ""),
            severity=request.args.get("severity", ""),
            client_ip=request.args.get("client_ip", ""),
            user=request.args.get("user", ""),
            days=_i("days", 0),
        )
        return jsonify({"success": True, "count": len(rows), "events": rows})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@audit_bp.route("/api/audit/export", methods=["GET"])
async def audit_export():
    if not await _verify_debug_console_key(request.headers.get("X-Debug-Console-Key", "")):
        return jsonify({"error": "Invalid Debug Console/Console key"}), 403
    try:
        def _i(name, d=0):
            try:
                return int(request.args.get(name, d))
            except Exception:
                return d
        fmt = (request.args.get("fmt", "json") or "json").strip().lower()
        if fmt not in ("json", "csv"):
            # 格式名会进入 Content-Disposition 文件名，白名单化避免头注入 / 异常文件名
            return jsonify({"success": False, "error": "unsupported fmt"}), 400
        rows = await audit_server.query(
            limit=_i("limit", 5000),
            category=request.args.get("category", ""),
            event_type=request.args.get("event_type", ""),
            severity=request.args.get("severity", ""),
            client_ip=request.args.get("client_ip", ""),
            user=request.args.get("user", ""),
            days=_i("days", 0),
        )
        text = audit_server.export_rows(rows, fmt)
        mt = "application/json" if fmt == "json" else "text/csv"
        return Response(text, mimetype=mt,
                       headers={"Content-Disposition": f"attachment; filename=audit_export.{fmt}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@audit_bp.route("/api/audit/stats", methods=["GET"])
async def audit_stats():
    if not await _verify_debug_console_key(request.headers.get("X-Debug-Console-Key", "")):
        return jsonify({"error": "Invalid Debug Console/Console key"}), 403
    try:
        def _i(name, d=0):
            try:
                return int(request.args.get(name, d))
            except Exception:
                return d
        return jsonify({"success": True, "stats": await audit_server.stats(_i("days", 7))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@audit_bp.route("/internal/audit", methods=["POST"])
async def audit_internal():
    if not await _check_internal_secret():
        return jsonify({"success": False, "error": "invalid internal secret"}), 403
    try:
        data = await request.get_json(force=True, silent=True) or {}
        await audit_server.audit_log(
            data.get("category", "unknown"),
            data.get("event_type", "unknown"),
            data.get("severity", "low"),
            data.get("details", ""),
            data.get("user_uid", ""),
            data.get("user_name", ""),
            data.get("client_ip", ""),
            data.get("node_id", ""),
        )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
