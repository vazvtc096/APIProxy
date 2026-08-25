"""认证服务器路由。

  GET  /api/auth/status       认证服务器状态
  POST /api/auth/introspect  令牌自省（RFC 7662 风格；受 AUTH_SERVER_INTROSPECTION 开关）
  POST /api/auth/revoke      吊销会话（RCON 密钥保护）
  POST /internal/auth/verify 集群内部会话校验（X-Internal-Secret）
"""
from quart import Blueprint, request, jsonify

from .. import auth_server
from ..core_console import _internal_secret
from ..core_rcon import _verify_rcon_key

auth_bp = Blueprint("auth_server", __name__)


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


async def _check_internal_secret() -> bool:
    secret = request.headers.get("X-Internal-Secret", "")
    expected = _internal_secret()
    if expected:
        return secret == expected
    ip = _client_ip()
    return ip.startswith("127.") or ip == "::1" or ip == "localhost"


@auth_bp.route("/api/auth/status", methods=["GET"])
async def auth_status():
    return jsonify({"success": True, **auth_server.auth_status()})


@auth_bp.route("/api/auth/introspect", methods=["POST"])
async def auth_introspect():
    if not auth_server._introspection_enabled():
        return jsonify({"active": False, "error": "introspection disabled"}), 403
    try:
        payload = await request.get_json(force=True, silent=True) or {}
        token = payload.get("token") or ""
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth[len("Bearer "):]
        return jsonify(await auth_server.introspect(token))
    except Exception as e:
        return jsonify({"active": False, "error": str(e)}), 500


@auth_bp.route("/api/auth/revoke", methods=["POST"])
async def auth_revoke():
    if not await _verify_rcon_key(request.headers.get("X-RCON-Key", "")):
        return jsonify({"error": "Invalid RCON/Console key"}), 403
    try:
        payload = await request.get_json(force=True, silent=True) or {}
        sid = payload.get("session_id") or payload.get("token") or ""
        if not sid:
            return jsonify({"success": False, "error": "missing session_id"}), 400
        ok = await auth_server.revoke_session(sid)
        return jsonify({"success": ok})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@auth_bp.route("/internal/auth/verify", methods=["POST"])
async def auth_verify_internal():
    if not await _check_internal_secret():
        return jsonify({"success": False, "active": False, "error": "invalid internal secret"}), 403
    try:
        payload = await request.get_json(force=True, silent=True) or {}
        sid = payload.get("session_id") or ""
        active, user = await auth_server.verify_session(sid)
        return jsonify({"success": True, "active": active, "user": user})
    except Exception as e:
        return jsonify({"success": False, "active": False, "error": str(e)}), 500
