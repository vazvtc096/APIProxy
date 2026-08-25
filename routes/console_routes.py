"""Console 运维控制台路由。

  POST /internal/console   节点间内部端点：本地执行一条命令（供 dispatch 跨节点转发）。
                          鉴权：X-Internal-Secret（CLUSTER_SECRET / RCON_SECRET），无密钥时仅回环。
  POST /api/console/exec   运维人员运行时下发命令，支持 target（self/lb/worker:<id>/all）。
                          鉴权：X-RCON-Key（与原 RCON 共用最高权限密钥）。
  GET  /api/console/help   命令清单。
"""

from quart import Blueprint, request, jsonify

from ..core_console import (
    dispatch_async, run_locally_async, console_help_text, _internal_secret,
    console_tier_for_key, check_command_permission, TIER_NAMES,
)
from ..core_rcon import _verify_rcon_key

console_bp = Blueprint("console", __name__)


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


async def _check_internal_secret() -> bool:
    secret = request.headers.get("X-Internal-Secret", "")
    expected = _internal_secret()
    if expected:
        return secret == expected
    # 无共享密钥：仅允许回环（内网可信回退）
    ip = _client_ip()
    return ip.startswith("127.") or ip == "::1" or ip == "localhost"


@console_bp.route("/internal/console", methods=["POST"])
async def internal_console():
    if not await _check_internal_secret():
        return jsonify({"success": False, "output": "invalid internal secret", "data": {}}), 403
    try:
        payload = await request.get_json(force=True, silent=True) or {}
        command = payload.get("command")
        args = payload.get("args") or []
        if isinstance(args, str):
            args = args.split()
        if not command:
            return jsonify({"success": False, "output": "missing command", "data": {}}), 400
        result = await run_locally_async(command, args)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "output": f"error: {e}", "data": {}}), 500


@console_bp.route("/api/console/exec", methods=["POST"])
async def console_exec():
    key = request.headers.get("X-RCON-Key", "")
    if not await _verify_rcon_key(key):
        return jsonify({"error": "Invalid RCON/Console key"}), 403
    try:
        payload = await request.get_json(force=True, silent=True) or {}
        command = (payload.get("command") or "").strip()
        target = payload.get("target", "self") or "self"
        args = payload.get("args") or []
        if isinstance(args, str):
            args = args.split()
        if not command:
            return jsonify({"success": False, "output": "缺少 command", "data": {}}), 400

        # 精细化权限（目标 3.2）：校验密钥层级是否足以执行该命令
        tier = console_tier_for_key(key)
        ok, req = check_command_permission(command, tier)
        if not ok:
            return jsonify({
                "success": False,
                "output": (f"权限不足：命令 `{command}` 需层级 {req}({TIER_NAMES.get(req)})，"
                           f"当前密钥层级 {tier}({TIER_NAMES.get(tier)})"),
                "data": {"required_tier": req, "granted_tier": tier},
            }), 403

        result = await dispatch_async(command, args, target)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "output": f"error: {e}", "data": {}}), 500


@console_bp.route("/api/console/help", methods=["GET"])
async def console_help():
    return console_help_text(), 200, {"Content-Type": "text/plain; charset=utf-8"}
