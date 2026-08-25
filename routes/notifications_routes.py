"""通知铃铛路由：查询 / 标记已读 / 未读数。

与好友关系完全解耦——公告与系统通知写入 notifications 表后，前端通过本蓝图
的接口在右上角铃铛里实时读取，不再依赖 admin 这个「虚拟好友」聊天会话。

鉴权：登录会话（session）即可，与社交路由一致。
"""
from quart import Blueprint, request, session, jsonify

from .. import notifications as _ntf
from ..core import _get_current_user, _require_login

notif_bp = Blueprint("notif", __name__)


@notif_bp.route("/api/notifications", methods=["GET"])
async def api_notifications_list():
    """通知列表 + 未读数。?limit=30&unread=1 仅取未读。"""
    err = await _require_login()
    if err:
        return err
    user = await _get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    limit = min(int(request.args.get("limit", 30)), 100)
    unread_only = request.args.get("unread") == "1"
    items = await _ntf.get_notifications(user["uid"], limit=limit, unread_only=unread_only)
    total_unread = await _ntf.unread_count(user["uid"])
    return jsonify({"notifications": items, "unread_count": total_unread}), 200


@notif_bp.route("/api/notifications/unread", methods=["GET"])
async def api_notifications_unread():
    """仅返回未读数（供铃铛红点高频轮询 / SSE 复用）。"""
    err = await _require_login()
    if err:
        return err
    user = await _get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"unread_count": await _ntf.unread_count(user["uid"])}), 200


@notif_bp.route("/api/notifications/read", methods=["POST"])
async def api_notifications_read():
    """标记已读。body: {"id": "<nid>"} 标记单条；缺省 / id=all 标记全部。"""
    err = await _require_login()
    if err:
        return err
    user = await _get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = await request.get_json(silent=True) or {}
    notif_id = (data.get("id") or "all")
    if notif_id != "all" and not isinstance(notif_id, str):
        notif_id = str(notif_id)
    affected = await _ntf.mark_read(user["uid"], notif_id)
    return jsonify({"success": True, "affected": affected,
                    "unread_count": await _ntf.unread_count(user["uid"])}), 200
