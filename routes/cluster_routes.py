"""集群状态端点与管理鉴权。

- GET /cluster/login        ：登录页（手动点击「登录」建立会话）
- GET /cluster/nodes       ：在线 Worker 列表（含指标与负载得分，按得分升序）
- GET /cluster/route       ：当前最优 Worker 的 host:port（供 LB/客户端路由）

鉴权（满足「每次启动随机 Token」要求）：
- 两种放行方式：URL 携带 ?token=<CLUSTER_TOKEN>，或先访问 /cluster/login 点击登录写入会话。
- 未携带有效凭据（且无会话）时：浏览器访问跳转到登录页；API 携带了错误 token 则返回 403 JSON。
- 仅 LB 角色下 nodes 才有数据；Worker 角色下 nodes 为空。
"""

from quart import Blueprint, jsonify, request, session, redirect

from .. import configs
from ..cluster import cluster, get_cluster_token

cluster_bp = Blueprint("cluster", __name__)

_SESSION_KEY = "cluster_auth"

_LOGIN_PAGE = (
    "<!doctype html>"
    "<html lang='zh-CN'><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1'>"
    "<title>集群管理登录</title>"
    "<style>"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;"
    "background:#f5f6f8;color:#1f2329;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
    ".card{background:#fff;border:1px solid #e5e6eb;border-radius:12px;padding:32px 36px;width:360px;box-shadow:0 4px 16px rgba(0,0,0,.06)}"
    "h2{margin:0 0 6px;font-size:20px}"
    "p.sub{margin:0 0 20px;color:#86909c;font-size:13px}"
    "label{display:block;font-size:13px;color:#4e5969;margin-bottom:6px}"
    "input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #c9cdd4;border-radius:8px;font-size:14px;margin-bottom:14px}"
    "button{width:100%;padding:10px;border:0;border-radius:8px;background:#3370ff;color:#fff;font-size:14px;cursor:pointer}"
    "button:hover{background:#2861e6}"
    ".err{color:#f53f3f;font-size:13px;margin-bottom:12px;min-height:18px}"
    ".hint{margin-top:14px;font-size:12px;color:#86909c;line-height:1.6}"
    "</style></head><body><div class='card'>"
    "<h2>集群管理登录</h2>"
    "<p class='sub'>请输入本次启动生成的集群管理令牌</p>"
    "<form method='post' action='/cluster/login'>"
    "<label for='token'>管理令牌 (CLUSTER_TOKEN)</label>"
    "<input id='token' name='token' type='text' placeholder='从启动日志获取' autocomplete='off' autofocus>"
    "<div class='err'>__ERR__</div>"
    "<button type='submit'>登录</button>"
    "</form>"
    "<p class='hint'>令牌在进程启动时打印于日志（CLUSTER_TOKEN）。也可在 API 请求中直接附加 ?token=&lt;CLUSTER_TOKEN&gt; 访问。</p>"
    "</div></body></html>"
)


async def _request_token() -> str:
    """从 URL 查询参数或表单中取 token（GET 用 query，登录 POST 用 form）。"""
    t = request.args.get("token")
    if t:
        return t.strip()
    try:
        form = await request.form
        if form and form.get("token"):
            return form.get("token").strip()
    except Exception:
        pass
    return ""


async def _authed() -> bool:
    """已通过 URL token 或登录会话鉴权。"""
    if await _request_token() == get_cluster_token():
        return True
    return bool(session.get(_SESSION_KEY))


def _deny():
    """未鉴权时的分流：API（带了 token）回 403 JSON；浏览器跳转登录页。"""
    return redirect("/cluster/login")


async def _deny_async():
    if await _request_token():
        return jsonify({"error": "invalid or missing token",
                        "hint": "pass ?token=<CLUSTER_TOKEN> or login at /cluster/login"}), 403
    return redirect("/cluster/login")


@cluster_bp.route("/cluster/login", methods=["GET", "POST"])
async def cluster_login():
    token = await _request_token()
    # 令牌正确（URL 或表单）：写入会话并跳转管理页（首次登录会下发会话 Cookie）
    if token == get_cluster_token():
        session[_SESSION_KEY] = True
        return redirect("/cluster/nodes")
    # 已登录（会话态）直接跳转
    if await _authed():
        return redirect("/cluster/nodes")
    err = "令牌错误，请检查启动日志中的 CLUSTER_TOKEN" if token else ""
    return _LOGIN_PAGE.replace("__ERR__", err), 200


@cluster_bp.route("/cluster/logout")
async def cluster_logout():
    session.pop(_SESSION_KEY, None)
    return redirect("/cluster/login")


@cluster_bp.route("/cluster/nodes")
async def cluster_nodes():
    if not await _authed():
        denied = await _deny_async()
        if denied is not None:
            return denied
    if not configs.CLUSTER_ENABLED:
        return jsonify({"enabled": False, "role": None, "nodes": []})
    nodes = cluster.get_nodes()
    return jsonify({
        "enabled": True,
        "role": cluster.role,
        "count": len(nodes),
        "nodes": [
            {
                "node_id": n.get("node_id"),
                "host": n.get("host"),
                "port": n.get("port"),
                "cpu": n.get("cpu"),
                "mem": n.get("mem"),
                "conn": n.get("conn"),
                "score": round(n.get("score", 0), 2),
            }
            for n in nodes
        ],
    })


@cluster_bp.route("/cluster/route")
async def cluster_route():
    if not await _authed():
        denied = await _deny_async()
        if denied is not None:
            return denied
    if not configs.CLUSTER_ENABLED:
        return jsonify({"error": "cluster disabled"}), 404
    best = cluster.select_best()
    if not best:
        return jsonify({"error": "no available worker"}), 503
    return jsonify({
        "host": best.get("host"),
        "port": best.get("port"),
        "node_id": best.get("node_id"),
        "score": round(best.get("score", 0), 2),
    })
