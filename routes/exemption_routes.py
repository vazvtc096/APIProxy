"""
豁免密钥路由
公开接口：
  POST /api/exemption/request      - 提交豁免申请
  GET  /api/exemption/status/<id>  - 查询申请状态

管理员接口：
  GET    /api/admin/exemption/pending   - 待审核列表
  GET    /api/admin/exemption/all       - 全部申请（可按状态过滤）
  POST   /api/admin/exemption/approve/<id>  - 批准
  POST   /api/admin/exemption/reject/<id>   - 拒绝
"""
import asyncio
import json
import logging
from quart import Blueprint, request, jsonify, session, Response
from ..exemption import (
    request_exemption, list_pending, list_all,
    approve_request, reject_request, get_request_status,
    register_listener, unregister_listener,
)
from ..core import _get_client_ip, _get_user_agent, _require_admin

exemption_bp = Blueprint('exemption', __name__)


# ---------- 公开接口 ----------

@exemption_bp.route('/api/exemption/request', methods=['POST'])
async def submit_request():
    """提交豁免申请（公开，无需登录）"""
    data = await request.get_json() or {}
    reason = data.get('reason', '').strip()

    client_ip = _get_client_ip()
    user_agent = _get_user_agent() if hasattr(__import__('..core', fromlist=['_get_user_agent']), '_get_user_agent') else ''
    device_fp = data.get('device_fingerprint', '').strip()

    success, msg, req_id = request_exemption(
        requester_ip=client_ip,
        requester_ua=user_agent,
        device_fingerprint=device_fp,
        reason=reason,
    )

    if success:
        return jsonify({'message': msg, 'request_id': req_id}), 201
    return jsonify({'error': msg, 'request_id': req_id}), 400


@exemption_bp.route('/api/exemption/status/<int:request_id>', methods=['GET'])
async def check_status(request_id):
    """查询申请状态（公开，但只能查自己 IP 提交的）"""
    client_ip = _get_client_ip()
    status = get_request_status(request_id, requester_ip=client_ip)
    if not status:
        return jsonify({'error': '申请不存在或无权查看'}), 404
    return jsonify(status)


# ---------- 管理员接口 ----------

@exemption_bp.route('/api/admin/exemption/pending', methods=['GET'])
async def admin_pending():
    """管理员：待审核列表"""
    err = await _require_admin()
    if err:
        return err
    pending = list_pending(limit=100)
    return jsonify({'pending': pending, 'count': len(pending)})


@exemption_bp.route('/api/admin/exemption/all', methods=['GET'])
async def admin_all():
    """管理员：全部申请，可按 status 过滤"""
    err = await _require_admin()
    if err:
        return err
    status = request.args.get('status', '').strip() or None
    requests = list_all(status=status, limit=200)
    return jsonify({'requests': requests, 'count': len(requests)})


@exemption_bp.route('/api/admin/exemption/approve/<int:request_id>', methods=['POST'])
async def admin_approve(request_id):
    """管理员：批准申请，返回 exemption key"""
    err = await _require_admin()
    if err:
        return err
    admin_name = session.get('user', 'unknown')
    success, msg, key = approve_request(request_id, admin_name)
    if success:
        return jsonify({
            'message': msg,
            'request_id': request_id,
            'exemption_key': key,
            'validity_seconds': 600,
            'note': '此密钥仅显示一次，请立即复制发给申请人。10分钟内有效，只能使用一次。',
        })
    return jsonify({'error': msg}), 400


@exemption_bp.route('/api/admin/exemption/reject/<int:request_id>', methods=['POST'])
async def admin_reject(request_id):
    """管理员：拒绝申请"""
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    reason = data.get('reason', '').strip()
    admin_name = session.get('user', 'unknown')
    success, msg = reject_request(request_id, admin_name, reason)
    if success:
        return jsonify({'message': msg, 'request_id': request_id})
    return jsonify({'error': msg}), 400


# ---------- SSE 实时推送（替代轮询） ----------

@exemption_bp.route('/api/exemption/stream/<int:request_id>', methods=['GET'])
async def exemption_stream(request_id):
    """
    SSE 实时推送豁免申请审核结果（callback 机制，替代前端轮询）。
    管理员批准/拒绝后，服务端主动 push 事件给前端，前端无需定时查询。
    事件类型：
      - connected: 连接建立
      - approved:  审核通过（携带 exemption_key）
      - rejected:  审核拒绝（携带 reason）
    每 30 秒发送一次心跳注释保持连接。
    """
    client_ip = _get_client_ip()

    # 检查申请是否存在且属于当前 IP
    status = get_request_status(request_id, requester_ip=client_ip)
    if not status:
        return jsonify({'error': '申请不存在或无权查看'}), 404

    # 如果已经是终态，直接返回结果（不需要 SSE）
    if status['status'] in ('approved', 'rejected', 'expired', 'used'):
        return jsonify(status)

    # 注册 SSE 监听器，等待审核结果回调
    q = register_listener(request_id)

    async def event_stream():
        try:
            # 连接建立事件
            yield f"event: connected\ndata: {json.dumps({'request_id': request_id, 'status': 'pending'})}\n\n"

            # 等待审核结果（最多等 10 分钟，与密钥有效期一致）
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30)
                    # 推送审核结果事件
                    yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                    # 终态事件后关闭连接
                    break
                except asyncio.TimeoutError:
                    # 30 秒心跳，保持连接（SSE 注释行，前端不会触发事件）
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            # 前端断开连接
            pass
        finally:
            unregister_listener(request_id, q)

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # 禁用 Nginx 缓冲，确保 SSE 实时推送
            'Connection': 'keep-alive',
        },
    )
