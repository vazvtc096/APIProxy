"""充值与交易路由"""
import asyncio
import datetime

from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from .. import payments as _payments
from .. import db as _db
from ..core_db import _get_conn
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, DEBUG_CONSOLE_ENABLED, DEBUG_CONSOLE_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from ..configs import PAYMENT, PAYMENT_ENABLED
from .. import configs
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf
from .. import cache_store
from ..utils.qr import qr_svg

recharge_bp = Blueprint('recharge', __name__)

@recharge_bp.route('/api/recharge/request', methods=['POST'])
async def recharge_request():
    """用户提交充值请求"""
    # 限流检查
    allowed, remaining = _check_rate_limit('recharge')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429
    
    _oerr = await _oauth_ensure_user(['transactions:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = await request.get_json() or {}
    amount = data.get('amount', 0.0)
    
    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'error': 'Amount must be a positive number'}), 400
    
    # 限制最大充值金额
    if amount > 10000:
        return jsonify({'error': 'Amount too large (max 10000)'}), 400
    
    user_name = session['user']
    
    # 获取用户信息
    users = await async_db_query(
        "SELECT uid, user_name FROM users WHERE user_name = ?",
        (user_name,)
    )
    if not users:
        return jsonify({'error': 'User not found'}), 404
    
    user_data = users[0]
    request_id = _generate_request_id()
    
    # 插入充值请求
    await async_db_query(
        """INSERT INTO recharge_requests 
           (request_id, user_uid, user_name, amount, status) 
           VALUES (?, ?, ?, ?, 'pending')""",
        (request_id, user_data['uid'], user_name, amount)
    )
    
    return jsonify({
        'message': 'Recharge request submitted',
        'request_id': request_id,
        'amount': amount,
        'status': 'pending'
    }), 201



@recharge_bp.route('/api/recharge/my-requests', methods=['GET'])
async def my_recharge_requests():
    """查看我的充值请求"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user_name = session['user']
    
    # 获取查询参数
    status = request.args.get('status', '')
    limit = min(int(request.args.get('limit', 20)), 100)
    offset = int(request.args.get('offset', 0))
    
    # 构建查询
    sql = "SELECT * FROM recharge_requests WHERE user_name = ?"
    args = [user_name]
    
    if status and status in ['pending', 'approved', 'rejected']:
        sql += " AND status = ?"
        args.append(status)
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    
    requests = await async_db_query(sql, args)
    
    return jsonify({
        'requests': requests,
        'total': len(requests)
    })


# ---------- 管理员路由 ----------

@recharge_bp.route('/api/transactions', methods=['GET'])
async def my_transactions():
    """获取我的余额变动记录"""
    _oerr = await _oauth_ensure_user(['transactions:read'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    page = int(request.args.get('page', 1))
    page_size = min(int(request.args.get('page_size', 20)), 100)
    offset = (page - 1) * page_size
    tx_type = request.args.get('type', '')
    
    # 构建查询
    sql = "SELECT * FROM balence_transactions WHERE user_uid = ?"
    args = [user['uid']]
    
    if tx_type:
        sql += " AND type = ?"
        args.append(tx_type)
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([page_size, offset])
    
    transactions = await async_db_query(sql, args)
    
    # 获取总数
    count_sql = "SELECT COUNT(*) as cnt FROM balence_transactions WHERE user_uid = ?"
    count_args = [user['uid']]
    if tx_type:
        count_sql += " AND type = ?"
        count_args.append(tx_type)
    
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'transactions': transactions,
        'total': total,
        'page': page,
        'page_size': page_size
    })

# ---------- 模型列表（自动获取上游） ----------
# GET /v1/models 与 /api/models（兼容别名）：合并所有上游 API Key 的 /models 目录，缓存 MODELS_CACHE_TTL 秒。
# 鉴权：Bearer（API Key 或 OAuth api scope）或浏览器 cookie 会话。
MODELS_CACHE_TTL = 300
_MODELS_CACHE = {'ts': 0.0, 'data': None}



@recharge_bp.route('/api/usage/summary', methods=['GET'])
async def api_usage_summary():
    """当前用户用量汇总（费用 / 请求数 / 按模型 / 每日趋势）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    days = request.args.get('days', 7, type=int)
    days = max(1, min(days, 365))
    user_name = user['user_name']

    # 用量汇总为读多写少的聚合查询，按 user+days 短缓存（默认 15s），
    # 削减每打开概览/用量页对 usage_logs 的多段聚合扫描压力。
    cache_key = f"usage:summary:{user_name}:{days}"
    cached = cache_store.cache_get_json(cache_key)
    if cached is not None:
        return jsonify(cached), 200

    daily = await _usage_daily(user_name=user_name, days=days)
    models_daily = await _usage_daily_by_model(user_name=user_name, days=days)
    models = await async_db_query(
        """SELECT model, COUNT(*) as requests, COALESCE(SUM(cost), 0) as cost,
                  COALESCE(SUM(total_tokens), 0) as tokens
           FROM usage_logs
           WHERE user_name = ? AND created_at >= DATE('now', '-' || ? || ' days')
           GROUP BY model ORDER BY cost DESC""",
        (user_name, days)
    ) or []
    totals = await async_db_query(
        """SELECT COUNT(*) as requests, COALESCE(SUM(cost), 0) as cost,
                  COALESCE(SUM(total_tokens), 0) as tokens,
                  COALESCE(SUM(input_tokens), 0) as in_tokens,
                  COALESCE(SUM(output_tokens), 0) as out_tokens
           FROM usage_logs WHERE user_name = ? AND created_at >= DATE('now', '-' || ? || ' days')""",
        (user_name, days)
    )
    t = totals[0] if totals else {'requests': 0, 'cost': 0, 'tokens': 0, 'in_tokens': 0, 'out_tokens': 0}
    payload = {
        'days': days,
        'total': {'requests': t['requests'], 'cost': round(float(t['cost'] or 0), 6),
                  'tokens': t['tokens'], 'input_tokens': t['in_tokens'],
                  'output_tokens': t['out_tokens']},
        'daily': daily,
        'models_daily': models_daily,
        'models': [{'model': m['model'], 'requests': m['requests'],
                    'cost': round(float(m['cost'] or 0), 6), 'tokens': m['tokens']} for m in models],
    }
    cache_store.cache_set_json(cache_key, payload, ttl=15)
    return jsonify(payload), 200


# ============================================================================
# 在线支付（可配置多支付方式：epay / wechatpay / alipay / stripe / paypal）
# 下单 -> 网关收银台 -> 异步回调入账；查单兜底
# ============================================================================

MAX_RECHARGE_AMOUNT = 10000  # 与 /api/recharge/request 保持一致


async def _credit_request(request_id: str, order_no: str, channel: str, amount: float) -> tuple:
    """幂等入账：CAS 抢占（pending/failed -> approved），成功者才加余额并记账。

    返回 (ok, message)。并发回调 / 查单兜底同时触发时仅第一个事务生效。
    """
    def _tx():
        conn = _get_conn()
        try:
            _db.begin_write(conn)
            cur = conn.cursor()
            cur.execute("SELECT * FROM recharge_requests WHERE request_id = ?", (request_id,))
            req = cur.fetchone()
            if not req:
                return False, "充值请求不存在"
            if req['status'] == 'approved':
                return True, "已入账（幂等命中）"
            if req['status'] not in ('pending', 'failed'):
                return False, f"充值请求状态为 {req['status']}，无法入账"
            if abs(float(req['amount'] or 0) - float(amount)) > 1e-6:
                return False, f"金额不匹配（本地 {req['amount']} / 网关 {amount}），拒绝入账"
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cur.execute(
                """UPDATE recharge_requests
                   SET status = 'approved', processed_at = ?, pay_channel = ?, pay_order_no = ?
                   WHERE request_id = ? AND status IN ('pending', 'failed')""",
                (now, channel, str(order_no or ''), request_id)
            )
            if cur.rowcount != 1:
                conn.rollback()
                return True, "已入账（并发幂等命中）"
            cur.execute(
                "UPDATE users SET balence = COALESCE(balence, 0) + ? WHERE user_name = ?",
                (amount, req['user_name'])
            )
            cur.execute("SELECT balence FROM users WHERE user_name = ?", (req['user_name'],))
            row = cur.fetchone()
            new_bal = float(row['balence'] or 0.0) if row else 0.0
            cur.execute(
                """INSERT INTO balence_transactions
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'recharge', ?, ?, ?, ?)""",
                ('bt_' + generate_uid(), req['user_uid'], req['user_name'],
                 round(float(amount), 6), round(new_bal, 6), str(order_no or ''),
                 f'{channel} 在线支付')
            )
            conn.commit()
            return True, "入账成功"
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            return False, f"入账事务失败: {e}"
        finally:
            conn.close()
    return await asyncio.to_thread(_tx)


@recharge_bp.route('/api/payment-methods', methods=['GET'])
async def payment_methods():
    """返回当前可用的在线支付方式（前端渲染支付选择器）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({
        'enabled': _payments.enabled(PAYMENT),
        'methods': _payments.available_methods(PAYMENT),
    })


@recharge_bp.route('/api/recharge/pay', methods=['POST'])
async def recharge_pay():
    """在线充值：按所选支付方式在网关创建订单，返回收银台跳转地址"""
    if not _payments.enabled(PAYMENT):
        return jsonify({'error': '在线支付通道未启用'}), 404
    allowed, _ = _check_rate_limit('recharge')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429
    _oerr = await _oauth_ensure_user(['transactions:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data = await request.get_json() or {}
    method = str(data.get('method') or '').strip().lower()
    try:
        amount = round(float(data.get('amount', 0)), 2)
    except (TypeError, ValueError):
        return jsonify({'error': 'Amount must be a positive number'}), 400
    if amount <= 0:
        return jsonify({'error': 'Amount must be a positive number'}), 400
    if amount > MAX_RECHARGE_AMOUNT:
        return jsonify({'error': f'Amount too large (max {MAX_RECHARGE_AMOUNT})'}), 400

    provider = _payments.get_provider(PAYMENT, method)
    if not provider or not provider.enabled:
        return jsonify({'error': '不支持的支付方式或该方式未启用'}), 400

    user_name = session['user']
    users = await async_db_query(
        "SELECT uid, user_name FROM users WHERE user_name = ?", (user_name,))
    if not users:
        return jsonify({'error': 'User not found'}), 404
    user_data = users[0]

    request_id = _generate_request_id()
    await async_db_query(
        """INSERT INTO recharge_requests
           (request_id, user_uid, user_name, amount, status, pay_channel)
           VALUES (?, ?, ?, ?, 'pending', ?)""",
        (request_id, user_data['uid'], user_name, amount, method)
    )

    resp = await provider.create_order(request_id, amount, "APIProxy 余额充值")
    if resp.get('error') or not (resp.get('pay_url') or resp.get('qr_code')):
        # 下单失败：标记 failed（网关若实际已建单，回调/查单仍可入账）
        await async_db_query(
            "UPDATE recharge_requests SET status = 'failed', admin_remark = ? WHERE request_id = ?",
            (str(resp.get('error') or '网关未返回支付地址')[:200], request_id)
        )
        return jsonify({'error': resp.get('error') or '网关下单失败'}), 502

    qr_code = str(resp.get('qr_code') or '')
    await async_db_query(
        "UPDATE recharge_requests SET pay_order_no = ?, pay_qr_url = ? WHERE request_id = ?",
        (str(resp.get('order_no') or ''), qr_code, request_id)
    )
    return jsonify({
        'request_id': request_id,
        'method': method,
        'order_no': resp.get('order_no') or '',
        'amount': amount,
        'pay_url': resp.get('pay_url') or '',
        'qr_code': qr_code,
        # 服务端统一渲染二维码：微信 NATIVE 的 code_url 前端无法直接扫码，
        # 这里给出二维码图片地址（前端 <img src>）与内联 SVG（即时渲染）。
        'qr_url': f'/api/recharge/qr/{request_id}' if qr_code else '',
        'qr_svg': qr_svg(qr_code) or '' if qr_code else '',
        'status': str(resp.get('status') or 'PENDING'),
    }), 201


@recharge_bp.route('/api/recharge/callback/<method>', methods=['GET', 'POST'])
async def payment_callback(method):
    """网关异步回调（服务端对服务端，验签，无会话）。

    同时接受 GET（易支付等）与 POST（JSON / 表单 / XML，微信）两种回调。
    """
    provider = _payments.get_provider(PAYMENT, method)
    if not provider or not provider.enabled:
        return jsonify({'error': 'unknown payment method'}), 404

    if request.method == 'GET':
        data = dict(request.args)
        raw = b""
    else:
        raw = await request.get_data()
        data = await request.get_json(silent=True)
        if data is None:
            form = await request.form
            data = dict(form) if form else {}
    headers = {k: v for k, v in request.headers.items()}

    res = await provider.parse_callback(data, headers=headers, raw=raw)
    if not res.get('ok'):
        body, mime = provider.callback_ack(False)
        return Response(body, mimetype=mime), 400

    # 非成功事件（下单/过期等）：确认即可，避免网关无谓重试
    if str(res.get('status') or '').upper() != 'PAID':
        body, mime = provider.callback_ack(True)
        return Response(body, mimetype=mime), 200

    request_id = str(res.get('request_id') or '')
    order_no = str(res.get('order_no') or '')
    row = await async_db_query(
        "SELECT request_id, user_name, amount FROM recharge_requests"
        " WHERE request_id = ? OR (pay_order_no IS NOT NULL AND pay_order_no != '' AND pay_order_no = ?)",
        (request_id, order_no),
        fetch_one=True,
    )
    if not row:
        # 本地无此订单：确认（网关重试也无法处理），留日志排查
        return jsonify({'ok': True, 'ignored': 'unknown order'}), 200

    try:
        amount = float(res.get('amount'))
    except (TypeError, ValueError):
        amount = float(row['amount'])
    ok, msg = await _credit_request(row['request_id'], order_no, str(method), amount)
    if not ok:
        # 让网关按各自策略重试
        body, mime = provider.callback_ack(False)
        return Response(body, mimetype=mime), 500

    await _hooks.fire_event('RECHARGE_APPROVED', trigger_user=row['user_name'],
                            target_user=row['user_name'], amount=row['amount'])
    body, mime = provider.callback_ack(True)
    return Response(body, mimetype=mime), 200


@recharge_bp.route('/api/recharge/status/<request_id>', methods=['GET'])
async def payment_status(request_id):
    """查单兜底：网关回调丢失时，主动向网关查单并补入账"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    row = await async_db_query(
        "SELECT * FROM recharge_requests WHERE request_id = ? AND user_name = ?",
        (request_id, session['user']),
        fetch_one=True,
    )
    if not row:
        return jsonify({'error': 'Request not found'}), 404

    channel = str(row['pay_channel'] or '')
    provider = _payments.get_provider(PAYMENT, channel) if channel else None
    if row['status'] in ('pending', 'failed') and provider and provider.enabled:
        q = await provider.query_order(request_id, row['pay_order_no'])
        if str(q.get('status') or '').upper() == 'PAID':
            ok, _ = await _credit_request(request_id,
                                          str(q.get('order_no') or row['pay_order_no'] or ''),
                                          channel, float(row['amount']))
            if ok:
                await _hooks.fire_event('RECHARGE_APPROVED', trigger_user=row['user_name'],
                                        target_user=row['user_name'], amount=row['amount'])
                row['status'] = 'approved'
    return jsonify({
        'request_id': request_id,
        'amount': row['amount'],
        'status': row['status'],
        'pay_channel': row['pay_channel'],
        'pay_order_no': row['pay_order_no'],
    })


@recharge_bp.route('/api/recharge/qr/<request_id>', methods=['GET'])
async def payment_qr(request_id):
    """返回待支付订单的二维码图片（SVG）。

    微信 NATIVE 等扫码支付下单后返回的是 code_url 字符串，浏览器无法直接扫码，
    这里由服务端渲染为二维码。安全约束：
      - 仅订单本人可访问；
      - 二维码内容恒取自本订单已落库的 pay_qr_url（网关下发），
        不接受任何外部 data 参数，杜绝被当作任意二维码/钓鱼图片生成器。
    """
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    row = await async_db_query(
        "SELECT pay_qr_url FROM recharge_requests WHERE request_id = ? AND user_name = ?",
        (request_id, session['user']),
        fetch_one=True,
    )
    if not row or not row.get('pay_qr_url'):
        return jsonify({'error': 'No QR code for this request'}), 404
    svg = qr_svg(str(row['pay_qr_url']))
    if not svg:
        return jsonify({'error': 'QR generation unavailable'}), 503
    resp = Response(svg, mimetype='image/svg+xml')
    resp.headers['Cache-Control'] = 'private, max-age=300'
    return resp



