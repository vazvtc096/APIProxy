"""充值与交易路由"""
import asyncio
import datetime

from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from .. import bank_pay
from .. import db as _db
from ..core_db import _get_conn
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, DEBUG_CONSOLE_ENABLED, DEBUG_CONSOLE_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from ..configs import BANK_PAY, BANK_PAY_ENABLED
from .. import configs
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf
from .. import cache_store

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
# analogBank 在线支付通道（商户网关：下单 -> 收银台 -> 异步回调入账）
# ============================================================================

MAX_RECHARGE_AMOUNT = 10000  # 与 /api/recharge/request 保持一致


async def _bank_credit(request_id: str, bank_order_no: str, amount: float) -> tuple:
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
                return False, f"金额不匹配（本地 {req['amount']} / 银行 {amount}），拒绝入账"
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cur.execute(
                """UPDATE recharge_requests
                   SET status = 'approved', processed_at = ?, pay_channel = 'analogbank', bank_order_no = ?
                   WHERE request_id = ? AND status IN ('pending', 'failed')""",
                (now, bank_order_no, request_id)
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
                 round(float(amount), 6), round(new_bal, 6), bank_order_no,
                 'analogBank 在线支付')
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


@recharge_bp.route('/api/recharge/bank/pay', methods=['POST'])
async def bank_pay_create():
    """在线充值：在 analogBank 创建支付订单，返回收银台跳转地址"""
    if not bank_pay.bank_pay_enabled():
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
    try:
        amount = round(float(data.get('amount', 0)), 2)
    except (TypeError, ValueError):
        return jsonify({'error': 'Amount must be a positive number'}), 400
    if amount <= 0:
        return jsonify({'error': 'Amount must be a positive number'}), 400
    if amount > MAX_RECHARGE_AMOUNT:
        return jsonify({'error': f'Amount too large (max {MAX_RECHARGE_AMOUNT})'}), 400

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
           VALUES (?, ?, ?, ?, 'pending', 'analogbank')""",
        (request_id, user_data['uid'], user_name, amount)
    )

    resp = await bank_pay.create_order(request_id, f"{amount:.2f}", f"APIProxy 余额充值")
    if resp.get('error') or not resp.get('order_no'):
        # 下单失败：标记 failed（银行若实际已建单，回调/查单仍可入账）
        await async_db_query(
            "UPDATE recharge_requests SET status = 'failed', admin_remark = ? WHERE request_id = ?",
            (str(resp.get('error'))[:200], request_id)
        )
        return jsonify({'error': resp.get('error') or '银行网关下单失败'}), 502

    await async_db_query(
        "UPDATE recharge_requests SET bank_order_no = ? WHERE request_id = ?",
        (resp['order_no'], request_id)
    )
    pay_url = resp.get('pay_url') or f"/pay/{resp['order_no']}"
    return jsonify({
        'request_id': request_id,
        'order_no': resp['order_no'],
        'amount': amount,
        'pay_url': BANK_PAY['public_url'] + pay_url,
        'status': resp.get('status', 'PENDING'),
    }), 201


@recharge_bp.route('/api/recharge/bank/callback', methods=['POST'])
async def bank_pay_callback():
    """analogBank 异步回调（服务端对服务端，HMAC-SHA256 验签，无会话）"""
    data = await request.get_json(silent=True) or {}
    if not bank_pay.verify_callback(data):
        return jsonify({'error': '签名校验失败'}), 401
    # 非成功事件（过期等）直接确认，避免银行无谓重试
    if data.get('event') != 'payment.success' or data.get('status') != 'PAID':
        return jsonify({'ok': True})

    order_no = str(data.get('order_no') or '')
    merchant_order = str(data.get('merchant_order') or '')
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'error': 'amount 非法'}), 400

    row = await async_db_query(
        "SELECT request_id, user_name, amount FROM recharge_requests"
        " WHERE bank_order_no = ? OR request_id = ?",
        (order_no, merchant_order),
        fetch_one=True,
    )
    if not row:
        # 本地无此订单：200 确认（银行重试也无法处理），留日志排查
        return jsonify({'ok': True, 'ignored': 'unknown order'}), 200

    ok, msg = await _bank_credit(row['request_id'], order_no, amount)
    if not ok:
        # 让银行按 30s/120s 重试
        return jsonify({'error': msg}), 500

    await _hooks.fire_event('RECHARGE_APPROVED', trigger_user=row['user_name'],
                            target_user=row['user_name'], amount=row['amount'])
    return jsonify({'ok': True}), 200


@recharge_bp.route('/api/recharge/bank/status/<request_id>', methods=['GET'])
async def bank_pay_status(request_id):
    """查单兜底：银行回调丢失时，主动向银行查单并补入账"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    row = await async_db_query(
        "SELECT * FROM recharge_requests WHERE request_id = ? AND user_name = ?",
        (request_id, session['user']),
        fetch_one=True,
    )
    if not row:
        return jsonify({'error': 'Request not found'}), 404

    if row['status'] in ('pending', 'failed') and row['pay_channel'] == 'analogbank' \
            and bank_pay.bank_pay_enabled():
        q = await bank_pay.query_order(request_id)
        if q.get('status') == 'PAID':
            ok, _ = await _bank_credit(request_id, q.get('order_no') or '', float(row['amount']))
            if ok:
                await _hooks.fire_event('RECHARGE_APPROVED', trigger_user=row['user_name'],
                                        target_user=row['user_name'], amount=row['amount'])
                row['status'] = 'approved'
    return jsonify({
        'request_id': request_id,
        'amount': row['amount'],
        'status': row['status'],
        'pay_channel': row['pay_channel'],
        'bank_order_no': row['bank_order_no'],
    })



