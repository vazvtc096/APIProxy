"""充值与交易路由"""
from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, RCON_ENABLED, RCON_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from .. import configs
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf

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

    daily = await _usage_daily(user_name=user_name, days=days)
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
    return jsonify({
        'days': days,
        'total': {'requests': t['requests'], 'cost': round(float(t['cost'] or 0), 6),
                  'tokens': t['tokens'], 'input_tokens': t['in_tokens'],
                  'output_tokens': t['out_tokens']},
        'daily': daily,
        'models': [{'model': m['model'], 'requests': m['requests'],
                    'cost': round(float(m['cost'] or 0), 6), 'tokens': m['tokens']} for m in models],
    }), 200



