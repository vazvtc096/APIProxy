"""用户路由：API Key 管理/设置/会话"""
from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, DEBUG_CONSOLE_ENABLED, DEBUG_CONSOLE_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from .. import configs
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf
from .. import tokenpolicy as _tokenpolicy
from .. import budget as _budget
from .. import subscription as _subscription

user_bp = Blueprint('user', __name__)


@user_bp.route('/api/user/budget', methods=['GET'])
async def get_my_budget():
    """当前用户的月度消费预算与本月已消费"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    info = await asyncio.to_thread(_budget.get_budget, session['user'])
    if not info:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(info)


@user_bp.route('/api/user/budget', methods=['POST'])
async def set_my_budget():
    """设置自己的月度消费预算（0 或空 = 取消限制）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    data = await request.get_json() or {}
    ok, err = await asyncio.to_thread(
        _budget.set_budget, session['user'], data.get('monthly_budget'))
    return (jsonify({'ok': True}) if ok else (jsonify({'error': err}), 400))


@user_bp.route('/api/tokens', methods=['GET'])
async def list_tokens():
    """当前用户的令牌列表（含策略与用量；key 只暴露哈希前缀提示）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    try:
        rows = _tokenpolicy.list_policies(session['user'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'tokens': rows})


@user_bp.route('/api/tokens/<int:key_id>/policy', methods=['POST'])
async def update_token_policy(key_id: int):
    """更新自己令牌的策略（额度/过期/模型白名单/IP白名单/停用）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    data = await request.get_json() or {}
    ok, err = await _asyncio.to_thread(
        _tokenpolicy.set_policy, key_id, session['user'], False,
        label=data.get('label'),
        expires_at=data.get('expires_at'),
        quota=data.get('quota'),
        allowed_models=data.get('allowed_models'),
        ip_whitelist=data.get('ip_whitelist'),
        is_active=data.get('is_active'),
        rpm_limit=data.get('rpm_limit'),
        tpm_limit=data.get('tpm_limit'),
    )
    return (jsonify({'ok': True}) if ok else (jsonify({'error': err}), 400))


@user_bp.route('/api/redeem', methods=['POST'])
async def redeem_code():
    """用户自助兑换充值码到余额"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    data = await request.get_json() or {}
    from .. import redeem as _redeem
    ok, msg = await _asyncio.to_thread(_redeem.redeem, data.get('code'), session['user'])
    return (jsonify({'ok': True, 'message': msg}) if ok
            else (jsonify({'error': msg}), 400))


@user_bp.route('/apikeys', methods=['GET'])
async def list_apikeys():
    """获取当前用户的 API Key 列表"""
    _oerr = await _oauth_ensure_user(['apikeys:read'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    username = session['user']
    users = await async_db_query(
        "SELECT apikeys FROM users WHERE user_name = ?",
        (username,)
    )
    
    if not users:
        return jsonify({'error': 'User not found'}), 404
    
    apikeys_str = users[0]['apikeys'] or ''
    apikeys = [k.strip() for k in apikeys_str.split(',') if k.strip()]
    
    return jsonify({'apikeys': apikeys})



@user_bp.route('/apikey', methods=['POST'])
async def create_apikey():
    _oerr = await _oauth_ensure_user(['apikeys:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    owner = session['user']

    def _gen():
        # 已登录用户直接创建，不需要密码验证
        return APIKey._require_apikey_trusted(owner)

    try:
        new_key = await asyncio.to_thread(_gen)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'apikey': new_key}), 201



@user_bp.route('/userinfo', methods=['GET'])
async def userinfo():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    owner = session['user']

    # 已登录用户直接按用户名查询
    user = await async_db_query(
        "SELECT user_name, balence, apikeys, uid, created_at, is_admin, is_banned, ban_reason, ban_expire_at, max_overdraft, must_change_password, monthly_budget, budget_spent, budget_month FROM users WHERE user_name = ?",
        (owner,)
    )
    if not user:
        session.clear()
        return jsonify({'error': 'User not found'}), 404

    info = user[0]
    
    # 检查是否被封禁
    is_banned, ban_msg = await _is_user_banned(info)
    
    return jsonify({
        'username': info['user_name'],
        'uid': info.get('uid'),
        'balence': info['balence'],
        'max_overdraft': info.get('max_overdraft', 0) or 0,
        'monthly_budget': float(info.get('monthly_budget') or 0.0),
        'budget_spent': round(float(info.get('budget_spent') or 0.0), 6)
                        if (info.get('budget_month') or '') == _budget.current_month() else 0.0,
        'created_at': info.get('created_at'),
        'apikeys': info['apikeys'].split(',') if info['apikeys'] else [],
        'is_admin': bool(info.get('is_admin', 0)),
        'must_change_password': bool(info.get('must_change_password', 0)),
        'is_banned': is_banned,
        'ban_reason': ban_msg if is_banned else ''
    })





@user_bp.route('/api/user/settings', methods=['GET'])
async def get_user_settings():
    """获取用户设置"""
    _oerr = await _oauth_ensure_user(['user:read'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    username = session['user']
    user = await async_db_query("SELECT max_sessions FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    max_sessions = user[0].get('max_sessions', DEFAULT_MAX_SESSIONS)
    if max_sessions is None:
        max_sessions = DEFAULT_MAX_SESSIONS
    max_sessions = int(max_sessions)
    
    return jsonify({
        'max_sessions': max_sessions,
        'max_allowed': MAX_ACTIVE_SESSIONS,
        'min_allowed': 1
    }), 200



@user_bp.route('/api/user/settings', methods=['POST'])
async def update_user_settings():
    """修改用户设置"""
    _oerr = await _oauth_ensure_user(['user:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = await request.get_json() or {}
    max_sessions = data.get('max_sessions')
    
    if max_sessions is None:
        return jsonify({'error': 'max_sessions is required'}), 400
    
    # 验证输入
    try:
        max_sessions = int(max_sessions)
    except (ValueError, TypeError):
        return jsonify({'error': 'max_sessions must be an integer'}), 400
    
    if max_sessions < 1 or max_sessions > MAX_ACTIVE_SESSIONS:
        return jsonify({'error': f'max_sessions must be between 1 and {MAX_ACTIVE_SESSIONS}'}), 400
    
    username = session['user']
    
    # 更新设置
    await async_db_query(
        "UPDATE users SET max_sessions = ? WHERE user_name = ?",
        (max_sessions, username)
    )
    
    logging.info(f"Settings updated: user {username}, max_sessions={max_sessions}")
    return jsonify({
        'message': 'Settings updated successfully',
        'max_sessions': max_sessions
    }), 200



@user_bp.route('/api/user/delete', methods=['POST'])
async def delete_account():
    """注销账号"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = await request.get_json() or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password required for confirmation'}), 400
    
    username = session['user']
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 不能删除管理员
    if user[0].get('is_admin'):
        return jsonify({'error': 'Admin account cannot be deleted'}), 400
    
    # 验证密码
    if not verify_password(password, user[0]['user_password']):
        return jsonify({'error': 'Password incorrect'}), 400
    
    uid = user[0].get('uid')
    
    # 删除用户的所有会话
    try:
        sessions = await _get_user_sessions(username)
        for s in sessions:
            await _delete_session(s['session_id'])
    except Exception as e:
        logging.error(f"Delete user sessions failed: {e}")
    
    # 删除用户的充值请求
    await async_db_query("DELETE FROM recharge_requests WHERE user_uid = ?", (uid,))

    # 清除好友关系（防止残留悬空引用，导致给已注销用户发消息时报 Recipient not found）
    await async_db_query("DELETE FROM friends WHERE user_uid = ? OR friend_uid = ?", (uid, uid))

    # 删除用户
    await async_db_query("DELETE FROM users WHERE user_name = ?", (username,))
    
    # 清除 session
    session.clear()
    
    logging.info(f"User account deleted: {username} (UID: {uid})")
    return jsonify({'message': 'Account deleted successfully'}), 200



@user_bp.route('/api/user/sessions', methods=['GET'])
async def get_user_sessions():
    """获取当前用户的活跃会话列表"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    username = session['user']
    
    try:
        sessions = await _get_user_sessions(username)
        current_session_id = session.get('session_id')
        
        # 格式化返回
        result = []
        for s in sessions:
            result.append({
                'session_id': s['session_id'],
                'user_agent': s['user_agent'],
                'ip_address': s['ip_address'],
                'created_at': s['created_at'],
                'last_active_at': s['last_active_at'],
                'is_current': s['session_id'] == current_session_id
            })
        
        return jsonify({
            'sessions': result,
            'max_sessions': MAX_ACTIVE_SESSIONS,
            'current_count': len(result)
        }), 200
    except Exception as e:
        logging.error(f"Get user sessions failed: {e}")
        return jsonify({'error': 'Failed to get sessions'}), 500



@user_bp.route('/api/user/sessions/<session_id>', methods=['DELETE'])
async def delete_user_session(session_id):
    """踢掉某个会话（设备）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    username = session['user']
    current_session_id = session.get('session_id')
    
    # 不能踢掉当前会话
    if session_id == current_session_id:
        return jsonify({'error': 'Cannot terminate current session'}), 400
    
    try:
        # 验证会话属于当前用户
        sessions = await _get_user_sessions(username)
        session_ids = [s['session_id'] for s in sessions]
        
        if session_id not in session_ids:
            return jsonify({'error': 'Session not found'}), 404
        
        # 删除会话
        await _delete_session(session_id)
        
        logging.info(f"Session terminated by user: {username}, session_id: {session_id}")
        return jsonify({'message': 'Session terminated successfully'}), 200
    except Exception as e:
        logging.error(f"Delete user session failed: {e}")
        return jsonify({'error': 'Failed to terminate session'}), 500



@user_bp.route("/settings")
async def settings():
    """设置页面"""
    if "user" not in session:
        return redirect(url_for("login_page"))
    return await render_template("settings.html")



@user_bp.route('/apikey/<key>', methods=['DELETE'])
async def delete_apikey(key):
    """删除指定的 API Key"""
    _oerr = await _oauth_ensure_user(['apikeys:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    owner = session['user']
    
    # 获取用户信息
    users = await async_db_query(
        "SELECT apikeys FROM users WHERE user_name = ?",
        (owner,)
    )
    if not users:
        return jsonify({'error': 'User not found'}), 404
    
    current_keys = users[0]['apikeys'] or ''
    key_list = [k for k in current_keys.split(',') if k]
    
    if key not in key_list:
        return jsonify({'error': 'API key not found'}), 404
    
    # 移除该 key
    key_list.remove(key)
    new_keys = ','.join(key_list)
    
    await async_db_query(
        "UPDATE users SET apikeys = ? WHERE user_name = ?",
        (new_keys, owner)
    )
    
    logging.info(f"API key deleted: user {owner}, key {key[:8]}...")
    return jsonify({'message': 'API key deleted'}), 200







# ---------- 套餐 / 订阅（花账户余额） ----------

@user_bp.route('/api/plans', methods=['GET'])
async def list_plans():
    """列出可订阅套餐（含已解析的权益列表）。"""
    plans = await _subscription.get_plans(only_active=True)
    return jsonify({'plans': plans}), 200


@user_bp.route('/api/subscribe', methods=['POST'])
async def do_subscribe():
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    data = await request.get_json() or {}
    plan_id = (data.get('plan_id') or '').strip()
    if not plan_id:
        return jsonify({'error': 'plan_id required'}), 400
    ok, msg, sub = await _subscription.subscribe(session['user'], plan_id)
    if not ok:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg, 'subscription': sub}), 200


@user_bp.route('/api/my/subscriptions', methods=['GET'])
async def my_subscriptions():
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    subs = await _subscription.list_my_subscriptions(session['user'])
    active = await _subscription.get_active_subscription(session['user'])
    return jsonify({'active': active, 'subscriptions': subs}), 200


@user_bp.route('/api/my/subscriptions/<int:sub_id>', methods=['DELETE'])
async def cancel_my_subscription(sub_id: int):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    ok, msg, _ = await _subscription.cancel_subscription(session['user'], sub_id)
    return jsonify({'message': msg}), 200 if ok else 400


@user_bp.route('/plans', methods=['GET'])
async def plans_page():
    if 'user' not in session:
        return redirect('/login')
    return await render_template('plans.html')


# ---------- 会话管理（多设备登录限制） ----------


