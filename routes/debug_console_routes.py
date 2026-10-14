"""Debug Console 远程控制路由"""
from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app, BASE_DIR
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

debug_console_bp = Blueprint('debug_console', __name__)

@debug_console_bp.route('/api/debug-console/key/refresh', methods=['POST'])
async def debug_console_refresh_key():
    """刷新 Debug Console 密钥（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    new_key = await _refresh_debug_console_key()
    logging.warning("Debug Console key refreshed via Debug Console API")
    return jsonify({
        'message': 'Debug Console key refreshed',
        'new_key': new_key
    }), 200


# ---------- 系统统计 ----------


@debug_console_bp.route('/api/debug-console/stats', methods=['GET'])
async def debug_console_stats():
    """获取系统统计信息（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    # 用户统计
    users = await async_db_query("SELECT COUNT(*) as cnt FROM users")
    total_users = users[0]['cnt'] if users else 0
    
    admin_users = await async_db_query("SELECT COUNT(*) as cnt FROM users WHERE is_admin = 1")
    total_admins = admin_users[0]['cnt'] if admin_users else 0
    
    banned_users = await async_db_query("SELECT COUNT(*) as cnt FROM users WHERE is_banned = 1")
    total_banned = banned_users[0]['cnt'] if banned_users else 0
    
    # 会话统计
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    sessions = await async_db_query(
        "SELECT COUNT(*) as cnt FROM sessions WHERE expires_at > ?",
        (now,)
    )
    active_sessions = sessions[0]['cnt'] if sessions else 0
    
    # 充值请求统计
    pending_recharges = await async_db_query(
        "SELECT COUNT(*) as cnt FROM recharge_requests WHERE status = 'pending'"
    )
    pending_recharge_count = pending_recharges[0]['cnt'] if pending_recharges else 0
    
    # 总余额
    total_balence_result = await async_db_query("SELECT SUM(balence) as total FROM users")
    total_balence = total_balence_result[0]['total'] if total_balence_result and total_balence_result[0]['total'] else 0
    
    return jsonify({
        'users': {
            'total': total_users,
            'admins': total_admins,
            'banned': total_banned,
            'total_balence': round(total_balence, 6)
        },
        'sessions': {
            'active': active_sessions
        },
        'recharge_requests': {
            'pending': pending_recharge_count
        }
    }), 200


# ---------- 用户管理 ----------


@debug_console_bp.route('/api/debug-console/users', methods=['GET'])
async def debug_console_list_users():
    """获取所有用户列表（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 50, type=int)
    page_size = min(page_size, 200)
    offset = (page - 1) * page_size
    
    users = await async_db_query(
        "SELECT id, user_name, uid, email, balence, is_admin, is_banned, ban_reason, created_at, last_login_ip, last_login_time, max_sessions FROM users ORDER BY id DESC LIMIT ? OFFSET ?",
        (page_size, offset)
    )
    
    total_result = await async_db_query("SELECT COUNT(*) as cnt FROM users")
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'users': [dict(u) for u in users],
        'total': total,
        'page': page,
        'page_size': page_size
    }), 200



@debug_console_bp.route('/api/debug-console/user/<username>', methods=['GET'])
async def debug_console_get_user(username):
    """获取用户详情（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_data = dict(user[0])
    user_data.pop('user_password', None)
    
    apikeys_str = user_data.get('apikeys', '')
    apikey_count = len([k for k in apikeys_str.split(',') if k.strip()]) if apikeys_str else 0
    user_data['apikey_count'] = apikey_count
    
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    sessions = await async_db_query(
        "SELECT COUNT(*) as cnt FROM sessions WHERE user_name = ? AND expires_at > ?",
        (username, now)
    )
    user_data['active_sessions'] = sessions[0]['cnt'] if sessions else 0
    
    return jsonify(user_data), 200



@debug_console_bp.route('/api/debug-console/users', methods=['POST'])
async def debug_console_create_user():
    """创建用户（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    data = await request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    is_admin = data.get('is_admin', False)
    balence = data.get('balence', 0.0)
    max_sessions = data.get('max_sessions', DEFAULT_MAX_SESSIONS)
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    existing = await async_db_query("SELECT id FROM users WHERE user_name = ?", (username,))
    if existing:
        return jsonify({'error': 'Username already exists'}), 400
    
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password too short (min {MIN_PASSWORD_LENGTH} chars)'}), 400
    if not any(c.isalpha() for c in password):
        return jsonify({'error': 'Password must contain at least one letter'}), 400
    if not any(c.isdigit() for c in password):
        return jsonify({'error': 'Password must contain at least one digit'}), 400
    
    import uuid
    uid = uuid.uuid4().hex[:12]
    password_hash = hash_password(password)
    max_sessions = max(1, min(int(max_sessions), MAX_ACTIVE_SESSIONS))
    
    await async_db_query(
        "INSERT INTO users (user_name, user_password, apikeys, balence, uid, is_admin, email, max_sessions) VALUES (?, ?, '', ?, ?, ?, ?, ?)",
        (username, password_hash, float(balence), uid, 1 if is_admin else 0, email, max_sessions)
    )
    
    logging.info(f"Debug Console created user: {username} (admin={is_admin})")
    return jsonify({
        'message': 'User created successfully',
        'username': username,
        'uid': uid
    }), 201



@debug_console_bp.route('/api/debug-console/user/<username>', methods=['PUT'])
async def debug_console_update_user(username):
    """修改用户信息（Debug Console 权限，可改任意字段）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    data = await request.get_json() or {}
    
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    updates = []
    params = []
    
    allowed_fields = ['email', 'balence', 'is_admin', 'is_banned', 'ban_reason', 'max_sessions']
    
    for field in allowed_fields:
        if field in data:
            value = data[field]
            if field == 'is_admin':
                value = 1 if value else 0
            if field == 'is_banned':
                value = 1 if value else 0
            if field == 'max_sessions':
                value = max(1, min(int(value), MAX_ACTIVE_SESSIONS))
            updates.append(f"{field} = ?")
            params.append(value)
    
    if 'password' in data and data['password']:
        new_password = data['password']
        if len(new_password) < MIN_PASSWORD_LENGTH:
            return jsonify({'error': f'Password too short (min {MIN_PASSWORD_LENGTH} chars)'}), 400
        password_hash = hash_password(new_password)
        updates.append("user_password = ?")
        params.append(password_hash)
    
    if not updates:
        return jsonify({'error': 'No fields to update'}), 400
    
    params.append(username)
    
    await async_db_query(
        f"UPDATE users SET {', '.join(updates)} WHERE user_name = ?",
        tuple(params)
    )
    
    logging.info(f"Debug Console updated user: {username}, fields: {list(data.keys())}")
    return jsonify({'message': 'User updated successfully'}), 200



@debug_console_bp.route('/api/debug-console/user/<username>', methods=['DELETE'])
async def debug_console_delete_user(username):
    """删除用户（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 清除好友关系（需在删除用户前执行，子查询依赖 users 表）
    await async_db_query("DELETE FROM friends WHERE user_uid IN (SELECT uid FROM users WHERE user_name = ?) OR friend_uid IN (SELECT uid FROM users WHERE user_name = ?)", (username, username))
    await async_db_query("DELETE FROM recharge_requests WHERE user_name = ?", (username,))
    await async_db_query("DELETE FROM sessions WHERE user_name = ?", (username,))
    await async_db_query("DELETE FROM users WHERE user_name = ?", (username,))
    
    logging.warning(f"Debug Console deleted user: {username}")
    return jsonify({'message': 'User deleted successfully'}), 200



@debug_console_bp.route('/api/debug-console/user/<username>/ban', methods=['POST'])
async def debug_console_ban_user(username):
    """封禁用户（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    data = await request.get_json() or {}
    reason = data.get('reason', 'Banned by Debug Console')
    
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    await async_db_query(
        "UPDATE users SET is_banned = 1, ban_reason = ? WHERE user_name = ?",
        (reason, username)
    )
    
    await async_db_query("DELETE FROM sessions WHERE user_name = ?", (username,))
    
    logging.warning(f"Debug Console banned user: {username}, reason: {reason}")
    return jsonify({'message': 'User banned successfully'}), 200



@debug_console_bp.route('/api/debug-console/user/<username>/unban', methods=['POST'])
async def debug_console_unban_user(username):
    """解封用户（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    await async_db_query(
        "UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expire_at = NULL WHERE user_name = ?",
        (username,)
    )
    
    logging.info(f"Debug Console unbanned user: {username}")
    return jsonify({'message': 'User unbanned successfully'}), 200



@debug_console_bp.route('/api/debug-console/user/<username>/balence', methods=['POST'])
async def debug_console_adjust_balence(username):
    """调整用户余额（Debug Console 权限，可正可负）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    data = await request.get_json() or {}
    amount = data.get('amount', 0)
    set_balence = data.get('set_balence', None)
    
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400
    
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if set_balence is not None:
        new_balence = float(set_balence)
        await async_db_query(
            "UPDATE users SET balence = ? WHERE user_name = ?",
            (new_balence, username)
        )
        logging.info(f"Debug Console set balence for user {username}: {new_balence}")
        return jsonify({
            'message': 'Balance updated',
            'new_balence': round(new_balence, 6)
        }), 200
    else:
        current = user[0]['balence']
        new_balence = current + amount
        if new_balence < 0:
            new_balence = 0
        
        await async_db_query(
            "UPDATE users SET balence = ? WHERE user_name = ?",
            (new_balence, username)
        )
        
        logging.info(f"Debug Console adjusted balence for user {username}: {amount:+}, new: {new_balence}")
        return jsonify({
            'message': 'Balance adjusted',
            'adjustment': amount,
            'old_balence': round(current, 6),
            'new_balence': round(new_balence, 6)
        }), 200


# ---------- 会话管理 ----------


@debug_console_bp.route('/api/debug-console/sessions', methods=['GET'])
async def debug_console_list_sessions():
    """获取所有活跃会话（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    sessions = await async_db_query(
        "SELECT s.*, u.is_admin, u.balence FROM sessions s LEFT JOIN users u ON s.user_name = u.user_name WHERE s.expires_at > ? ORDER BY s.last_active_at DESC",
        (now,)
    )
    
    return jsonify({
        'sessions': [dict(s) for s in sessions],
        'total': len(sessions)
    }), 200



@debug_console_bp.route('/api/debug-console/session/<session_id>', methods=['DELETE'])
async def debug_console_kick_session(session_id):
    """踢掉指定会话（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    session_info = await async_db_query(
        "SELECT * FROM sessions WHERE session_id = ?",
        (session_id,)
    )
    if not session_info:
        return jsonify({'error': 'Session not found'}), 404
    
    await async_db_query("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    
    logging.info(f"Debug Console kicked session: {session_id}, user: {session_info[0]['user_name']}")
    return jsonify({'message': 'Session kicked successfully'}), 200



@debug_console_bp.route('/api/debug-console/user/<username>/sessions', methods=['DELETE'])
async def debug_console_kick_all_user_sessions(username):
    """踢掉指定用户的所有会话（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    await async_db_query("DELETE FROM sessions WHERE user_name = ?", (username,))
    
    logging.warning(f"Debug Console kicked all sessions for user: {username}")
    return jsonify({'message': 'All user sessions kicked'}), 200


# ---------- 充值请求管理 ----------


@debug_console_bp.route('/api/debug-console/recharge-requests', methods=['GET'])
async def debug_console_list_recharge_requests():
    """获取充值请求列表（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    status = request.args.get('status', 'all')
    
    query = "SELECT * FROM recharge_requests"
    params = []
    
    if status != 'all':
        query += " WHERE status = ?"
        params.append(status)
    
    query += " ORDER BY created_at DESC"
    
    requests = await async_db_query(query, tuple(params) if params else ())
    
    return jsonify({
        'requests': [dict(r) for r in requests],
        'total': len(requests)
    }), 200



@debug_console_bp.route('/api/debug-console/recharge-request/<int:req_id>/approve', methods=['POST'])
async def debug_console_approve_recharge(req_id):
    """通过充值请求（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    data = await request.get_json() or {}
    remark = data.get('remark', 'Approved by Debug Console')
    
    req = await async_db_query("SELECT * FROM recharge_requests WHERE id = ?", (req_id,))
    if not req:
        return jsonify({'error': 'Recharge request not found'}), 404
    
    req = req[0]
    if req['status'] != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
    
    user = await async_db_query("SELECT balence FROM users WHERE user_name = ?", (req['user_name'],))
    if user:
        new_balence = user[0]['balence'] + req['amount']
        await async_db_query(
            "UPDATE users SET balence = ? WHERE user_name = ?",
            (new_balence, req['user_name'])
        )
    
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    await async_db_query(
        "UPDATE recharge_requests SET status = 'approved', admin_name = 'Debug Console', admin_remark = ?, processed_at = ? WHERE id = ?",
        (remark, now, req_id)
    )
    
    logging.info(f"Debug Console approved recharge request {req_id}: {req['user_name']} +{req['amount']}")
    return jsonify({'message': 'Recharge request approved'}), 200



@debug_console_bp.route('/api/debug-console/recharge-request/<int:req_id>/reject', methods=['POST'])
async def debug_console_reject_recharge(req_id):
    """拒绝充值请求（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    data = await request.get_json() or {}
    remark = data.get('remark', 'Rejected by Debug Console')
    
    req = await async_db_query("SELECT * FROM recharge_requests WHERE id = ?", (req_id,))
    if not req:
        return jsonify({'error': 'Recharge request not found'}), 404
    
    req = req[0]
    if req['status'] != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
    
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    await async_db_query(
        "UPDATE recharge_requests SET status = 'rejected', admin_name = 'Debug Console', admin_remark = ?, processed_at = ? WHERE id = ?",
        (remark, now, req_id)
    )
    
    logging.info(f"Debug Console rejected recharge request {req_id}: {req['user_name']}")
    return jsonify({'message': 'Recharge request rejected'}), 200


# ---------- SQL 查询 ----------


@debug_console_bp.route('/api/debug-console/sql', methods=['POST'])
async def debug_console_sql_query():
    """执行 SQL 查询（Debug Console 权限，只读）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    data = await request.get_json() or {}
    sql = data.get('sql', '').strip()
    
    if not sql:
        return jsonify({'error': 'SQL query required'}), 400
    
    sql_upper = sql.upper().strip()
    if not sql_upper.startswith('SELECT'):
        return jsonify({'error': 'Only SELECT queries are allowed for safety'}), 400
    
    limit = data.get('limit', 100)
    limit = min(int(limit), 500)
    
    try:
        if 'LIMIT' not in sql_upper:
            sql = sql.rstrip(';') + f" LIMIT {limit}"
        
        result = await async_db_query(sql)
        
        return jsonify({
            'success': True,
            'rows': [dict(r) for r in result],
            'row_count': len(result)
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ---------- 日志查看 ----------


@debug_console_bp.route('/api/debug-console/login-logs', methods=['GET'])
async def debug_console_login_logs():
    """查看登录日志（Debug Console 权限）"""
    ok, err = await _debug_console_auth()
    if not ok:
        return err
    
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 50, type=int)
    page_size = min(page_size, 200)
    offset = (page - 1) * page_size
    username = request.args.get('username', '')
    
    query = "SELECT * FROM login_logs"
    count_query = "SELECT COUNT(*) as cnt FROM login_logs"
    params = []
    
    if username:
        query += " WHERE user_name = ?"
        count_query += " WHERE user_name = ?"
        params.append(username)
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([page_size, offset])
    
    logs = await async_db_query(query, tuple(params))
    
    count_params = params[:-2] if username else ()
    total_result = await async_db_query(count_query, tuple(count_params))
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'logs': [dict(l) for l in logs],
        'total': total,
        'page': page,
        'page_size': page_size
    }), 200




@debug_console_bp.route('/debug-console/login')
async def debug_console_login_page():
    """Debug Console 登录页面"""
    if _is_debug_console_authenticated():
        return redirect(url_for('debug_console_terminal_page'))
    return await render_template('debug_console/login.html')



@debug_console_bp.route('/debug-console/login', methods=['POST'])
async def debug_console_login_submit():
    """Debug Console 登录提交 - 双重认证（管理员账号 + Debug Console 密钥）"""
    data = await request.get_json() or {}
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    username = data.get('username', '')
    password = data.get('password', '')
    debug_console_key = data.get('key', '')
    
    # 统一错误提示，不透露具体哪个错了（安全考虑）
    error_msg = '用户名、密码或密钥错误'
    
    if not username or not password or not debug_console_key:
        return jsonify({'error': error_msg}), 401
    
    # 验证管理员账号密码
    admin_valid = await _debug_console_verify_admin_credentials(username, password)
    
    # 验证 Debug Console 密钥
    key_valid = await _verify_debug_console_key(debug_console_key)
    
    # 两者都通过才算认证成功
    if admin_valid and key_valid:
        session['debug_console_authenticated'] = True
        session['debug_console_admin_username'] = username
        return jsonify({'success': True, 'message': 'Authentication successful'})
    else:
        return jsonify({'error': error_msg}), 401



@debug_console_bp.route('/debug-console/logout', methods=['GET', 'POST'])
async def debug_console_logout():
    """Debug Console 登出"""
    # 只清除 Debug Console 相关的 session，不影响普通用户登录
    session.pop('debug_console_authenticated', None)
    session.pop('debug_console_admin_username', None)
    
    if request.method == 'POST':
        return jsonify({'success': True})
    return redirect(url_for('debug_console_login_page'))



@debug_console_bp.route('/debug-console/terminal')
async def debug_console_terminal_page():
    """Debug Console 终端页面"""
    if not _is_debug_console_authenticated():
        return redirect(url_for('debug_console_login_page'))
    return await render_template('debug_console/terminal.html')



@debug_console_bp.route('/debug-console/api/auth-check')
async def debug_console_auth_check():
    """检查 Debug Console 认证状态"""
    authenticated = _is_debug_console_authenticated()
    username = session.get('debug_console_admin_username', '')
    return jsonify({
        'authenticated': authenticated,
        'username': username if authenticated else ''
    })



@debug_console_bp.route('/debug-console/execute', methods=['POST'])
async def debug_console_execute_command():
    """执行 Debug Console 命令（Web 版）"""
    if not _is_debug_console_authenticated():
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = await request.get_json() or {}
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    command = data.get('command', '').strip()
    if not command:
        return jsonify({'error': 'Command is required'}), 400
    
    # 使用 debug_console.py 的命令处理器执行命令
    try:
        from ..debug_console import DebugConsoleCommandHandler
        handler = DebugConsoleCommandHandler()
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            output = loop.run_until_complete(handler.handle(command))
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'command': command,
            'output': output
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # ① Fail-closed：OAuth JWT 签名密钥必须显式配置，缺失则拒绝启动，
    # 避免回退到不安全默认值而静默签发/验签令牌。
    if not OAUTH_JWT_SECRET:
        logging.critical(
            "OAUTH_JWT_SECRET is not set. Refusing to start (fail-closed). "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and add it to the config file (config.yaml / config.json / config.toml) "
            "as OAUTH_JWT_SECRET: \"...\""
        )
        raise SystemExit(1)

    # ③ 保护敏感文件：限制数据库与配置文件仅所有者可读写（Windows 下尽力而为）。
    _config_path = getattr(configs, 'CONFIG_PATH', None)
    for _p in (DB_PATH,
               _config_path,
               os.path.join(os.path.dirname(__file__), '.session_secret'),
               os.path.join(os.path.dirname(__file__), '.debug_console_key')):
        try:
            if _p and os.path.exists(_p):
                os.chmod(_p, 0o600)
        except Exception:
            pass

    # 完整数据库 schema 初始化：创建/迁移所有表（含安全事件、IP 封禁、OAuth 等新增表与字段）。
    # 必须在其他 _init_* 之前执行，确保运行期所需的表与字段存在。
    try:
        from .. import smart_init
        smart_init.smart_init()
    except Exception as e:
        logging.error(f"smart_init failed: {e}")

    _init_sessions_table()
    _init_rate_limit_table()  # 创建限流计数表（SQLite 持久化）
    # 启动时清理过期的限流记录，避免表无限增长
    try:
        _cleanup_rate_limits_sync()
    except Exception:
        pass
    _cleanup_expired_sessions_sync()  # 启动时清理过期会话

    # 启动上游客户端并拉取一次模型目录（失败不致命）
    try:
        asyncio.run(upstreams.startup_refresh())
        logging.info("Upstream clients initialized and model catalog refreshed.")
    except Exception as e:
        logging.error(f"Upstream startup refresh failed: {e}")

    # 从 DB 加载时段计费配置（覆盖/合并 config.yaml 的 schedules）
    try:
        n = pricing.reload_pricing_from_db()
        logging.info(f"Pricing schedules loaded from DB: {n} rows")
    except Exception as e:
        logging.error(f"Pricing reload from DB failed: {e}")
    
    # 启动 Debug Console 远程控制台（后台线程）
    try:
        _start_debug_console_server_thread()
        logging.info("Debug Console server starting...")
    except Exception as e:
        logging.error(f"Failed to start Debug Console server: {e}")
    
    # 启动定时任务调度器
    try:
        from ..scheduler import start_scheduler
        start_scheduler()
        logging.info("Task scheduler started...")
    except Exception as e:
        logging.error(f"Failed to start task scheduler: {e}")
    
    # 启动 Web 服务
    from ..configs import SSL_ENABLED, SSL_CERT, SSL_KEY, HTTPS_PORT
    
    if SSL_ENABLED:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt

        cert_path = SSL_CERT or os.path.join(BASE_DIR, 'certs', 'server.crt')
        key_path = SSL_KEY or os.path.join(BASE_DIR, 'certs', 'server.key')

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logging.info("Auto-generating self-signed TLS certificate...")
            os.makedirs(os.path.dirname(cert_path), exist_ok=True)

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, 'CN'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Cloud LLM API Proxy'),
                x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(dt.datetime.utcnow())
                .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                .sign(key, hashes.SHA256())
            )

            with open(key_path, 'wb') as f:
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            logging.info(f"Self-signed cert generated: {cert_path}")

        from hypercorn.config import Config as HyperConfig
        from hypercorn.asyncio import serve

        config = HyperConfig()
        config.bind = [f"0.0.0.0:{HTTPS_PORT}"]
        config.certfile = cert_path
        config.keyfile = key_path
        config.ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
        config.accesslog = "-"
        config.errorlog = "-"
        config.ssl_handshake_timeout = 60

        print(f"HTTPS enabled, listening on port {HTTPS_PORT} (TLS 1.2/1.3)")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(serve(app, config))
    else:
        # 生产环境必须关闭 debug 模式，防止 Werkzeug 交互式调试器导致远程代码执行
        debug_mode = os.getenv('DEBUG', 'false').lower() == 'true'
        app.run(host='0.0.0.0', port=5000, debug=debug_mode)




