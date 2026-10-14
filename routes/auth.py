"""认证路由：注册/登录/登出/密码重置"""
from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, DEBUG_CONSOLE_ENABLED, DEBUG_CONSOLE_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from .. import configs
from .. import ja3 as _ja3
from .. import honeypot as _honeypot
from .. import ja3_threat as _ja3threat
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
async def register():
    # 限流检查
    allowed, remaining = _check_rate_limit('register')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429, {'Retry-After': str(_get_rate_limit_retry_after('register'))}

    data = await request.get_json() or {}
    owner = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    code = data.get('code', '').strip()
    captcha_token = data.get('captcha_token', '').strip()
    captcha_x = data.get('captcha_x')

    # 输入验证
    if not owner or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(owner) > MAX_USERNAME_LENGTH:
        return jsonify({'error': f'Username too long (max {MAX_USERNAME_LENGTH} chars)'}), 400
    # 用户名只允许字母、数字、下划线（防 XSS 载体 / 特殊字符注入）
    if not _is_safe_username(owner):
        return jsonify({'error': 'Username can only contain letters, numbers and underscores'}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({"error": f"Password too short (min {MIN_PASSWORD_LENGTH} chars)"}), 400
    
    # 密码强度检查：必须包含字母和数字
    if not any(c.isalpha() for c in password):
        return jsonify({"error": "Password must contain at least one letter"}), 400
    if not any(c.isdigit() for c in password):
        return jsonify({"error": "Password must contain at least one digit"}), 400
    
    # 验证方式分支：SMTP 已配置走邮箱验证码，未配置走滑块验证码（WebUI 热改实时生效）
    if configs.smtp_configured():
        # 邮箱验证（如果提供了邮箱则必须验证）
        if email:
            if '@' not in email or '.' not in email:
                return jsonify({'error': 'Invalid email format'}), 400
            if not code:
                return jsonify({'error': 'Verification code required'}), 400

            # 验证验证码
            try:
                from ..email_utils import verify_code
                success, msg = verify_code(email, code)
                if not success:
                    return jsonify({'error': msg}), 400
            except ImportError:
                pass  # email_utils 不可用时跳过验证
            except Exception as e:
                logging.error(f"Verify email code error: {e}")
                return jsonify({'error': 'Verification failed'}), 400

            # 检查邮箱是否已被注册
            existing_email = await async_db_query("SELECT user_name FROM users WHERE email = ?", (email,))
            if existing_email:
                return jsonify({'error': 'Email already registered'}), 400
    else:
        # 滑块验证码兜底（无 SMTP 时无法发邮件，用滑块阻止自动化注册）
        if not captcha_token:
            return jsonify({'error': '请完成滑块验证'}), 400
        try:
            from ..captcha import verify_slider_captcha
            ok, msg = verify_slider_captcha(captcha_token, captcha_x)
            if not ok:
                return jsonify({'error': msg}), 400
        except Exception as e:
            logging.error(f"Slider captcha verify error: {e}")
            return jsonify({'error': '验证失败，请刷新后重试'}), 400
        # 未配置 SMTP 时不存储未经验证的邮箱，避免邮箱被冒用
        email = ''

    # 检查用户是否已存在（模糊提示，防止用户名枚举）
    existing = await async_db_query("SELECT user_name FROM users WHERE user_name = ?", (owner,))
    if existing:
        return jsonify({'error': 'This username is unavailable, please choose another'}), 400

    # 生成密码哈希和 UID（0~15 为系统虚拟用户保留池，防御式避让）
    password_hash = hash_password(password)
    from ..system_users import is_system_uid as _is_sys_uid
    uid = generate_uid()
    while _is_sys_uid(uid):
        uid = generate_uid()

    if email:
        await async_db_query(
            "INSERT INTO users (user_name, user_password, balence, uid, email) VALUES (?, ?, 0, ?, ?)",
            (owner, password_hash, uid, email)
        )
    else:
        await async_db_query(
            "INSERT INTO users (user_name, user_password, balence, uid) VALUES (?, ?, 0, ?)",
            (owner, password_hash, uid)
        )

    # 新用户默认与内置 admin 互为好友（受保护，不可删除），以便接收通知/公告
    try:
        await _ann.ensure_admin_friendship(uid, owner)
    except Exception as e:
        logging.error(f"ensure_admin_friendship failed for {owner}: {e}")

    # 触发注册事件（钩子引擎）
    await fire_event('USER_REGISTER', trigger_user=uid, client_ip=_get_client_ip())

    return jsonify({'message': 'User registered successfully', 'uid': uid}), 201



@auth_bp.route('/login', methods=['POST'])
async def login():
    client_ip = _get_client_ip()
    user_agent = _get_user_agent()
    # JA3 / JA4 指纹采集（用于追溯与跨 IP 关联）
    ja3_info = {}
    try:
        ja3_info = _ja3.extract_ja3(request, client_ip)
        ja3_hash = ja3_info.get('ja3_hash', '') or ''
    except Exception:
        ja3_hash = ''
    # IP 白名单：匹配则按条目 bypass 范围跳过对应拦截（默认 all = 全部跳过）
    wl_bypass = await _whitelist_bypass(client_ip)

    # 限流检查（白名单可绕过 ratelimit）
    allowed, remaining = _check_rate_limit('login')
    if not allowed and 'all' not in wl_bypass and 'ratelimit' not in wl_bypass:
        return jsonify({'error': 'Too many attempts, please try again later'}), 429, {'Retry-After': str(_get_rate_limit_retry_after('login'))}

    data = await request.get_json() or {}
    owner = data.get('username', '').strip()
    password = data.get('password', '')

    # IP 黑名单检查（管理员手动封禁的 IP 直接拒绝登录；白名单可绕过 blacklist）
    try:
        ip_rows = await async_db_query(
            "SELECT reason, ban_expire_at FROM ip_blacklist "
            "WHERE ip = ? AND (ban_expire_at IS NULL OR ban_expire_at > ?)",
            (client_ip, time.time())
        )
        if ip_rows and 'all' not in wl_bypass and 'blacklist' not in wl_bypass:
            await _record_login_log('', owner, client_ip, user_agent, 'failed', 'IP blocked by admin', ja3_hash)
            return jsonify({'error': 'Access denied: your IP has been blocked by administrator'}), 403
    except Exception as e:
        logging.error(f"IP blacklist check failed: {e}")

    if not owner or not password:
        return jsonify({'error': 'Username and password required'}), 400

    # 设备解析（后续风险评分/蜜罐/填充检测共用）
    from ..security import parse_user_agent, record_security_event, ban_ip_auto
    device = parse_user_agent(user_agent)

    # 凭证填充检测：同一 JA3 在窗口内尝试大量不同账号 → stuffing 扫描器。
    # 合成指纹（syn-）跨用户聚合，默认不参与判定（CRED_STUFFING_APPLY_SYNTHETIC 可开），
    # 避免 NAT/校园网下多个真实用户共用同浏览器指纹时误判+误布蜜罐。
    stuffing = None
    if (getattr(configs, 'CRED_STUFFING_ENABLED', True) and ja3_hash
            and (ja3_info.get('source') != 'synthetic'
                 or getattr(configs, 'CRED_STUFFING_APPLY_SYNTHETIC', False))):
        try:
            stuffing = _ja3threat.record_login_attempt(ja3_hash, client_ip, owner)
            if stuffing and stuffing.get('stuffing'):
                logging.warning(f"凭证填充检测命中: JA3={ja3_hash} "
                                f"distinct_users={stuffing.get('distinct_users')} ip={client_ip}")
                # 记录安全事件（审计留档，始终执行）
                try:
                    await record_security_event(
                        async_db_query, '', owner, 'credential_stuffing', 'critical', 80,
                        [f"JA3 指纹 {ja3_hash} 在 {int(stuffing.get('window', 300))}s 内尝试 "
                         f"{stuffing.get('distinct_users')} 个不同账号",
                         f"IP: {client_ip}", f"UA: {user_agent}"],
                        client_ip, device, action_taken='monitored')
                except Exception as e:
                    logging.error(f"cred stuffing event failed: {e}")
                # 命中即封 IP（若开启；默认关，仅告警+蜜罐）
                if getattr(configs, 'CRED_STUFFING_BLOCK', False):
                    try:
                        await ban_ip_auto(async_db_query, client_ip, 'minutes',
                                          getattr(configs, 'IDS_IPS_AUTHFAIL_WINDOW', 30),
                                          'credential stuffing (JA3)')
                    except Exception as e:
                        logging.error(f"cred stuffing ban failed: {e}")
        except Exception as e:
            logging.error(f"cred stuffing check failed: {e}")

    # 先查用户
    users = await async_db_query(
        "SELECT * FROM users WHERE user_name = ?",
        (owner,)
    )
    if not users:
        # 记录失败日志
        await _record_login_log('', owner, client_ip, user_agent, 'failed', 'User not found', ja3_hash)
        # 蜜罐诱捕：自动化程序尝试登录「不存在的用户」→ 动态布设诱饵账号并将其诱入，
        # 真实用户不受影响（仍返回统一错误，攻击者以为自己登录成功）。
        # 触发条件扩展：命中凭证填充（同 JA3 批量试账号）时也布设蜜罐诱捕。
        try:
            if ((configs.HONEYPOT_ENABLED and configs.HONEYPOT_ON_UNKNOWN_USER
                    and device.is_automation
                    and 'all' not in wl_bypass and 'account_ban' not in wl_bypass)
                or (configs.HONEYPOT_ENABLED
                    and getattr(configs, 'CRED_STUFFING_DEPLOY_HONEYPOT', True)
                    and stuffing and stuffing.get('stuffing')
                    and 'all' not in wl_bypass and 'account_ban' not in wl_bypass)):
                bait = await _honeypot.maybe_bait(
                    owner, hash_password(password), client_ip, ja3_hash,
                    user_agent, True, False)
                if bait.get('deployed'):
                    # 诱入：建立会话，攻击者进入蜜罐环境（后续请求被全程留痕+限制）
                    try:
                        bait_uid = bait.get('uid', '') or generate_uid()
                        session_id = await _create_session(
                            username=bait['bait_username'], user_uid=bait_uid,
                            user_agent=user_agent, ip=client_ip)
                        session['user'] = bait['bait_username']
                        if session_id:
                            session['session_id'] = session_id
                        session['is_honeypot'] = True
                        session.permanent = True
                        logging.warning(f"蜜罐诱捕成功: {bait['bait_username']} <- {client_ip}")
                        return jsonify({'message': 'Logged in', 'is_admin': False,
                                        'must_change_password': False, 'honeypot': True}), 200
                    except Exception as e:
                        logging.error(f"honeypot lure-in failed: {e}")
        except Exception as e:
            logging.error(f"honeypot deploy on unknown user failed: {e}")
        # 统一错误信息，防止用户名枚举
        return jsonify({'error': 'Invalid credentials'}), 401

    user = users[0]

    # 系统虚拟用户（UID 池 0~15）禁止任何登录，不论密码是否命中
    from ..system_users import is_system_uid as _is_sys_uid
    if _is_sys_uid(user.get('uid', '')):
        await _record_login_log(user.get('uid', ''), owner, client_ip, user_agent, 'failed', 'System account login attempt', ja3_hash)
        logging.warning(f"[security] system account login attempt blocked: {owner} from {client_ip}")
        return jsonify({'error': 'Invalid credentials'}), 401

    # 验证密码（支持哈希和旧明文兼容）
    if not verify_password(password, user['user_password']):
        # 记录失败日志
        await _record_login_log(user.get('uid', ''), owner, client_ip, user_agent, 'failed', 'Wrong password', ja3_hash)
        # 规则 R1：多次输错 → 封 IP
        try:
            from ..security import enforce_failed_login_ip
            await enforce_failed_login_ip(async_db_query, client_ip, owner)
        except Exception as e:
            logging.error(f"enforce_failed_login_ip failed: {e}")
        return jsonify({'error': 'Invalid credentials'}), 401

    # 检查是否被封禁（白名单可绕过 account_ban）
    is_banned, ban_msg = await _is_user_banned(user)
    if is_banned and 'all' not in wl_bypass and 'account_ban' not in wl_bypass:
        # 记录失败日志
        await _record_login_log(user.get('uid', ''), owner, client_ip, user_agent, 'failed', f'Banned: {ban_msg}', ja3_hash)
        return jsonify({'error': f'Account banned: {ban_msg}'}), 403

    # ---- 设备类型检测与异常风险评分 ----
    from ..security import (
        parse_user_agent,
        calculate_login_risk,
        record_security_event,
        auto_temp_ban,
    )
    device = parse_user_agent(user_agent)
    user_data = dict(user)
    # 获取最近 24 小时登录日志，用于多 IP / 连续失败检测
    try:
        recent_logs = await async_db_query(
            "SELECT user_name, login_ip, status, created_at FROM login_logs "
            "WHERE user_name = ? AND created_at >= datetime('now', '-1 day')",
            (owner,)
        ) or []
    except Exception:
        recent_logs = []

    risk_score, risk_details, severity = calculate_login_risk(
        device, client_ip, user_data, recent_logs
    )

    # 记录安全事件（审计留档，始终执行）
    try:
        await record_security_event(
            async_db_query,
            user.get('uid', ''), owner, 'login', severity,
            risk_score, risk_details, client_ip, device,
            action_taken='',
        )
    except Exception as e:
        logging.error(f"Record security event failed: {e}")

    # 高风险评分仍记录安全事件（审计）；实际封禁改由三规则引擎驱动
    # （failed_login_ip / success_login_account / bulk_request_device），此处不再自动封禁
    if severity in ('restrict', 'ban'):
        logging.warning(f"登录高风险(仅审计): {owner} severity={severity} details={risk_details}")

    # 更新用户登录信息（含设备类型，供下次风险比对）；同时累加登录次数（供钩子 DSL 使用）
    try:
        await async_db_query(
            "UPDATE users SET last_login_ip = ?, last_login_time = CURRENT_TIMESTAMP, "
            "last_login_user_agent = ?, last_device_type = ?, last_device_os = ?, "
            "last_active_time = CURRENT_TIMESTAMP, login_count = COALESCE(login_count, 0) + 1 "
            "WHERE user_name = ?",
            (client_ip, user_agent, device.device_type,
             f"{device.os_name} {device.os_version}".strip(), owner)
        )
    except Exception as e:
        logging.error(f"Update login info failed: {e}")

    # 异地登录 / 设备异常提醒邮件
    last_login_ip = user.get('last_login_ip')
    user_email = user.get('email', '')
    if user_email and (severity == 'warn' or (last_login_ip and last_login_ip != client_ip)):
        try:
            from ..email_utils import send_login_alert_email
            from datetime import datetime
            login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            send_login_alert_email(
                user_email, owner, client_ip, user_agent, login_time,
                device_type=device.display_name, risk_level=severity,
                risk_details=risk_details,
            )
        except Exception as e:
            logging.error(f"Send login alert email failed: {e}")

    # 记录成功日志
    await _record_login_log(user.get('uid', ''), owner, client_ip, user_agent, 'success', '', ja3_hash)

    # 规则 R2：多次连续成功登录（不同 IP）→ 封账号（最低 10min，由规则引擎收敛）
    try:
        from ..security import enforce_success_login_account
        await enforce_success_login_account(async_db_query, owner, client_ip)
    except Exception as e:
        logging.error(f"enforce_success_login_account failed: {e}")

    # 多设备登录限制：检查活跃会话数，超过则踢掉最旧的
    try:
        # 获取用户设置的最大设备数（1~5，默认1）
        user_max_sessions = user.get('max_sessions', DEFAULT_MAX_SESSIONS)
        if user_max_sessions is None:
            user_max_sessions = DEFAULT_MAX_SESSIONS
        # 确保在合法范围内
        user_max_sessions = max(1, min(int(user_max_sessions), MAX_ACTIVE_SESSIONS))
        
        session_count = await _get_user_session_count(owner)
        if session_count >= user_max_sessions:
            # 超过限制，踢掉最旧的会话
            await _kick_oldest_session(owner)
        
        # 创建新会话
        session_id = await _create_session(
            username=owner,
            user_uid=user.get('uid', ''),
            user_agent=user_agent,
            ip=client_ip
        )
    except Exception as e:
        logging.error(f"Create session failed: {e}")
        # 会话创建失败不影响登录，降级为普通 session
        session_id = None

    # Session 只存用户名和会话ID，不存密码
    session['user'] = owner
    if session_id:
        session['session_id'] = session_id
    if user.get('is_honeypot'):
        session['is_honeypot'] = True
    session.permanent = True  # 使用 PERMANENT_SESSION_LIFETIME 有效期

    # ③ 强制管理员首次改密：管理员且被标记需改密时，记录到会话并返回标记
    must_change = False
    try:
        if user.get('is_admin') and user.get('must_change_password', 0):
            session['must_change_password'] = True
            must_change = True
    except Exception:
        pass

    # 确保与内置 admin 的默认好友关系存在（历史用户 / 手工建号兜底）
    try:
        await _ann.ensure_admin_friendship(user.get('uid', ''), owner)
    except Exception as e:
        logging.error(f"ensure_admin_friendship failed on login: {e}")

    # 触发登录事件（钩子引擎）。注意：login_count 已在上面 +1，钩子里读到的是本次登录后的值
    await fire_event('USER_LOGIN', trigger_user=user.get('uid', ''), client_ip=client_ip)

    return jsonify({
        'message': 'Logged in',
        'is_admin': bool(user.get('is_admin', 0)),
        'must_change_password': must_change,
    }), 200



@auth_bp.route('/api/password-reset/request', methods=['POST'])
async def password_reset_request():
    """请求密码重置（发送验证码到绑定邮箱）"""
    # 限流检查
    allowed, remaining = _check_rate_limit('login')  # 复用登录的限流配置
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429
    
    data = await request.get_json() or {}
    username = data.get('username', '').strip()
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    # 查找用户
    user = await async_db_query("SELECT user_name, email FROM users WHERE user_name = ?", (username,))
    
    # 无论用户是否存在，都返回相同的提示（防止用户名枚举）
    if not user or not user[0].get('email'):
        # 用户不存在或没有绑定邮箱，也返回成功提示（不泄露信息）
        return jsonify({'message': 'If the username exists and has a bound email, a reset code has been sent'}), 200
    
    email = user[0]['email']
    
    # 发送验证码邮件
    try:
        from ..email_utils import send_password_reset_email
        success, msg = send_password_reset_email(email, username)
        if not success:
            return jsonify({'error': msg}), 400
    except ImportError:
        return jsonify({'error': 'Email service not configured'}), 500
    except Exception as e:
        logging.error(f"Password reset email error: {e}")
        return jsonify({'error': 'Failed to send reset email'}), 500
    
    return jsonify({'message': 'If the username exists and has a bound email, a reset code has been sent'}), 200



@auth_bp.route('/api/password-reset/confirm', methods=['POST'])
async def password_reset_confirm():
    """确认密码重置（验证验证码并设置新密码）"""
    # 限流检查
    allowed, remaining = _check_rate_limit('password_reset')
    if not allowed:
        return jsonify({'error': 'Too many attempts, please try again later'}), 429

    data = await request.get_json() or {}
    username = data.get('username', '').strip()
    code = data.get('code', '').strip()
    new_password = data.get('new_password', '')
    
    if not username or not code or not new_password:
        return jsonify({'error': 'Username, code and new password required'}), 400
    
    # 新密码强度检查
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password too short (min {MIN_PASSWORD_LENGTH} chars)'}), 400
    if not any(c.isalpha() for c in new_password):
        return jsonify({'error': 'Password must contain at least one letter'}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({'error': 'Password must contain at least one digit'}), 400
    
    # 查找用户
    user = await async_db_query("SELECT user_name, email FROM users WHERE user_name = ?", (username,))
    if not user or not user[0].get('email'):
        return jsonify({'error': 'Invalid username or code'}), 400
    
    email = user[0]['email']
    
    # 验证验证码（绑定类型和用户名，防止跨用途/跨账号复用）
    try:
        from ..email_utils import verify_code
        success, msg = verify_code(email, code, expected_type='password_reset', expected_username=username)
        if not success:
            return jsonify({'error': msg}), 400
    except ImportError:
        return jsonify({'error': 'Email service not configured'}), 500
    
    # 更新密码
    new_password_hash = hash_password(new_password)
    await async_db_query(
        "UPDATE users SET user_password = ? WHERE user_name = ?",
        (new_password_hash, username)
    )
    
    logging.info(f"Password reset successful: user {username}")
    return jsonify({'message': 'Password reset successfully'}), 200


@auth_bp.route('/logout', methods=['POST'])
async def logout():
    # 删除数据库中的会话记录
    session_id = session.get('session_id')
    if session_id:
        try:
            await _delete_session(session_id)
        except Exception as e:
            logging.error(f"Delete session failed: {e}")
    
    session.clear()
    return jsonify({'message': 'Logged out'}), 200



@auth_bp.route("/api/change-password", methods=["POST"])


@auth_bp.route('/api/user/change-password', methods=['POST'])
async def change_password():
    """修改密码"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = await request.get_json() or {}
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    
    if not old_password or not new_password:
        return jsonify({'error': 'Old password and new password required'}), 400
    
    # 新密码长度检查
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password too short (min {MIN_PASSWORD_LENGTH} chars)'}), 400
    
    # 新密码强度检查
    if not any(c.isalpha() for c in new_password):
        return jsonify({'error': 'Password must contain at least one letter'}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({'error': 'Password must contain at least one digit'}), 400
    
    username = session['user']
    user = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 验证旧密码
    if not verify_password(old_password, user[0]['user_password']):
        return jsonify({'error': 'Old password incorrect'}), 400
    
    # 更新密码
    new_password_hash = hash_password(new_password)
    await async_db_query(
        "UPDATE users SET user_password = ? WHERE user_name = ?",
        (new_password_hash, username)
    )

    # ③ 清除强制改密标记
    try:
        await async_db_query(
            "UPDATE users SET must_change_password = 0 WHERE user_name = ?",
            (username,)
        )
    except Exception:
        pass
    session.pop('must_change_password', None)

    logging.info(f"Password changed: user {username}")
    return jsonify({'message': 'Password changed successfully'}), 200



@auth_bp.route('/login')
async def login_page():
    """登录页面"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return await render_template('login.html')



@auth_bp.route('/register')
async def register_page():
    """注册页面"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return await render_template('register.html')


_ALLOWED_SECTIONS = {'overview', 'apikeys', 'usage', 'recharge', 'admin', 'users', 'stats', 'model-prices', 'models', 'upstreams'}



@auth_bp.route('/forgot-password')
async def forgot_password_page():
    """忘记密码页面"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return await render_template('forgot_password.html')


# ---------- 邮箱验证码相关路由 ----------

