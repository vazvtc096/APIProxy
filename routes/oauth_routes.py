"""OAuth 2.0 路由"""
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
from .user import delete_apikey

oauth_bp = Blueprint('oauth', __name__)

@oauth_bp.route('/oauth/authorize', methods=['GET', 'POST'])
async def oauth_authorize():
    """授权端点：采用授权码 + PKCE（与 GitHub 公共客户端一致）。
    - client_id=default（或不传）走内置公开客户端：redirect_uri 可为任意 http(s) 绝对地址（支持第三方回调）、必须带 code_challenge（强制 PKCE）。
    - 已注册 client_id 走标准授权码流程。
    登录并确认授权后，重定向到 redirect_uri?code=...&state=...，由前端用 code_verifier 调 /oauth/token 换 token。
    """
    if request.method == 'GET':
        client_id = request.args.get('client_id', '')
        redirect_uri = request.args.get('redirect_uri', '')
        response_type = request.args.get('response_type', '')
        scope = request.args.get('scope', '')
        state = request.args.get('state', '')
        code_challenge = request.args.get('code_challenge', '')
        code_challenge_method = request.args.get('code_challenge_method', '')
        username = password = decision = ''
    else:
        form = await request.form
        client_id = form.get('client_id', '')
        redirect_uri = form.get('redirect_uri', '')
        response_type = form.get('response_type', '')
        scope = form.get('scope', '')
        state = form.get('state', '')
        code_challenge = form.get('code_challenge', '')
        code_challenge_method = form.get('code_challenge_method', '')
        decision = form.get('decision', '')
        username = form.get('username', '')
        password = form.get('password', '')

    client_id = (client_id or '').strip()
    redirect_uri = (redirect_uri or '').strip()
    # 无客户端语义：空 client_id 视为使用内置公开客户端 'default'
    if not client_id:
        client_id = 'default'
    is_default = (client_id == 'default')

    if is_default:
        # 内置公开客户端：不校验 secret；redirect_uri 允许任意 http(s) 绝对地址（第三方回调）；强制 PKCE（code_challenge 必填）
        client = await oauth.get_client(async_db_query, 'default')
        if not client:
            return jsonify({'error': 'server_error', 'error_description': '内置默认客户端未初始化'}), 500
        if not redirect_uri:
            return jsonify({'error': 'invalid_request', 'error_description': 'redirect_uri is required'}), 400
        if not _is_absolute_http_uri(redirect_uri):
            return jsonify({'error': 'invalid_redirect_uri', 'error_description': 'redirect_uri must be an absolute http(s) URL'}), 400
        if not code_challenge:
            return jsonify({'error': 'invalid_request', 'error_description': 'code_challenge is required (PKCE mandatory)'}), 400
        if response_type and response_type != 'code':
            return _oauth_redirect_error(redirect_uri, 'unsupported_response_type', state)
        scope = oauth.normalize_scope(scope) or 'api'
        # 收紧：默认公开客户端只授予安全基线 scope，剥离任何高危 scope
        # （user:write / transactions:write / apikeys:write / debug_console），避免第三方应用一键索取账户毁灭性权限。
        _req_scopes = set(scope.split())
        _unsafe = _req_scopes & set(oauth.SENSITIVE_SCOPES)
        if _unsafe:
            _safe = _req_scopes - set(oauth.SENSITIVE_SCOPES)
            scope = oauth.normalize_scope(' '.join(sorted(_safe))) or 'api'
    else:
        client = await oauth.get_client(async_db_query, client_id)
        if not client:
            return jsonify({'error': 'invalid_client', 'error_description': 'unknown client_id'}), 400
        if not oauth.client_allows_redirect_uri(client, redirect_uri):
            return jsonify({'error': 'invalid_redirect_uri'}), 400
        if response_type and response_type != 'code':
            return _oauth_redirect_error(redirect_uri, 'unsupported_response_type', state)
        scope = oauth.normalize_scope(scope) or (client.get('scopes') or 'api')
        if not oauth.scope_subset(scope, client.get('scopes') or ''):
            return _oauth_redirect_error(redirect_uri, 'invalid_scope', state)

    # 尚未登录：展示登录表单
    if 'user' not in session:
        if request.method == 'POST' and username and password:
            users = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
            if users and verify_password(password, users[0]['user_password']):
                session['user'] = username
                # 登录成功，落到下方授权确认环节
            else:
                return await render_template('oauth_login.html', error='用户名或密码错误',
                                             client=client,
                                             client_id=client_id, redirect_uri=redirect_uri,
                                             response_type=response_type, scope=scope, state=state,
                                             code_challenge=code_challenge, code_challenge_method=code_challenge_method)
        else:
            return await render_template('oauth_login.html', error='',
                                         client=client,
                                         client_id=client_id, redirect_uri=redirect_uri, response_type=response_type,
                                         scope=scope, state=state, code_challenge=code_challenge,
                                         code_challenge_method=code_challenge_method)
        # 登录成功，继续向下进入授权确认

    # 已登录（或刚登录成功）：展示授权确认页，确认后才发授权码
    _scopes_categorized = oauth.categorize_scopes(scope)
    if request.method == 'POST' and decision:
        if decision == 'allow':
            # debug_console 仅为管理员保留：非管理员请求到含 debug_console 的 scope 直接拒绝
            if 'debug_console' in scope.split():
                _u = await async_db_query("SELECT is_admin FROM users WHERE user_name = ?", (session['user'],))
                if not _u or not int(_u[0].get('is_admin') or 0):
                    return _oauth_redirect_error(redirect_uri, 'access_denied', state)
            urows = await async_db_query("SELECT uid, user_name FROM users WHERE user_name = ?", (session['user'],))
            uid = urows[0]['uid'] if urows else ''
            code = await oauth.create_auth_code(async_db_query, client_id, uid, session['user'], scope,
                                                redirect_uri, code_challenge, code_challenge_method)
            sep = '&' if '?' in redirect_uri else '?'
            return redirect(f"{redirect_uri}{sep}code={code}&state={state}")
        return _oauth_redirect_error(redirect_uri, 'access_denied', state)

    return await render_template('oauth_consent.html', client=client, scope=scope,
                                 scopes_categorized=_scopes_categorized, state=state,
                                 client_id=client_id, redirect_uri=redirect_uri, response_type=response_type,
                                 code_challenge=code_challenge, code_challenge_method=code_challenge_method,
                                 user_name=session['user'])



@oauth_bp.route('/oauth/token', methods=['POST'])
async def oauth_token():
    """Token 端点：授权码 + PKCE / 刷新令牌 / 客户端凭证。"""
    form = await request.form
    grant_type = form.get('grant_type', '')
    client_id = form.get('client_id', '')
    client_secret = form.get('client_secret', '')

    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        import base64
        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            cid, csec = decoded.split(':', 1)
            client_id = client_id or cid
            client_secret = client_secret or csec
        except Exception:
            pass

    if grant_type not in ('authorization_code', 'refresh_token', 'client_credentials'):
        return jsonify({'error': 'unsupported_grant_type'}), 400

    client = await oauth.authenticate_client(async_db_query, client_id, client_secret)
    if not client:
        return jsonify({'error': 'invalid_client'}), 401

    if grant_type == 'authorization_code':
        code = form.get('code', '')
        redirect_uri = form.get('redirect_uri', '')
        code_verifier = form.get('code_verifier', '')
        row = await oauth.consume_auth_code(async_db_query, code)
        if not row:
            return jsonify({'error': 'invalid_grant', 'error_description': 'authorization code invalid or expired'}), 400
        if row['client_id'] != client_id:
            return jsonify({'error': 'invalid_grant'}), 400
        if redirect_uri and row['redirect_uri'] != redirect_uri:
            return jsonify({'error': 'invalid_grant', 'error_description': 'redirect_uri mismatch'}), 400
        chal = row.get('code_challenge')
        if chal:
            method = row.get('code_challenge_method') or 'plain'
            if not oauth.pkce_verify(code_verifier, chal, method):
                return jsonify({'error': 'invalid_grant', 'error_description': 'PKCE verification failed'}), 400
        tokens = await oauth.issue_tokens(async_db_query, client_id, row['user_uid'], row['user_name'], row['scope'])
        return jsonify(tokens), 200

    if grant_type == 'refresh_token':
        refresh_token = form.get('refresh_token', '')
        tokens = await oauth.refresh_tokens(async_db_query, refresh_token, client_id)
        if not tokens:
            return jsonify({'error': 'invalid_grant', 'error_description': 'refresh token invalid or expired'}), 400
        return jsonify(tokens), 200

    if grant_type == 'client_credentials':
        scope = oauth.normalize_scope(form.get('scope', ''))
        if scope and not oauth.scope_subset(scope, client.get('scopes') or ''):
            return jsonify({'error': 'invalid_scope'}), 400
        scope = scope or (client.get('scopes') or 'api')
        owner = client.get('owner_name') or None
        if not owner:
            return jsonify({'error': 'invalid_grant', 'error_description': 'client has no bound owner account'}), 400
        urows = await async_db_query("SELECT uid, user_name FROM users WHERE user_name = ?", (owner,))
        if not urows:
            return jsonify({'error': 'invalid_grant', 'error_description': 'bound owner account not found'}), 400
        tokens = await oauth.issue_tokens(async_db_query, client_id, urows[0]['uid'], owner, scope)
        return jsonify(tokens), 200

    return jsonify({'error': 'unsupported_grant_type'}), 400



@oauth_bp.route('/oauth/revoke', methods=['POST'])
async def oauth_revoke():
    """RFC 7009 Token 吊销端点。"""
    form = await request.form
    token = form.get('token', '')
    token_type_hint = form.get('token_type_hint', '')
    client_id = form.get('client_id', '')
    client_secret = form.get('client_secret', '')
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        import base64
        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            cid, csec = decoded.split(':', 1)
            client_id = client_id or cid
            client_secret = client_secret or csec
        except Exception:
            pass
    if client_id:
        client = await oauth.authenticate_client(async_db_query, client_id, client_secret)
        if not client:
            return jsonify({'error': 'invalid_client'}), 401
    if not token:
        return jsonify({'error': 'invalid_request'}), 400
    await oauth.revoke_token(async_db_query, token, token_type_hint)
    return jsonify({}), 200



@oauth_bp.route('/oauth/introspect', methods=['POST'])
async def oauth_introspect():
    """RFC 7662 Token 内省端点。"""
    form = await request.form
    token = form.get('token', '')
    client_id = form.get('client_id', '')
    client_secret = form.get('client_secret', '')
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        import base64
        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            cid, csec = decoded.split(':', 1)
            client_id = client_id or cid
            client_secret = client_secret or csec
        except Exception:
            pass
    client = await oauth.authenticate_client(async_db_query, client_id, client_secret)
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    if not token:
        return jsonify({'error': 'invalid_request'}), 400
    result = await oauth.introspect_token(async_db_query, token)
    if result.get('active') and result.get('client_id') != client_id:
        return jsonify({'active': False}), 200
    return jsonify(result), 200



@oauth_bp.route('/oauth/device_authorization', methods=['POST'])
async def oauth_device_authorization():
    """RFC 8628 设备授权端点。"""
    form = await request.form
    client_id = form.get('client_id', '')
    client_secret = form.get('client_secret', '')
    scope = oauth.normalize_scope(form.get('scope', ''))
    client = await oauth.authenticate_client(async_db_query, client_id, client_secret)
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    if scope and not oauth.scope_subset(scope, client.get('scopes') or ''):
        return jsonify({'error': 'invalid_scope'}), 400
    scope = scope or (client.get('scopes') or 'api')
    device_code, user_code, exp, interval = await oauth.create_device_code(async_db_query, client_id, scope)
    return jsonify({
        'device_code': device_code,
        'user_code': user_code,
        'verification_uri': '/oauth/device',
        'verification_uri_complete': f'/oauth/device?user_code={user_code}',
        'interval': interval,
        'expires_in': int(exp - time.time()),
    }), 200



@oauth_bp.route('/oauth/device', methods=['GET', 'POST'])
async def oauth_device():
    """RFC 8628 用户验证页（GET 展示表单，POST 处理登录与授权决策）。"""
    if request.method == 'GET':
        user_code = request.args.get('user_code', '')
        if 'user' not in session:
            return await render_template('oauth_device.html', logged_in=False, user_code=user_code, error='')
        return await render_template('oauth_device.html', logged_in=True, user_code=user_code, error='', user_name=session['user'])

    form = await request.form
    user_code = form.get('user_code', '')
    decision = form.get('decision', '')
    username = form.get('username', '')
    password = form.get('password', '')

    if 'user' not in session:
        if username and password:
            users = await async_db_query("SELECT * FROM users WHERE user_name = ?", (username,))
            if users and verify_password(password, users[0]['user_password']):
                session['user'] = username
            else:
                return await render_template('oauth_device.html', logged_in=False, user_code=user_code, error='用户名或密码错误')
        else:
            return await render_template('oauth_device.html', logged_in=False, user_code=user_code, error='')

    if decision == 'allow' and user_code:
        ok = await oauth.approve_device_code(async_db_query, user_code, '', session['user'])
        if ok:
            return await render_template('oauth_device.html', logged_in=True, user_code='', error='', success=True, user_name=session['user'])
        return await render_template('oauth_device.html', logged_in=True, user_code=user_code, error='用户码无效或已处理', user_name=session['user'])
    if decision == 'deny' and user_code:
        row = await oauth.get_device_code_by_usercode(async_db_query, user_code)
        if row:
            await async_db_query("UPDATE oauth_device_codes SET status='denied' WHERE user_code = ?", (user_code,))
        return await render_template('oauth_device.html', logged_in=True, user_code='', error='', denied=True, user_name=session['user'])
    return await render_template('oauth_device.html', logged_in=True, user_code=user_code, error='', user_name=session['user'])



@oauth_bp.route('/oauth/register', methods=['POST'])
async def oauth_register():
    """RFC 7591 动态客户端注册。

    - 受 config.yaml 的 OAUTH_REGISTRATION_OPEN 控制（关闭时返回 403）。
    - 按 IP 限流（复用 register 类别：60s / 3 次），防止被批量注册刷爆客户端表。
    - 安全钳制：动态注册的客户端**只能获得安全基线 scope**，SENSITIVE_SCOPES
      （user:write / transactions:write / apikeys:write / debug_console）一律剥离，
      避免任何访客自助注册后诱导用户授权账户毁灭性 / 资金类权限。
    """
    if not getattr(configs, 'OAUTH_REGISTRATION_OPEN', False):
        return jsonify({'error': 'registration_not_supported',
                        'error_description': '动态客户端注册已关闭（OAUTH_REGISTRATION_OPEN=false）'}), 403

    _allowed, _remaining = _check_rate_limit('register')
    if not _allowed:
        return jsonify({'error': 'too_many_requests',
                        'error_description': '注册过于频繁，请稍后再试'}), 429

    metadata = await request.get_json(silent=True)
    if not isinstance(metadata, dict):
        form = await request.form
        metadata = {k: form.get(k) for k in
                    ('client_name', 'scope', 'redirect_uris', 'grant_types', 'token_endpoint_auth_method')}
        metadata = {k: v for k, v in metadata.items() if v}
        for k in ('redirect_uris', 'grant_types'):
            v = metadata.get(k)
            if isinstance(v, str):
                metadata[k] = [x.strip() for x in v.split(',') if x.strip()]

    redirect_uris = metadata.get('redirect_uris') or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return jsonify({'error': 'invalid_redirect_uri',
                        'error_description': 'redirect_uris 至少需要一个回调地址（字符串数组）'}), 400
    for u in redirect_uris:
        _u = (u or '').strip()
        _ok = (_u.startswith('https://')
               or _u.startswith('http://localhost')
               or _u.startswith('http://127.0.0.1'))
        if not _ok:
            return jsonify({'error': 'invalid_redirect_uri',
                            'error_description': f'回调地址必须为 https://（或本机 http://localhost / http://127.0.0.1）：{u}'}), 400

    name = (metadata.get('client_name') or '').strip()
    if len(name) > 128:
        return jsonify({'error': 'invalid_client_metadata',
                        'error_description': 'client_name 过长（≤128 字符）'}), 400

    resp = await oauth.register_client(async_db_query, metadata)
    resp['registration_client_uri'] = '/oauth/register/' + resp['client_id']
    resp['client_id_issued_at'] = int(time.time())
    return jsonify(resp), 201



@oauth_bp.route('/oauth/callback')
async def oauth_callback():
    """无客户端模式下的同源回调页：展示 GitHub 风格的授权成功提示（token 在 URL 片段中，不在页面显示）。"""
    return await render_template('oauth_callback.html')



@oauth_bp.route('/oauth/userinfo', methods=['GET', 'POST'])
async def oauth_userinfo():
    """OAuth 用户信息端点（需 profile / openid scope）。"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'invalid_token'}), 401
    token = auth.split(' ', 1)[1]
    info = await oauth.validate_bearer(async_db_query, token)
    if not info:
        return jsonify({'error': 'invalid_token'}), 401
    scopes = info['scope'].split()
    if 'profile' not in scopes and 'openid' not in scopes:
        return jsonify({'error': 'insufficient_scope', 'error_description': 'requires profile or openid scope'}), 403
    resp = {'sub': info['user_uid'], 'username': info['user_name']}
    if 'profile' in scopes or 'email' in scopes:
        urows = await async_db_query(
            "SELECT email, uid, created_at FROM users WHERE user_name = ?", (info['user_name'],))
        if urows:
            u = urows[0]
            if 'profile' in scopes:
                resp['uid'] = u.get('uid')
                resp['created_at'] = u.get('created_at')
            if 'email' in scopes:
                resp['email'] = u.get('email') or ''
    return jsonify(resp), 200



@oauth_bp.route('/api/oauth', methods=['GET'])
@oauth_bp.route('/api/oauth/', methods=['GET'])
@oauth_bp.route('/api/oauth/<resource>', methods=['GET', 'POST', 'DELETE'])
@oauth_bp.route('/api/oauth/<resource>/<path:sub>', methods=['GET', 'POST', 'DELETE'])
async def oauth_api(resource=None, sub=None):
    """OAuth 授权访问统一入口。

    - 只接受 `Authorization: Bearer <access_token>`，不接受 cookie 会话；
    - GET /api/oauth 返回资源目录（含每项所需 scope 与当前令牌是否已获授权）；
    - 其余请求按资源表校验 scope 后，转交给对应的业务处理函数。
    """
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({
            'error': 'invalid_token',
            'error_description': '/api/oauth 命名空间只接受 OAuth Bearer 令牌，不接受 cookie 会话'
        }), 401
    info = await oauth.validate_bearer(async_db_query, auth.split(' ', 1)[1])
    if not info:
        return jsonify({'error': 'invalid_token'}), 401
    granted = set(info['scope'].split())

    # 资源目录
    if not resource:
        catalog = {}
        for name, methods in OAUTH_API_RESOURCES.items():
            catalog[name] = {
                'path': f'/api/oauth/{name}',
                'methods': {
                    m: {'scope': ' '.join(req),
                        'granted': not _scope_satisfied(req, granted)}
                    for m, (req, _h) in methods.items()
                }
            }
        return jsonify({'base': '/api/oauth', 'scope': info['scope'], 'resources': catalog}), 200

    entry = OAUTH_API_RESOURCES.get(resource)
    if not entry:
        return jsonify({'error': 'unknown_resource',
                        'error_description': '可用资源：' + ' '.join(sorted(OAUTH_API_RESOURCES))}), 404
    spec = entry.get(request.method)
    if not spec:
        return jsonify({'error': 'method_not_allowed',
                        'error_description': f'{resource} 支持的方法：' + ' '.join(sorted(entry))}), 405

    required, handler_name = spec
    missing = _scope_satisfied(required, granted)
    if missing:
        return jsonify({'error': 'insufficient_scope',
                        'error_description': 'requires: ' + ' '.join(missing)}), 403

    # 业务处理函数复用仪表盘那套，靠 session['user'] 识别身份，这里注入即可。
    # 该 session 不会下发 cookie，见 _oauth_ns_no_cookie。
    session['user'] = info['user_name']

    if resource == 'apikeys' and request.method == 'DELETE':
        if not sub:
            return jsonify({'error': 'invalid_request',
                            'error_description': '用法：DELETE /api/oauth/apikeys/<key>'}), 400
        return await delete_apikey(sub)
    return await globals()[handler_name]()



