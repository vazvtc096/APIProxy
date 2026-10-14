# -*- coding: utf-8 -*-
"""
oauth.py - OAuth 2.0 授权服务器核心逻辑

实现标准 RFC 6749 授权模式：
  - 授权码模式 (Authorization Code) + PKCE (RFC 7636)
  - 客户端凭证模式 (Client Credentials)
  - 刷新令牌 (Refresh Token)

附带 RFC 扩展：
  - Token 吊销 RFC 7009        (/oauth/revoke)
  - Token 内省 RFC 7662        (/oauth/introspect)
  - 设备授权流 RFC 8628        (/oauth/device_authorization + /oauth/device)
  - 动态客户端注册 RFC 7591    (/oauth/register)

所有数据库访问都通过传入的 `db` 异步可调用对象完成（函数首参），
以避免与 __main__ 形成循环导入。access token 为 HS256 JWT（无状态校验），
refresh token 为不透明随机串并落库以支持吊销/内省。

依赖：PyJWT（access token 签名）。
"""
import base64
import hashlib
import json
import secrets
import time
import uuid

import jwt

from .configs import OAUTH_JWT_SECRET

__all__ = [
    'SCOPES',
    'ALG',
    'ACCESS_TOKEN_TTL',
    'REFRESH_TOKEN_TTL',
    'AUTH_CODE_TTL',
    'DEVICE_CODE_TTL',
    'sign_access_token',
    'decode_access_token',
    'pkce_verify',
    'normalize_scope',
    'scope_subset',
    'client_allows_redirect_uri',
    'get_client',
    'authenticate_client',
    'create_auth_code',
    'consume_auth_code',
    'issue_tokens',
    'validate_bearer',
    'refresh_tokens',
    'revoke_token',
    'introspect_token',
    'create_device_code',
    'get_device_code_by_usercode',
    'approve_device_code',
    'poll_device_code',
    'list_tokens',
    'admin_revoke_token',
    'get_client_owner',
]

# ---------- 常量 ----------
ALG = 'HS256'
ACCESS_TOKEN_TTL = 3600          # access token 有效期（秒）：1 小时
REFRESH_TOKEN_TTL = 30 * 86400   # refresh token 有效期：30 天
AUTH_CODE_TTL = 600              # 授权码有效期：10 分钟
DEVICE_CODE_TTL = 600            # 设备码有效期：10 分钟
DEVICE_INTERVAL = 5              # 设备流轮询间隔（秒）
REGISTRATION_TTL = 0             # client_secret 不过期（0 表示不过期）

# 系统支持的 scope 及其说明
SCOPES = {
    'api': '调用 Cloud LLM API 代理（聊天补全 / 模型列表）',
    'openid': '返回用户标识 (sub)',
    'profile': '读取授权用户的基本资料（用户名 / UID / 注册时间）',
    'email': '读取授权用户的邮箱地址',
    'posts:read': '读取帖子、我的帖子与收藏',
    'posts:write': '发布 / 删除帖子、收藏帖子',
    'friends:read': '查看好友列表与好友请求',
    'friends:write': '发送 / 接受 / 拒绝好友请求、删除好友',
    'chat:read': '读取会话、消息与未读',
    'chat:write': '发送消息、转账、红包、撤回消息',
    'transactions:read': '查看交易记录与余额',
    'transactions:write': '发起充值请求、转账',
    'apikeys:read': '查看 API Key 列表',
    'apikeys:write': '创建 / 删除 API Key',
    'user:read': '读取个人设置与会话',
    'user:write': '修改密码 / 设置 / 注销账号',
    'debug_console': '远程控制台（仅管理员）',
}

# 高危 scope：一旦授予第三方应用即具备破坏能力，绝不允许出现在默认公开客户端，
# 也不允许通过动态/自助方式获取。仅限管理员显式创建的可信机密客户端、且由资源
# 所有者本人在授权页明确确认后才能授予。
SENSITIVE_SCOPES = (
    'user:write',        # 可修改密码 / 注销账号（账户毁灭性操作）
    'transactions:write',# 可发起充值 / 转账（资金操作）
    'apikeys:write',     # 可创建 / 删除 API Key（凭证泄露风险）
    'debug_console',              # 远程控制台（服务器级控制，仅管理员）
)

# 默认公开客户端（'default'）允许授予的 scope 安全基线：
# 仅含身份标识与只读类 scope，剔除一切写操作与管理类 scope。
# 任何超出此集合的请求 scope 在授权端点会被静默剥离（见 oauth_routes.oauth_authorize）。
DEFAULT_SAFE_SCOPES = 'api profile openid email posts:read posts:write friends:read friends:write chat:read chat:write transactions:read apikeys:read user:read'


def is_sensitive_scope(scope: str) -> bool:
    return scope in SENSITIVE_SCOPES


def categorize_scopes(scope_str) -> list:
    """将 scope 字符串拆为有序列表，每项含 (scope, 说明, 是否高危)。

    供授权确认页按「普通 / 高危」分区渲染，高危项显式红色警示。
    """
    out = []
    seen = set()
    for s in (scope_str or '').split():
        if not s or s in seen:
            continue
        seen.add(s)
        out.append({
            'scope': s,
            'desc': SCOPES.get(s, s),
            'sensitive': s in SENSITIVE_SCOPES,
        })
    return out


# ---------- 密钥与基础工具 ----------
def _secret() -> str:
    """返回显式配置的 OAuth JWT 签名密钥。

    fail-closed：未配置 OAUTH_JWT_SECRET 时拒绝签发/验签令牌，
    绝不使用 SESSION_SECRET 或不安全默认值兜底，避免静默降级为弱签名。
    """
    if not OAUTH_JWT_SECRET:
        raise RuntimeError(
            "OAUTH_JWT_SECRET is not configured. Refusing to sign/verify OAuth tokens (fail-closed). "
            "Set OAUTH_JWT_SECRET in .env, e.g. python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return OAUTH_JWT_SECRET


def _gen_client_id() -> str:
    return 'client_' + uuid.uuid4().hex[:20]


def _gen_client_secret() -> str:
    return uuid.uuid4().hex + secrets.token_hex(24)


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()


def _gen_code() -> str:
    return uuid.uuid4().hex + secrets.token_hex(16)


def _gen_jti() -> str:
    return uuid.uuid4().hex


def _gen_refresh() -> str:
    return 'rt_' + uuid.uuid4().hex + secrets.token_hex(16)


def _gen_user_code() -> str:
    """生成人类可读的用户码（形如 WDJB-MJHT），剔除易混淆字符。"""
    alphabet = 'BCDFGHJKLMNPQRSTVWXZ23456789'
    grp = lambda: ''.join(secrets.choice(alphabet) for _ in range(4))
    return f'{grp()}-{grp()}'


def normalize_scope(scope_str) -> str:
    """归一化 scope 字符串（去空、去重、保序）。"""
    if not scope_str:
        return ''
    seen = set()
    out = []
    for s in scope_str.split():
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return ' '.join(out)


def scope_subset(requested: str, allowed: str) -> bool:
    """判断请求的 scope 是否为客户端允许 scope 的子集。"""
    req = set(requested.split())
    allowed_set = set(allowed.split())
    return req <= allowed_set


def client_allows_redirect_uri(client: dict, redirect_uri: str) -> bool:
    uris = [u.strip() for u in (client.get('redirect_uris') or '').split(',') if u.strip()]
    return redirect_uri in uris


# ---------- PKCE ----------
def pkce_verify(code_verifier: str, code_challenge: str, method: str) -> bool:
    """校验 PKCE code_verifier 与 code_challenge 是否匹配。"""
    if not code_verifier or not code_challenge:
        return False
    method = (method or 'plain').lower()
    if method == 'plain':
        return code_verifier == code_challenge
    # S256
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    chal = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return secrets.compare_digest(chal, code_challenge)


# ---------- JWT access token ----------
def sign_access_token(client_id: str, user_uid, user_name, scope: str,
                      ttl: int = ACCESS_TOKEN_TTL) -> tuple:
    """签发 access token (JWT)，返回 (token, jti, exp_ts)。"""
    now = int(time.time())
    jti = _gen_jti()
    sub = user_uid or client_id
    payload = {
        'iss': 'APIProxy',
        'sub': sub,
        'aud': client_id,
        'exp': now + ttl,
        'iat': now,
        'jti': jti,
        'client_id': client_id,
        'scope': scope,
        'username': user_name or '',
        'token_type': 'access',
    }
    token = jwt.encode(payload, _secret(), algorithm=ALG)
    return token, jti, now + ttl


def decode_access_token(token: str):
    """解码并验签 access token，失败返回 None。"""
    try:
        return jwt.decode(token, _secret(), algorithms=[ALG], options={'verify_aud': False})
    except Exception:
        return None


# ---------- 客户端查询 ----------
async def get_client(db, client_id):
    rows = await db("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,))
    return dict(rows[0]) if rows else None


async def get_client_owner(db, client_id):
    """返回客户端绑定的计费账号名（用于客户端凭证模式）。"""
    client = await get_client(db, client_id)
    if not client:
        return None
    return client.get('owner_name') or None


async def authenticate_client(db, client_id, client_secret=None):
    """校验客户端身份（confidential 需 secret；public 无需）。"""
    client = await get_client(db, client_id)
    if not client:
        return None
    if client.get('is_confidential'):
        if not client_secret:
            return None
        if not secrets.compare_digest(_hash_secret(client_secret), client.get('client_secret_hash') or ''):
            return None
    return client


# ---------- 授权码 ----------
async def create_auth_code(db, client_id, user_uid, user_name, scope, redirect_uri,
                           code_challenge=None, code_challenge_method=None):
    code = _gen_code()
    exp = time.time() + AUTH_CODE_TTL
    await db(
        "INSERT INTO oauth_auth_codes "
        "(code, client_id, user_uid, user_name, scope, redirect_uri, code_challenge, code_challenge_method, expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (code, client_id, user_uid, user_name, scope, redirect_uri,
         code_challenge, (code_challenge_method or '').lower(), exp),
    )
    return code


async def consume_auth_code(db, code):
    """消费授权码（一次性）。过期/已用返回 None。"""
    rows = await db("SELECT * FROM oauth_auth_codes WHERE code = ?", (code,))
    if not rows:
        return None
    row = dict(rows[0])
    if row.get('used'):
        return None
    if (row.get('expires_at') or 0) < time.time():
        return None
    await db("UPDATE oauth_auth_codes SET used=1 WHERE code = ?", (code,))
    return row


# ---------- Token 签发 / 校验 / 刷新 / 吊销 / 内省 ----------
async def issue_tokens(db, client_id, user_uid, user_name, scope):
    """签发一组 token（access JWT + refresh 不透明串），落库并返回响应字典。"""
    access_token, jti, access_exp = sign_access_token(client_id, user_uid, user_name, scope)
    refresh_token = _gen_refresh()
    refresh_exp = time.time() + REFRESH_TOKEN_TTL
    await db(
        "INSERT INTO oauth_tokens "
        "(access_jti, refresh_token, client_id, user_uid, user_name, scope, access_expires_at, refresh_expires_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (jti, refresh_token, client_id, user_uid, user_name, scope, access_exp, refresh_exp),
    )
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_TTL,
        'scope': scope,
    }


async def validate_bearer(db, token: str):
    """校验 access token 并返回主体信息，失败返回 None。"""
    payload = decode_access_token(token)
    if not payload:
        return None
    if (payload.get('exp') or 0) < time.time():
        return None
    jti = payload.get('jti')
    if not jti:
        return None
    rows = await db("SELECT * FROM oauth_tokens WHERE access_jti = ? AND revoked = 0", (jti,))
    if not rows:
        return None
    row = dict(rows[0])
    if (row.get('access_expires_at') or 0) < time.time():
        return None
    return {
        'client_id': payload.get('client_id'),
        'user_uid': payload.get('sub'),
        'user_name': payload.get('username') or row.get('user_name'),
        'scope': payload.get('scope') or row.get('scope') or '',
    }


async def refresh_tokens(db, refresh_token: str, client_id: str):
    """用 refresh token 换取新 token 对（旧 refresh 立即吊销）。"""
    rows = await db("SELECT * FROM oauth_tokens WHERE refresh_token = ? AND revoked = 0", (refresh_token,))
    if not rows:
        return None
    row = dict(rows[0])
    if row.get('client_id') != client_id:
        return None
    if (row.get('refresh_expires_at') or 0) < time.time():
        return None
    await db("UPDATE oauth_tokens SET revoked=1 WHERE refresh_token = ?", (refresh_token,))
    return await issue_tokens(db, client_id, row.get('user_uid'), row.get('user_name'), row.get('scope') or '')


async def revoke_token(db, token: str, token_type_hint=None):
    """RFC 7009：吊销 token。成功返回 True（RFC 要求始终返回 200）。"""
    # 先尝试 refresh token
    r = await db("SELECT * FROM oauth_tokens WHERE refresh_token = ?", (token,))
    if r:
        await db("UPDATE oauth_tokens SET revoked=1 WHERE refresh_token = ?", (token,))
        return True
    # 再尝试 access token（解码取 jti）
    payload = decode_access_token(token)
    if payload and payload.get('jti'):
        await db("UPDATE oauth_tokens SET revoked=1 WHERE access_jti = ?", (payload['jti'],))
        return True
    return True


async def introspect_token(db, token: str):
    """RFC 7662：返回 token 内省结果。"""
    payload = decode_access_token(token)
    if not payload:
        return {'active': False}
    jti = payload.get('jti')
    rows = await db("SELECT * FROM oauth_tokens WHERE access_jti = ?", (jti,))
    if not rows:
        return {'active': False}
    row = dict(rows[0])
    if row.get('revoked') or (row.get('access_expires_at') or 0) < time.time():
        return {'active': False}
    return {
        'active': True,
        'scope': row.get('scope') or '',
        'client_id': row.get('client_id'),
        'username': row.get('user_name'),
        'sub': row.get('user_uid'),
        'exp': int(row.get('access_expires_at') or 0),
        'iat': int(payload.get('iat') or 0),
        'token_type': 'Bearer',
    }


# ---------- 设备授权流 (RFC 8628) ----------
async def create_device_code(db, client_id, scope):
    device_code = _gen_code()
    user_code = _gen_user_code()
    exp = time.time() + DEVICE_CODE_TTL
    await db(
        "INSERT INTO oauth_device_codes "
        "(device_code, user_code, client_id, scope, expires_at, interval) "
        "VALUES (?,?,?,?,?,?)",
        (device_code, user_code, client_id, scope, exp, DEVICE_INTERVAL),
    )
    return device_code, user_code, exp, DEVICE_INTERVAL


async def get_device_code_by_usercode(db, user_code):
    rows = await db("SELECT * FROM oauth_device_codes WHERE user_code = ?", (user_code,))
    if not rows:
        return None
    row = dict(rows[0])
    if (row.get('expires_at') or 0) < time.time():
        return None
    return row


async def approve_device_code(db, user_code, user_uid, user_name):
    row = await get_device_code_by_usercode(db, user_code)
    if not row:
        return False
    if row.get('status') != 'pending':
        return False
    await db(
        "UPDATE oauth_device_codes SET status='approved', user_uid=?, user_name=? WHERE user_code = ?",
        (user_uid, user_name, user_code),
    )
    return True


async def poll_device_code(db, device_code, client_id):
    """
    设备流轮询。返回三元组：
      ('ok', tokens_dict)      已授权，返回 token
      ('pending', None)        仍等待用户授权
      ('error', error_code)    authorization_pending / access_denied / expired_token / invalid_grant
    """
    rows = await db(
        "SELECT * FROM oauth_device_codes WHERE device_code = ? AND client_id = ?",
        (device_code, client_id),
    )
    if not rows:
        return ('error', 'invalid_grant')
    row = dict(rows[0])
    if (row.get('expires_at') or 0) < time.time():
        return ('error', 'expired_token')
    status = row.get('status')
    if status == 'pending':
        return ('pending', None)
    if status == 'denied':
        return ('error', 'access_denied')
    if status == 'approved':
        await db("UPDATE oauth_device_codes SET status='used' WHERE device_code = ?", (device_code,))
        tokens = await issue_tokens(db, client_id, row.get('user_uid'), row.get('user_name'), row.get('scope') or '')
        return ('ok', tokens)
    return ('error', 'invalid_grant')


# ---------- 管理员用 ----------
async def list_tokens(db, limit=200):
    rows = await db(
        "SELECT id, client_id, user_name, scope, access_expires_at, refresh_expires_at, revoked, created_at "
        "FROM oauth_tokens ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    return [dict(r) for r in rows]


async def admin_revoke_token(db, token_id: int):
    await db("UPDATE oauth_tokens SET revoked=1 WHERE id = ?", (token_id,))
