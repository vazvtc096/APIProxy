# -*- coding: utf-8 -*-
"""OIDC 客户端（依赖方 RP）：允许 APIProxy 用户用外部 OIDC 提供方登录。

本模块只把 APIProxy 当作 OIDC *客户端*（依赖方），不替代平台自身的 IdP 能力。
标准授权码 + PKCE 流程：
  1. /oidc/login/<provider> 生成 state + PKCE，重定向到提供方 authorize 端点；
  2. 提供方回调 /oidc/callback/<provider> 携带 code；
  3. 用 code + code_verifier 换 token（token 端点）；
  4. 用 access_token 拉 userinfo；
  5. 按 (provider_id, subject) 关联本地用户，未关联则按 email 绑定或自动建号；
  6. 建立 session。

提供方配置存 oidc_providers；本地用户 ↔ 外部 subject 映射存 user_oidc_links。
所有外部 HTTP 调用走 httpx，接受自签名/内网证书（configs.OIDC_TLS_VERIFY 可关）。
"""
import logging
import secrets
import string
import time
import uuid

import httpx

from .core_db import async_db_query
from . import configs

__all__ = [
    'list_providers',
    'get_enabled_providers',
    'get_provider',
    'discover',
    'create_provider',
    'update_provider',
    'delete_provider',
    'find_link',
    'create_link',
    'exchange_code',
    'fetch_userinfo',
    'resolve_local_user',
    'callback_url_for',
]

logger = logging.getLogger('oidc')


def _http_timeout() -> float:
    return float(getattr(configs, 'OIDC_HTTP_TIMEOUT', 15))


def _verify_tls() -> bool:
    return bool(getattr(configs, 'OIDC_TLS_VERIFY', True))


def callback_url_for(provider_id: str) -> str:
    base = (getattr(configs, 'BASEURL', '') or '').rstrip('/')
    return f"{base}/oidc/callback/{provider_id}"


# ---------- 提供方配置（管理员 CRUD） ----------

async def list_providers() -> list:
    rows = await async_db_query(
        "SELECT id, name, display_name, issuer, authorization_endpoint, token_endpoint, "
        "userinfo_endpoint, jwks_uri, client_id, enabled, auto_create, button_order, created_at "
        "FROM oidc_providers ORDER BY button_order ASC, id ASC")
    return [dict(r) for r in rows]


async def get_enabled_providers() -> list:
    rows = await async_db_query(
        "SELECT id, name, display_name, issuer, authorization_endpoint, token_endpoint, "
        "userinfo_endpoint, jwks_uri, client_id, enabled, auto_create, button_order "
        "FROM oidc_providers WHERE enabled = 1 ORDER BY button_order ASC, id ASC")
    return [dict(r) for r in rows]


async def get_provider(provider_id: str) -> dict | None:
    rows = await async_db_query("SELECT * FROM oidc_providers WHERE id = ?", (provider_id,))
    return dict(rows[0]) if rows else None


async def discover(issuer: str) -> dict:
    """拉取提供方 OIDC discovery 文档，补全端点。"""
    issuer = (issuer or '').rstrip('/')
    if not issuer:
        raise ValueError('issuer 不能为空')
    url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=_http_timeout(), verify=_verify_tls()) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        doc = resp.json()
    return {
        'issuer': doc.get('issuer', issuer),
        'authorization_endpoint': doc.get('authorization_endpoint'),
        'token_endpoint': doc.get('token_endpoint'),
        'userinfo_endpoint': doc.get('userinfo_endpoint'),
        'jwks_uri': doc.get('jwks_uri'),
    }


async def create_provider(data: dict) -> dict:
    """创建提供方。data 含 name/display_name/issuer/client_id/client_secret/端点/auto_create/button_order。
    若提供 issuer 但未给全端点，则自动 discovery 补全。返回新建行（含 id，secret 已哈希）。
    """
    name = (data.get('name') or '').strip()
    if not name:
        raise ValueError('name 必填')
    issuer = (data.get('issuer') or '').strip()
    auth_ep = (data.get('authorization_endpoint') or '').strip()
    token_ep = (data.get('token_endpoint') or '').strip()
    userinfo_ep = (data.get('userinfo_endpoint') or '').strip()
    jwks = (data.get('jwks_uri') or '').strip()
    # 自动 discovery 补全缺失端点
    if issuer and (not auth_ep or not token_ep or not userinfo_ep):
        try:
            doc = await discover(issuer)
            auth_ep = auth_ep or doc.get('authorization_endpoint') or ''
            token_ep = token_ep or doc.get('token_endpoint') or ''
            userinfo_ep = userinfo_ep or doc.get('userinfo_endpoint') or ''
            jwks = jwks or doc.get('jwks_uri') or ''
        except Exception as e:
            logger.warning(f"OIDC discovery failed for {issuer}: {e}")
    if not auth_ep or not token_ep or not userinfo_ep:
        raise ValueError('必须提供 authorization/token/userinfo 端点（或可用的 issuer 供自动发现）')
    secret = data.get('client_secret') or ''
    secret_hash = _hash_secret(secret) if secret else ''
    pid = 'oidc_' + uuid.uuid4().hex[:16]
    await async_db_query(
        """INSERT INTO oidc_providers
           (id, name, display_name, issuer, authorization_endpoint, token_endpoint,
            userinfo_endpoint, jwks_uri, client_id, client_secret, client_secret_hash, enabled,
            auto_create, button_order, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (pid, name, (data.get('display_name') or name),
         issuer, auth_ep, token_ep, userinfo_ep, jwks,
         (data.get('client_id') or ''), secret, secret_hash,
         1 if data.get('enabled', True) else 0,
         1 if data.get('auto_create') else 0,
         int(data.get('button_order') or 0)),
    )
    return await get_provider(pid)


async def update_provider(provider_id: str, data: dict) -> dict:
    prov = await get_provider(provider_id)
    if not prov:
        raise ValueError('提供方不存在')
    fields = []
    params = []
    for key in ('display_name', 'issuer', 'authorization_endpoint', 'token_endpoint',
               'userinfo_endpoint', 'jwks_uri', 'client_id'):
        if key in data and data[key] is not None:
            fields.append(f"{key} = ?")
            params.append(data[key])
    if 'enabled' in data:
        fields.append("enabled = ?")
        params.append(1 if data['enabled'] else 0)
    if 'auto_create' in data:
        fields.append("auto_create = ?")
        params.append(1 if data['auto_create'] else 0)
    if 'button_order' in data:
        fields.append("button_order = ?")
        params.append(int(data['button_order']))
    if data.get('client_secret'):
        fields.append("client_secret_hash = ?")
        params.append(_hash_secret(data['client_secret']))
    if not fields:
        return prov
    params.append(provider_id)
    await async_db_query(
        f"UPDATE oidc_providers SET {', '.join(fields)} WHERE id = ?", params)
    return await get_provider(provider_id)


async def delete_provider(provider_id: str):
    await async_db_query("DELETE FROM oidc_providers WHERE id = ?", (provider_id,))
    await async_db_query("DELETE FROM user_oidc_links WHERE provider_id = ?", (provider_id,))


# ---------- 本地用户关联 ----------

async def find_link(provider_id: str, subject_id: str) -> dict | None:
    rows = await async_db_query(
        "SELECT * FROM user_oidc_links WHERE provider_id = ? AND subject_id = ?",
        (provider_id, subject_id))
    return dict(rows[0]) if rows else None


async def create_link(user_uid: str, user_name: str, provider_id: str,
                      subject_id: str, email: str = ''):
    await async_db_query(
        """INSERT INTO user_oidc_links (user_uid, user_name, provider_id, subject_id, email, created_at)
           VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (user_uid, user_name, provider_id, subject_id, email or ''))


def _hash_secret(secret: str) -> str:
    import hashlib
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()


def _gen_username(base: str) -> str:
    """由外部标识生成合规本地用户名：仅保留 [a-zA-Z0-9_]，过长截断，空则随机。"""
    base = (base or '').strip().lower()
    allowed = [c for c in base if c.isalnum() or c == '_']
    name = ''.join(allowed)[:24] or ('oidc' + secrets.token_hex(4))
    return name


async def _create_local_user(username: str, email: str) -> str:
    """创建本地用户并建管理员好友关系，返回 user_name。用户名冲突自动加后缀。"""
    from .apikey import generate_uid, hash_password
    from . import announcements as _ann
    base = username
    attempt = 0
    while True:
        candidate = base if attempt == 0 else f"{base}_{attempt}"
        exists = await async_db_query("SELECT 1 FROM users WHERE user_name = ?", (candidate,))
        if not exists:
            username = candidate
            break
        attempt += 1
        if attempt > 20:
            username = f"{base}_{secrets.token_hex(4)}"
            break
    uid = generate_uid()
    # 外部登录账号：随机长密码（永不允许密码登录，除非用户自行设置）
    pw = secrets.token_urlsafe(24)
    await async_db_query(
        "INSERT INTO users (user_name, user_password, balence, uid, email) VALUES (?, ?, 0, ?, ?)",
        (username, hash_password(pw), uid, email or ''))
    try:
        await _ann.ensure_admin_friendship(uid, username)
    except Exception as e:
        logger.warning(f"ensure_admin_friendship failed for {username}: {e}")
    return username


async def resolve_local_user(provider_id: str, claims: dict, auto_create: bool) -> dict | None:
    """按 (provider, subject) 解析本地用户；未关联则按 email 绑定，再否则按 auto_create 建号。
    返回 {'user_name':..., 'user_uid':..., 'created':bool} 或 None（需先绑定）。
    """
    sub = claims.get('sub') or claims.get('sub_id') or ''
    email = (claims.get('email') or '').strip()
    if not sub:
        raise ValueError('userinfo 缺少 sub 标识')
    link = await find_link(provider_id, sub)
    if link:
        uname = link.get('user_name')
        u = await async_db_query("SELECT uid, user_name FROM users WHERE user_name = ?", (uname,))
        if u:
            return {'user_name': u[0]['user_name'], 'user_uid': u[0]['uid'], 'created': False}
    # 按 email 关联（若邮箱已存在本地账号，则绑定到它）
    if email:
        u = await async_db_query("SELECT uid, user_name FROM users WHERE email = ?", (email,))
        if u:
            uname = u[0]['user_name']
            await create_link(u[0]['uid'], uname, provider_id, sub, email)
            return {'user_name': uname, 'user_uid': u[0]['uid'], 'created': False}
    if not auto_create:
        return None
    uname = _gen_username(email.split('@')[0] if email else provider_id)
    uname = await _create_local_user(uname, email)
    u = await async_db_query("SELECT uid FROM users WHERE user_name = ?", (uname,))
    uid = u[0]['uid'] if u else ''
    await create_link(uid, uname, provider_id, sub, email)
    return {'user_name': uname, 'user_uid': uid, 'created': True}


# ---------- 协议交互 ----------

async def exchange_code(provider: dict, code: str, redirect_uri: str, code_verifier: str = '') -> dict:
    """用授权码换 token。返回解析后的 JSON（含 access_token / id_token 等）。"""
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': provider.get('client_id') or '',
    }
    if code_verifier:
        data['code_verifier'] = code_verifier
    secret = _client_secret(provider)
    if secret:
        # 机密客户端：优先 HTTP Basic（也带 body 兜底）
        auth = (provider.get('client_id') or '', secret)
    else:
        auth = None
    async with httpx.AsyncClient(timeout=_http_timeout(), verify=_verify_tls()) as client:
        resp = await client.post(
            provider['token_endpoint'], data=data,
            auth=auth, headers={'Accept': 'application/json'})
        resp.raise_for_status()
        return resp.json()


async def fetch_userinfo(provider: dict, access_token: str) -> dict:
    """用 access_token 拉 userinfo（优先 userinfo_endpoint，失败回退 id_token 解析暂不支持）。"""
    ep = provider.get('userinfo_endpoint')
    if not ep:
        raise ValueError('提供方未配置 userinfo_endpoint')
    async with httpx.AsyncClient(timeout=_http_timeout(), verify=_verify_tls()) as client:
        resp = await client.get(ep, headers={'Authorization': f'Bearer {access_token}'})
        resp.raise_for_status()
        return resp.json()


def _client_secret(provider: dict) -> str:
    """返回机密客户端的明文 client_secret（token 交换必需）。

    安全说明：OIDC 机密客户端必须凭 client_secret 换 token，因此明文存于
    oidc_providers.client_secret 列；client_secret_hash 仅作存在性/审计标记。
    管理员配置界面一律脱敏展示、写操作不回显。自管部署权衡；如需更强保护可外接 KMS。
    """
    return provider.get('client_secret') or ''


def gen_state() -> str:
    return secrets.token_urlsafe(32)


def gen_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def pkce_challenge(verifier: str) -> tuple:
    """返回 (challenge, method)。使用 S256。"""
    import hashlib
    import base64
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    chal = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return chal, 'S256'


def build_auth_url(provider: dict, state: str, redirect_uri: str,
                   code_challenge: str, scope: str = 'openid profile email') -> str:
    from urllib.parse import urlencode
    params = {
        'response_type': 'code',
        'client_id': provider.get('client_id') or '',
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    }
    sep = '&' if '?' in provider['authorization_endpoint'] else '?'
    return f"{provider['authorization_endpoint']}{sep}{urlencode(params)}"
