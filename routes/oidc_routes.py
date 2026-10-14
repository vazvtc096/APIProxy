# -*- coding: utf-8 -*-
"""OIDC 外部登录路由（依赖方 RP）。

- GET  /login/oidc                  列出已启用的外部提供方（或返回 JSON）
- GET  /oidc/login/<provider_id>    发起授权码 + PKCE 流程（重定向到提供方）
- GET  /oidc/callback/<provider_id> 提供方回调：换 token → userinfo → 关联/建号 → 建立会话
- 管理员：
    GET    /api/admin/oidc/providers
    POST   /api/admin/oidc/providers
    PUT    /api/admin/oidc/providers/<pid>
    DELETE /api/admin/oidc/providers/<pid>
"""
import logging

from quart import Blueprint, request, session, jsonify, redirect, url_for, render_template

from ..app import app
from .. import oidc
from ..core_db import async_db_query
from ..cloudflare import get_client_ip

oidc_bp = Blueprint('oidc', __name__)
logger = logging.getLogger('oidc_routes')


def _is_admin() -> bool:
    """当前会话是否为管理员（用于管理员 CRUD 守卫）。"""
    username = session.get('user')
    if not username:
        return False
    return _admin_check(username)


async def _admin_check(username: str) -> bool:
    rows = await async_db_query("SELECT is_admin FROM users WHERE user_name = ?", (username,))
    return bool(rows and int(rows[0].get('is_admin') or 0))


async def _require_admin():
    """返回 None 表示通过，否则返回 (resp, status) 元组。"""
    username = session.get('user')
    if not username:
        return jsonify({'error': 'unauthorized'}), 401
    if not await _admin_check(username):
        return jsonify({'error': 'forbidden'}), 403
    return None


@oidc_bp.route('/login/oidc', methods=['GET'])
async def oidc_login_page():
    """外部登录入口：列出已启用的提供方。"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    providers = await oidc.get_enabled_providers()
    # 仅暴露展示字段（不含 secret）
    safe = [{'id': p['id'], 'display_name': p.get('display_name') or p['name'],
             'name': p['name']} for p in providers]
    if request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({'providers': safe}), 200
    return await render_template('oidc_login.html', providers=safe)


@oidc_bp.route('/oidc/login/<provider_id>', methods=['GET'])
async def oidc_start(provider_id: str):
    """发起 OIDC 授权流程。"""
    provider = await oidc.get_provider(provider_id)
    if not provider or not int(provider.get('enabled') or 0):
        return jsonify({'error': 'provider not found or disabled'}), 404
    state = oidc.gen_state()
    verifier = oidc.gen_code_verifier()
    challenge, method = oidc.pkce_challenge(verifier)
    # 存入会话（state 防 CSRF，verifier 用于换 token）
    session['oidc_state'] = state
    session['oidc_verifier'] = verifier
    session['oidc_provider'] = provider_id
    session.permanent = True
    redirect_uri = oidc.callback_url_for(provider_id)
    auth_url = oidc.build_auth_url(provider, state, redirect_uri, challenge)
    return redirect(auth_url)


@oidc_bp.route('/oidc/callback/<provider_id>', methods=['GET'])
async def oidc_callback(provider_id: str):
    """提供方回调：完成授权码交换并登录。"""
    provider = await oidc.get_provider(provider_id)
    if not provider:
        return redirect('/login?error=oidc_provider_missing')
    # state 校验（防 CSRF）
    req_state = request.args.get('state', '')
    saved_state = session.get('oidc_state')
    saved_verifier = session.get('oidc_verifier')
    saved_provider = session.get('oidc_provider')
    # 任何不匹配都拒绝
    if not saved_state or req_state != saved_state or saved_provider != provider_id or not saved_verifier:
        return redirect('/login?error=oidc_state_mismatch')
    # 清理会话里的流程态
    session.pop('oidc_state', None)
    session.pop('oidc_verifier', None)
    session.pop('oidc_provider', None)

    error = request.args.get('error')
    if error:
        return redirect(f'/login?error=oidc_{error}')
    code = request.args.get('code', '')
    if not code:
        return redirect('/login?error=oidc_no_code')

    redirect_uri = oidc.callback_url_for(provider_id)
    try:
        tok = await oidc.exchange_code(provider, code, redirect_uri, saved_verifier)
        access_token = tok.get('access_token')
        if not access_token:
            return redirect('/login?error=oidc_no_token')
        claims = await oidc.fetch_userinfo(provider, access_token)
        resolved = await oidc.resolve_local_user(
            provider_id, claims, bool(int(provider.get('auto_create') or 0)))
    except Exception as e:
        logger.error(f"OIDC callback failed for {provider_id}: {e}")
        return redirect('/login?error=oidc_exchange_failed')

    if not resolved:
        # 未关联且未开自动注册：引导用户先在本站注册/登录并到设置页绑定
        return redirect('/login?error=oidc_not_linked')
    user_name = resolved['user_name']
    # 建立会话（与本站登录一致）
    try:
        from ..core import _create_session
        ua = request.headers.get('User-Agent', '')
        ip = get_client_ip()
        sid = await _create_session(username=user_name, user_uid=resolved.get('user_uid', ''),
                                   user_agent=ua, ip=ip)
        if sid:
            session['session_id'] = sid
    except Exception as e:
        logger.warning(f"OIDC _create_session failed (ignored): {e}")
    session['user'] = user_name
    session.permanent = True
    return redirect('/dashboard')


# ---------- 管理员 CRUD ----------

@oidc_bp.route('/api/admin/oidc/providers', methods=['GET'])
async def admin_list_providers():
    guard = await _require_admin()
    if guard:
        return guard
    providers = await oidc.list_providers()
    # 脱敏：不返回 client_secret 明文，仅给存在性标记
    safe = []
    for p in providers:
        p = dict(p)
        has_secret = bool(p.get('client_secret'))
        p.pop('client_secret', None)
        p['has_client_secret'] = has_secret
        safe.append(p)
    return jsonify({'providers': safe}), 200


@oidc_bp.route('/api/admin/oidc/providers', methods=['POST'])
async def admin_create_provider():
    guard = await _require_admin()
    if guard:
        return guard
    data = await request.get_json() or {}
    try:
        prov = await oidc.create_provider(data)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    prov = dict(prov)
    prov.pop('client_secret', None)
    return jsonify({'provider': prov}), 201


@oidc_bp.route('/api/admin/oidc/providers/<provider_id>', methods=['PUT'])
async def admin_update_provider(provider_id: str):
    guard = await _require_admin()
    if guard:
        return guard
    data = await request.get_json() or {}
    try:
        prov = await oidc.update_provider(provider_id, data)
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    if not prov:
        return jsonify({'error': 'provider not found'}), 404
    prov = dict(prov)
    prov.pop('client_secret', None)
    return jsonify({'provider': prov}), 200


@oidc_bp.route('/api/admin/oidc/providers/<provider_id>', methods=['DELETE'])
async def admin_delete_provider(provider_id: str):
    guard = await _require_admin()
    if guard:
        return guard
    await oidc.delete_provider(provider_id)
    return jsonify({'ok': True}), 200
