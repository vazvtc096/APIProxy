"""OAuth 辅助：回调重定向、Bearer 用户解析、API 资源 scope 映射。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
from quart import request, session, jsonify, redirect

from . import oauth
from .core_db import async_db_query


def _oauth_redirect_error(redirect_uri: str, error: str, state: str):
    """构造带 error 的回调重定向（RFC 6749）。"""
    from urllib.parse import urlencode
    q = {'error': error}
    if state:
        q['state'] = state
    sep = '&' if '?' in redirect_uri else '?'
    return redirect(f"{redirect_uri}{sep}{urlencode(q)}")


async def _oauth_ensure_user(required_scopes):
    """为普通 API 端点增加 OAuth Bearer 支持（不改变原有 cookie 流程）。

    - 无 Authorization 头：返回 None，由端点原有的 session 校验继续处理。
    - 有 Bearer：校验 token 有效性 + scope 是否满足 required_scopes；
      通过则把用户名注入 session['user']（供 _get_current_user 复用），返回 None；
      失败返回 (response, status) 元组，调用方直接 return。
    """
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth.split(' ', 1)[1]
    info = await oauth.validate_bearer(async_db_query, token)
    if not info:
        return jsonify({'error': 'invalid_token'}), 401
    scopes = info['scope'].split()
    missing = [s for s in required_scopes if s not in scopes]
    if missing:
        return jsonify({'error': 'insufficient_scope', 'error_description': 'requires: ' + ' '.join(missing)}), 403
    session['user'] = info['user_name']
    return None


OAUTH_API_RESOURCES = {
    'userinfo':     {'GET':    (['profile|openid'],        'oauth_userinfo')},
    'posts':        {'GET':    (['posts:read'],            'list_posts'),
                     'POST':   (['posts:write'],           'create_post')},
    'friends':      {'GET':    (['friends:read'],          'list_friends'),
                     'POST':   (['friends:write'],         'send_friend_request')},
    'chat':         {'GET':    (['chat:read'],             'list_conversations'),
                     'POST':   (['chat:write'],            'send_message')},
    'transactions': {'GET':    (['transactions:read'],     'my_transactions'),
                     'POST':   (['transactions:write'],    'recharge_request')},
    'apikeys':      {'GET':    (['apikeys:read'],          'list_apikeys'),
                     'POST':   (['apikeys:write'],         'create_apikey'),
                     'DELETE': (['apikeys:write'],         'delete_apikey')},
    'settings':     {'GET':    (['user:read'],             'get_user_settings'),
                     'POST':   (['user:write'],            'update_user_settings')},
}


_ALLOWED_SECTIONS = {'overview', 'apikeys', 'usage', 'recharge', 'admin', 'users', 'stats', 'model-prices', 'models', 'upstreams'}
