"""API 代理路由"""
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

chat_proxy_bp = Blueprint('chat_proxy', __name__)

@chat_proxy_bp.route('/v1/models', methods=['GET'])
@chat_proxy_bp.route('/api/models', methods=['GET'])
async def list_models():
    # 1. 鉴权
    auth = request.headers.get('Authorization')
    authed = False
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ', 1)[1]
        try:
            ak = APIKey.from_apikey(token)
            if ak is not None:
                authed = True
        except Exception:
            ak = None
        if not authed:
            oauth_info = await oauth.validate_bearer(async_db_query, token)
            if oauth_info and 'api' in oauth_info['scope'].split():
                authed = True
    if not authed and 'user' in session:
        authed = True
    if not authed:
        return jsonify({'error': 'unauthorized',
                        'error_description': '需要登录会话，或有效的 API Key / OAuth Bearer（api scope）'}), 401

    # 2. 缓存，避免每次请求都打上游
    now = time.time()
    if _MODELS_CACHE['data'] is not None and (now - _MODELS_CACHE['ts']) < MODELS_CACHE_TTL:
        return jsonify(_MODELS_CACHE['data'])

    # 3. 合并所有上游的模型目录（已缓存，失败不致命：返回已缓存/空列表）
    try:
        ids = await upstreams.refresh_models()
    except Exception as e:
        return jsonify({'error': 'upstream_models_failed',
                        'error_description': str(e)}), 502

    # 自动扩展：把上游返回但价格表还没有的模型登记进去（priced=0，待管理员定价）
    try:
        from . import db
        _conn = db.get_conn()
        try:
            _conn.execute(
                "CREATE TABLE IF NOT EXISTS model_prices "
                "(model TEXT PRIMARY KEY, input REAL NOT NULL DEFAULT 0, "
                "output REAL NOT NULL DEFAULT 0, priced INTEGER NOT NULL DEFAULT 0)"
            )
            if ids:
                _conn.executemany(
                    "INSERT OR IGNORE INTO model_prices (model, input, output, priced) VALUES (?, 0, 0, 0)",
                    [(i,) for i in ids],
                )
            _conn.commit()
        finally:
            _conn.close()
    except Exception:
        pass

    out = {'object': 'list', 'data': [{'id': i} for i in ids], 'count': len(ids)}
    _MODELS_CACHE['data'] = out
    _MODELS_CACHE['ts'] = now
    return jsonify(out)



@chat_proxy_bp.route('/api/pricing/current', methods=['GET'])
async def api_pricing_current():
    """当前时段计费档位（登录用户可见）。返回各模型当前命中的峰/谷价与档位。"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    import time
    now = time.localtime()
    pricing_cfg = configs.PRICING or {}
    models = pricing_cfg.get('models') or {}
    out = {}
    for m, entry in models.items():
        if not isinstance(entry, dict):
            continue
        inp, outp, tier = pricing.resolve_price_tier(m, None, now)
        out[m] = {'input': inp, 'output': outp, 'tier': tier}
    default = pricing_cfg.get('default') or {'input': 2, 'output': 4}
    return jsonify({
        'now': f"{now.tm_hour:02d}:{now.tm_min:02d}:{now.tm_sec:02d}",
        'models': out,
        'default': {'input': float(default.get('input', 2)), 'output': float(default.get('output', 4))}
    }), 200



@chat_proxy_bp.route('/v1/chat/completions', methods=['POST'])
@chat_proxy_bp.route('/api/chat/completions', methods=['POST'])
async def chat_completions():
    # 限流检查（按 API Key 限流）
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token_str = auth.split(' ')[1]

    # 限流检查（token 维度）
    allowed, remaining = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429

    # 1. 优先尝试 API Key（trusted 模式）
    api_key_obj = None
    try:
        api_key_obj = APIKey.from_apikey(token_str)
    except Exception:
        api_key_obj = None

    # 2. 退而尝试 OAuth 2.0 Bearer access token (JWT)
    if api_key_obj is None:
        oauth_info = await oauth.validate_bearer(async_db_query, token_str)
        if oauth_info:
            if 'api' not in oauth_info['scope'].split():
                return jsonify({'error': 'Insufficient scope: api scope required for proxy access'}), 403
            owner = oauth_info['user_name']
            # 用轻量命名空间对象复用后续基于 apikey_obj.owner 的扣费逻辑
            api_key_obj = type('OAuthKey', (), {'owner': owner, 'oauth': True})()
        else:
            return jsonify({'error': 'Invalid API key or OAuth access token'}), 401

    owner = api_key_obj.owner
    
    # 检查用户是否被封禁
    users = await async_db_query(
        "SELECT * FROM users WHERE user_name = ?",
        (owner,)
    )
    if users:
        is_banned, ban_msg = await _is_user_banned(users[0])
        if is_banned:
            return jsonify({'error': f'Account banned: {ban_msg}'}), 403

    # 3. 解析请求
    req_data = await request.get_json() or {}
    if not req_data:
        return jsonify({'error': 'Invalid JSON body'}), 400

    is_stream = req_data.get('stream', False)

    # 4. 获取该用户的队列
    queue = await task_manager.get_queue(owner)

    if is_stream:
        # 流式响应
        chunk_queue = asyncio.Queue()
        task_data = {
            'stream': True,
            'chunk_queue': chunk_queue,
            'apikey_obj': api_key_obj,
            'req_data': req_data
        }
        await queue.put(task_data)

        async def generate():
            # 保活间隔：长思考 / 上游空闲超过该时间未推任何数据块时，
            # 发送 SSE 注释行心跳，避免中间代理（nginx 默认 60s 读超时等）
            # 因空闲 RST 连接（客户端表现为 WinError 10054）。
            keepalive_timeout = 15
            while True:
                try:
                    chunk_type, chunk_data = await asyncio.wait_for(
                        chunk_queue.get(), timeout=keepalive_timeout)
                except asyncio.TimeoutError:
                    # SSE 注释行，客户端会忽略但能刷新空闲计时，防止连接被中间层断开
                    yield ": ping\n\n"
                    continue
                if chunk_type == 'done':
                    yield "data: [DONE]\n\n"
                    break
                elif chunk_type == 'error':
                    yield f"data: {json.dumps({'error': chunk_data})}\n\n"
                    break
                elif chunk_type == 'data':
                    yield f"data: {json.dumps(chunk_data)}\n\n"

        return Response(generate(), mimetype='text/event-stream')
    else:
        # 非流式响应
        future = asyncio.Future()
        task_data = {
            'stream': False,
            'future': future,
            'apikey_obj': api_key_obj,
            'req_data': req_data
        }
        await queue.put(task_data)

        try:
            result = await future
            return jsonify(result), 200
        except ValueError as e:
            # 业务错误（余额不足等）可以返回具体信息
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            # 内部错误脱敏，详细信息记日志
            logging.error(f"Chat API error for user {owner}: {e}")
            return jsonify({'error': 'Service temporarily unavailable, please try again later'}), 500


# ========== OpenAI Responses API（/v1/responses） ==========
# 翻译层：把 Responses 的 input 转为 chat messages，复用 _process_task/_process_stream_task 完成
# 上游代理与计费，再把 chat.completions 结果/流翻译回 Responses 形状。支持流式 SSE。


@chat_proxy_bp.route('/v1/responses', methods=['POST'])
async def responses_api():
    # 1. 鉴权（与 chat completions 一致）
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token_str = auth.split(' ')[1]

    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429

    api_key_obj = None
    try:
        api_key_obj = APIKey.from_apikey(token_str)
    except Exception:
        api_key_obj = None
    if api_key_obj is None:
        oauth_info = await oauth.validate_bearer(async_db_query, token_str)
        if oauth_info:
            if 'api' not in oauth_info['scope'].split():
                return jsonify({'error': 'Insufficient scope: api scope required'}), 403
            api_key_obj = type('OAuthKey', (), {'owner': oauth_info['user_name'], 'oauth': True})()
        else:
            return jsonify({'error': 'Invalid API key or OAuth access token'}), 401
    owner = api_key_obj.owner

    users = await async_db_query("SELECT * FROM users WHERE user_name = ?", (owner,))
    if users:
        is_banned, ban_msg = await _is_user_banned(users[0])
        if is_banned:
            return jsonify({'error': f'Account banned: {ban_msg}'}), 403

    # 2. 解析并转换为 chat messages
    body = await request.get_json() or {}
    if not body or not isinstance(body, dict):
        return jsonify({'error': 'Invalid JSON body'}), 400
    model = body.get('model')
    if not model:
        return jsonify({'error': 'model is required'}), 400
    messages = _responses_input_to_messages(body)

    # 透传其余兼容参数（temperature / top_p / max_output_tokens / tools / ...）
    req_data = {
        'model': model,
        'messages': messages,
        'stream': bool(body.get('stream', False)),
    }
    for k_src, k_dst in (('temperature', 'temperature'), ('top_p', 'top_p'),
                         ('max_output_tokens', 'max_tokens'), ('tools', 'tools'),
                         ('tool_choice', 'tool_choice'), ('n', 'n'),
                         ('stop', 'stop'), ('seed', 'seed'),
                         ('presence_penalty', 'presence_penalty'),
                         ('frequency_penalty', 'frequency_penalty')):
        if k_src in body:
            req_data[k_dst] = body[k_src]

    is_stream = req_data['stream']
    queue = await task_manager.get_queue(owner)

    if is_stream:
        chunk_queue = asyncio.Queue()
        task_data = {'stream': True, 'chunk_queue': chunk_queue,
                     'apikey_obj': api_key_obj, 'req_data': req_data}
        await queue.put(task_data)

        resp_id = 'resp_' + secrets.token_hex(12)
        msg_id = 'msg_' + secrets.token_hex(12)
        created = int(time.time())

        def _skeleton(status):
            return {'id': resp_id, 'object': 'response', 'created_at': created,
                    'status': status, 'model': model, 'output': [], 'usage': None}

        async def generate():
            keepalive_timeout = 15
            yield _sse_response_event('response.created', _skeleton('in_progress'))
            yield _sse_response_event('response.in_progress', _skeleton('in_progress'))
            yield _sse_response_event('response.output_item.added', {
                'output_index': 0,
                'item': {'id': msg_id, 'type': 'message', 'status': 'in_progress',
                         'role': 'assistant', 'content': []}})
            yield _sse_response_event('response.content_part.added', {
                'item_id': msg_id, 'output_index': 0, 'content_index': 0,
                'part': {'type': 'output_text', 'text': ''}})
            text = ''
            while True:
                try:
                    ctype, cdata = await asyncio.wait_for(chunk_queue.get(), timeout=keepalive_timeout)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                if ctype == 'done':
                    break
                if ctype == 'error':
                    yield _sse_response_event('response.failed', {'response': _skeleton('failed')})
                    return
                # chat.completions chunk
                chunk = cdata or {}
                delta = ((chunk.get('choices') or [{}])[0] or {}).get('delta', {})
                d = delta.get('content')
                if d:
                    text += d
                    yield _sse_response_event('response.output_text.delta', {
                        'item_id': msg_id, 'output_index': 0, 'content_index': 0, 'delta': d})
            final_item = {'id': msg_id, 'type': 'message', 'status': 'completed',
                          'role': 'assistant',
                          'content': [{'type': 'output_text', 'text': text, 'annotations': []}]}
            yield _sse_response_event('response.output_text.done', {
                'item_id': msg_id, 'output_index': 0, 'content_index': 0, 'text': text})
            yield _sse_response_event('response.output_item.done',
                                     {'output_index': 0, 'item': final_item})
            yield _sse_response_event('response.completed', {
                'response': {'id': resp_id, 'object': 'response', 'created_at': created,
                             'status': 'completed', 'model': model, 'output': [final_item],
                             'usage': None}})

        return Response(generate(), mimetype='text/event-stream')
    else:
        future = asyncio.Future()
        task_data = {'stream': False, 'future': future,
                     'apikey_obj': api_key_obj, 'req_data': req_data}
        await queue.put(task_data)
        try:
            result = await future
            return jsonify(_chat_to_responses(result, model)), 200
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logging.error(f"Responses API error for user {owner}: {e}")
            return jsonify({'error': 'Service temporarily unavailable, please try again later'}), 500


# ========== OAuth 2.0 授权服务器端点 ==========


