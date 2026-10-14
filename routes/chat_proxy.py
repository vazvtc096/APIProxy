"""API 代理路由"""
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

chat_proxy_bp = Blueprint('chat_proxy', __name__)


def _token_policy_check(token_str: str, model: str):
    """令牌级策略校验（额度/过期/IP白名单/模型白名单/停用/RPM/TPM限速）。
    仅对 APIKey 生效（OAuth token 不在 apikeys 表）。返回 (error_response, key_hash)。"""
    try:
        from ..apikey import _hash_apikey
        from .. import tokenpolicy as _tp
        kh = _hash_apikey(token_str)
        ok, reason = _tp.check_policy(kh, _cf_get_client_ip(), model)
        if ok:
            return None, kh
        status = 429 if reason.startswith('token rate limit') else 403
        return (jsonify({'error': f'token policy rejected: {reason}'}), status), None
    except Exception as e:
        logging.error(f"token policy check failed: {e}")
        return None, None  # 策略层故障不阻断主链路


@chat_proxy_bp.route('/v1/models', methods=['GET'])
@chat_proxy_bp.route('/api/models', methods=['GET'])
async def list_models():
    # 1. 鉴权（保留调用者身份：owner + key_hash，用于可见性过滤）
    auth = request.headers.get('Authorization')
    owner = ''
    key_hash = ''
    authed = False
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ', 1)[1]
        try:
            ak = APIKey.from_apikey(token)
            if ak is not None:
                authed = True
                owner = ak.owner or ''
                try:
                    from ..apikey import _hash_apikey
                    key_hash = _hash_apikey(token)
                except Exception:
                    key_hash = ''
        except Exception:
            ak = None
        if not authed:
            oauth_info = await oauth.validate_bearer(async_db_query, token)
            if oauth_info and 'api' in oauth_info['scope'].split():
                authed = True
                owner = oauth_info.get('user_name') or oauth_info.get('username') or ''
    if not authed and 'user' in session:
        authed = True
        owner = session.get('user', '') or ''
    if not authed:
        return jsonify({'error': 'unauthorized',
                        'error_description': '需要登录会话，或有效的 API Key / OAuth Bearer（api scope）'}), 401

    # 2. 缓存，避免每次请求都打上游（缓存全量列表，按调用者过滤后返回）
    now = time.time()
    if _MODELS_CACHE['data'] is not None and (now - _MODELS_CACHE['ts']) < MODELS_CACHE_TTL:
        return jsonify(_visible_models(_MODELS_CACHE['data'], owner, key_hash))

    # 3. 合并所有上游的模型目录（已缓存，失败不致命：返回已缓存/空列表）
    try:
        ids = await upstreams.refresh_models()
    except Exception as e:
        # 上游刷新失败：若仍有有效陈旧缓存，降级返回并标注 staleness，
        # 避免短暂上游抖动即把全站模型列表打挂成 502。
        if _MODELS_CACHE['data'] is not None:
            logging.warning(f"list_models: 上游刷新失败，降级返回陈旧缓存：{e}")
            stale = dict(_MODELS_CACHE['data'])
            stale['stale'] = True
            return jsonify(_visible_models(stale, owner, key_hash))
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
    return jsonify(_visible_models(out, owner, key_hash))


def _visible_models(out: dict, owner: str, key_hash: str) -> dict:
    """按调用者可见性过滤模型列表（不修改缓存的全量对象）。

    两组约束取交集：
    - 用户组 allowed_models（登录会话/APIKey 的 owner 都适用；空 = 不限）
    - 令牌级模型白名单（仅 APIKey，apikeys.allowed_models；空 = 不限）
    过滤层任何异常都放行全量（与鉴权链路「策略故障不阻断」一致）。
    """
    ids = [d.get('id') for d in (out.get('data') or []) if d.get('id')]
    try:
        if owner:
            from .. import user_groups
            g = user_groups.get_group(user_groups.get_user_group(owner))
            pats = (g or {}).get('allowed_models') or []
            if pats:
                ids = [m for m in ids if user_groups._match_any(m, pats)]
    except Exception as e:
        logging.warning(f"list_models group filter skipped: {e}")
    try:
        if key_hash:
            from .. import tokenpolicy as _tp
            p = _tp.get_policy(key_hash)
            am = (p or {}).get('allowed_models') or ''
            if str(am).strip():
                ids = [m for m in ids if _tp.model_allowed(m, am)]
    except Exception as e:
        logging.warning(f"list_models token filter skipped: {e}")
    res = dict(out)
    res['data'] = [{'id': m} for m in ids]
    res['count'] = len(ids)
    return res



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



def _extract_delta_text(chunk: dict) -> str:
    """从上游 chunk 里解包增量文本（兼容 delta / message / 非标准结构）。"""
    try:
        choices = chunk.get('choices') or []
        if not choices:
            return ''
        c0 = choices[0] or {}
        delta = c0.get('delta')
        if isinstance(delta, dict) and delta.get('content'):
            return str(delta['content'])
        msg = c0.get('message')
        if isinstance(msg, dict) and msg.get('content'):
            return str(msg['content'])
        if isinstance(c0.get('text'), str):
            return c0['text']
    except Exception:
        pass
    return ''


def _extract_reasoning(chunk: dict) -> str:
    """提取思考内容（DeepSeek 风格 delta.reasoning_content），仅作空响应兜底。"""
    try:
        choices = chunk.get('choices') or []
        if not choices:
            return ''
        delta = choices[0].get('delta') or {}
        rc = delta.get('reasoning_content') or ''
        return str(rc) if rc else ''
    except Exception:
        return ''


async def _dispatch_chat(owner, req_data, apikey_obj, token_str=None, on_done=None):
    """chat completions 统一调度核心。

    /v1/chat/completions 与 /api/playground/chat 共用此函数，确保封禁校验、模型白名单、
    令牌级策略、参数治理、计费下游走的是同一套逻辑（单一事实来源）。

    owner:        计费身份（用户名）
    req_data:     完整 OpenAI chat.completions 形状请求体（model/messages/stream/...）
    apikey_obj:   带 .owner / .oauth 的命名空间对象，传给 task_manager 做扣费
    token_str:    原始 Bearer token（仅 APIKey 路径用于令牌策略；OAuth/session 传 None）
    on_done:      流式结束时回调 (acc_text) -> 可选额外 SSE 字符串；用于 playground 落库

    返回 dict:
      stream=True  -> {'stream': True,  'status': 200, 'response': <SSE Response>, 'result': None, 'error': None}
      stream=False -> {'stream': False, 'status': int, 'response': None, 'result': dict|None, 'error': dict|None}
    """
    # 账号封禁校验
    users = await async_db_query("SELECT * FROM users WHERE user_name = ?", (owner,))
    if users:
        is_banned, ban_msg = await _is_user_banned(users[0])
        if is_banned:
            return {'stream': False, 'status': 403, 'response': None, 'result': None,
                    'error': {'error': f'Account banned: {ban_msg}'}}

    # 用户组：模型白名单 + 价格倍率
    from .. import user_groups as _ug
    _allowed, _reason, _mult = _ug.check_model_access(owner, req_data.get('model') or '')
    if not _allowed:
        return {'stream': False, 'status': 403, 'response': None, 'result': None, 'error': {'error': _reason}}

    # 令牌级策略（仅 APIKey；OAuth/session 无 apikeys 表记录，跳过）
    _key_hash = None
    if not getattr(apikey_obj, 'oauth', False) and token_str:
        _tok_err, _key_hash = _token_policy_check(token_str, req_data.get('model') or '')
        if _tok_err:
            return {'stream': False, 'status': _tok_err[1], 'response': None, 'result': None, 'error': _tok_err[0]}

    # 请求参数治理：max_tokens 上限 / temperature/top_p 范围（全部来自配置，无硬编码魔数）
    from .. import parampolicy as _pp
    _ok, _why = _pp.validate(req_data)
    if not _ok:
        return {'stream': False, 'status': 400, 'response': None, 'result': None,
                'error': {'error': f'invalid parameter: {_why}'}}

    _is_stream = req_data.get('stream', False)
    queue = await task_manager.get_queue(owner)

    if _is_stream:
        chunk_queue = asyncio.Queue()
        task_data = {'stream': True, 'chunk_queue': chunk_queue, 'apikey_obj': apikey_obj,
                     'req_data': req_data, 'price_multiplier': _mult, 'key_hash': _key_hash}
        await queue.put(task_data)

        async def generate():
            acc = ''
            reasoning = ''
            keepalive_timeout = 15
            while True:
                try:
                    chunk_type, chunk_data = await asyncio.wait_for(chunk_queue.get(), timeout=keepalive_timeout)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                if chunk_type == 'done':
                    if on_done:
                        try:
                            extra = await on_done(acc or reasoning)
                            if extra:
                                yield extra
                        except Exception as e:
                            logging.error(f"_dispatch_chat on_done failed: {e}")
                    yield "data: [DONE]\n\n"
                    break
                elif chunk_type == 'error':
                    yield f"data: {json.dumps({'error': chunk_data})}\n\n"
                    break
                elif chunk_type == 'data':
                    yield f"data: {json.dumps(chunk_data)}\n\n"
                    acc += _extract_delta_text(chunk_data)
                    reasoning += _extract_reasoning(chunk_data)

        return {'stream': True, 'status': 200,
                'response': Response(generate(), mimetype='text/event-stream'),
                'result': None, 'error': None}

    future = asyncio.Future()
    task_data = {'stream': False, 'future': future, 'apikey_obj': apikey_obj,
                 'req_data': req_data, 'price_multiplier': _mult, 'key_hash': _key_hash}
    await queue.put(task_data)
    try:
        result = await future
        return {'stream': False, 'status': 200, 'response': None, 'result': result, 'error': None}
    except ValueError as e:
        return {'stream': False, 'status': 400, 'response': None, 'result': None, 'error': {'error': str(e)}}
    except Exception as e:
        logging.error(f"Chat API error for user {owner}: {e}")
        return {'stream': False, 'status': 500, 'response': None, 'result': None,
                'error': {'error': 'Service temporarily unavailable, please try again later'}}


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

    req_data = await request.get_json() or {}
    if not req_data:
        return jsonify({'error': 'Invalid JSON body'}), 400

    # 委托给统一调度核心（与 /api/playground/chat 共用：封禁/模型白名单/令牌策略/参数治理/计费）
    dispatch = await _dispatch_chat(api_key_obj.owner, req_data, apikey_obj, token_str)
    if dispatch['stream']:
        return dispatch['response']
    return jsonify(dispatch['result']), dispatch['status']
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
    # 用户组：模型白名单 + 价格倍率
    from .. import user_groups as _ug
    _allowed, _reason, _mult = _ug.check_model_access(owner, model)
    if not _allowed:
        return jsonify({'error': _reason}), 403

    # 令牌级策略（仅 APIKey）
    _key_hash = None
    if not getattr(api_key_obj, 'oauth', False):
        _tok_err, _key_hash = _token_policy_check(token_str, model)
        if _tok_err:
            return _tok_err

    # 请求参数治理：max_tokens 上限 / temperature/top_p 范围
    from .. import parampolicy as _pp
    _ok, _why = _pp.validate(body)
    if not _ok:
        return jsonify({'error': f'invalid parameter: {_why}'}), 400

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
                     'apikey_obj': api_key_obj, 'req_data': req_data,
                     'price_multiplier': _mult, 'key_hash': _key_hash}
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
                     'apikey_obj': api_key_obj, 'req_data': req_data,
                     'price_multiplier': _mult, 'key_hash': _key_hash}
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


