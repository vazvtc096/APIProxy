"""Google Gemini 兼容层：/v1beta/models/{model}:generateContent 等。

把 Gemini Generative Language API 请求翻译为 OpenAI chat/completions，复用既有
任务管道（鉴权、限流、封禁、用户组、令牌策略、模型映射、负载均衡、预扣费/退款、
用量日志），再把响应/流翻译回 Gemini 事件格式。

暂不支持：Gemini 原生 tools / functionCalling / codeExecution（按需再加）。
"""
import asyncio
import json
import logging
import time

from quart import Blueprint, request, jsonify, Response

from ..app import app
from ..core import (task_manager, async_db_query, _check_rate_limit, _is_user_banned)
from .. import oauth
from ..apikey import APIKey, _hash_apikey
from .. import user_groups, tokenpolicy, parampolicy, upstreams
from ..cloudflare import get_client_ip

gemini_bp = Blueprint('gemini_compat', __name__)

from ._gemini_translate import (
    _split_model_action, gemini_to_openai, openai_to_gemini,
    openai_chunk_to_gemini, gemini_sse,
)


async def _auth_and_owner():
    """复用 chat_proxy 的鉴权逻辑（APIKey 优先，OAuth 兜底），返回 (api_key_obj, error_tuple)。"""
    auth = request.headers.get('Authorization') or ''
    if not auth.startswith('Bearer '):
        return None, (jsonify({'error': {'code': 401, 'message': 'Missing Authorization header'}}), 401)
    token_str = auth.split(' ', 1)[1]
    api_key_obj = None
    try:
        api_key_obj = APIKey.from_apikey(token_str)
    except Exception:
        api_key_obj = None
    if api_key_obj is None:
        oauth_info = await oauth.validate_bearer(async_db_query, token_str)
        if oauth_info:
            if 'api' not in oauth_info['scope'].split():
                return None, (jsonify({'error': {'code': 403, 'message': 'api scope required'}}), 403)
            api_key_obj = type('OAuthKey', (), {'owner': oauth_info['user_name'], 'oauth': True})()
        else:
            return None, (jsonify({'error': {'code': 401, 'message': 'Invalid API key or OAuth token'}}), 401)
    return api_key_obj, None


@gemini_bp.route('/v1beta/models/<path:modelpath>', methods=['POST'])
@gemini_bp.route('/v1beta/models/<path:modelpath>/', methods=['POST'])
async def gemini_generate(modelpath: str):
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': {'code': 429, 'message': 'Rate limit exceeded'}}), 429

    api_key_obj, err = await _auth_and_owner()
    if err:
        return err

    model, action = _split_model_action(modelpath)
    is_stream = action.startswith('stream')

    users = await async_db_query("SELECT * FROM users WHERE user_name = ?", (api_key_obj.owner,))
    if users:
        is_banned, ban_msg = await _is_user_banned(users[0])
        if is_banned:
            return jsonify({'error': {'code': 403, 'message': f'Account banned: {ban_msg}'}}), 403

    body = await request.get_json() or {}
    try:
        translated = gemini_to_openai(body)
    except Exception as e:
        return jsonify({'error': {'code': 400, 'message': f'invalid request: {e}'}}), 400

    messages = translated['messages']
    if not messages:
        return jsonify({'error': {'code': 400, 'message': 'contents is required'}}), 400
    if not model:
        return jsonify({'error': {'code': 400, 'message': 'model is required'}}), 400

    # 用户组：模型白名单 + 价格倍率
    _allowed, _reason, _mult = user_groups.check_model_access(api_key_obj.owner, model)
    if not _allowed:
        return jsonify({'error': {'code': 403, 'message': _reason}}), 403

    # 令牌级策略（仅 APIKey）
    _key_hash = None
    if not getattr(api_key_obj, 'oauth', False):
        _kh = _hash_apikey(token_str) if (token_str := request.headers.get('Authorization', '').split(' ', 1)[-1]) else None
        _ok, _pr = tokenpolicy.check_policy(_kh, get_client_ip(), model)
        if not _ok:
            _status = 429 if _pr.startswith('token rate limit') else 403
            return jsonify({'error': {'code': _status, 'message': f'token policy rejected: {_pr}'}}), _status
        _key_hash = _kh

    # 参数治理
    _ok, _why = parampolicy.validate(body.get('generationConfig') or {})
    if not _ok:
        return jsonify({'error': {'code': 400, 'message': f'invalid parameter: {_why}'}}), 400

    req_data = {'model': model, 'messages': messages,
                'stream': is_stream, **translated['kwargs']}

    queue = await task_manager.get_queue(api_key_obj.owner)

    # ---- 非流式 ----
    if not is_stream:
        future = asyncio.Future()
        task_data = {'stream': False, 'future': future, 'apikey_obj': api_key_obj,
                     'req_data': req_data, 'price_multiplier': _mult, 'key_hash': _key_hash}
        await queue.put(task_data)
        try:
            result = await future
        except ValueError as e:
            return jsonify({'error': {'code': 400, 'message': str(e)}}), 400
        except Exception:
            logging.exception("gemini generate error")
            return jsonify({'error': {'code': 500, 'message': 'Service temporarily unavailable'}}), 500
        return jsonify(openai_to_gemini(result, model)), 200

    # ---- 流式：OpenAI chunk 流 -> Gemini SSE ----
    chunk_queue = asyncio.Queue()
    task_data = {'stream': True, 'chunk_queue': chunk_queue, 'apikey_obj': api_key_obj,
                 'req_data': req_data, 'price_multiplier': _mult, 'key_hash': _key_hash}
    await queue.put(task_data)

    async def generate():
        last_usage = None
        keepalive_timeout = 15
        while True:
            try:
                ctype, cdata = await asyncio.wait_for(chunk_queue.get(), timeout=keepalive_timeout)
            except asyncio.TimeoutError:
                yield ": ping\n\n"
                continue
            if ctype == 'done':
                if last_usage:
                    yield gemini_sse({'usageMetadata': last_usage, 'modelVersion': model})
                yield "data: [DONE]\n\n"
                break
            if ctype == 'error':
                yield gemini_sse({'error': {'code': 500, 'message': str(cdata)}})
                return
            chunk = cdata or {}
            if chunk.get('usage'):
                u = chunk['usage']
                last_usage = {
                    'promptTokenCount': int(u.get('prompt_tokens') or 0),
                    'candidatesTokenCount': int(u.get('completion_tokens') or 0),
                    'totalTokenCount': int(u.get('total_tokens') or 0),
                }
            gchunk = openai_chunk_to_gemini(chunk, model)
            if gchunk:
                yield gemini_sse(gchunk)

    return Response(generate(), mimetype='text/event-stream')


@gemini_bp.route('/v1beta/models', methods=['GET'])
async def gemini_list_models():
    """Gemini 形状的模型列表（name 前缀 models/）。"""
    try:
        names = list(upstreams._ALL_MODELS or [])
    except Exception:
        names = []
    return jsonify({
        "models": [{
            "name": f"models/{m}",
            "displayName": m,
            "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        } for m in names]
    }), 200
