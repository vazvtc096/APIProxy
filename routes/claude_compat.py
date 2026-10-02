"""Anthropic Messages API 兼容层：/v1/messages。

把 Claude 原生请求（system / content blocks / image source.base64）翻译为
OpenAI chat/completions，复用既有任务管道（鉴权、限流、封禁、用户组、
令牌策略、模型映射、负载均衡、预扣费/退款、用量日志），再把响应/SSE 流
翻译回 Anthropic 事件格式。

暂不支持：tools/tool_use（Anthropic 工具调用语义与 OpenAI 差异大，按需再加）。
"""
import asyncio
import json
import logging
import secrets
import time

from quart import Blueprint, request, jsonify, Response

from ..app import app
from ..core import (task_manager, async_db_query, _check_rate_limit, _is_user_banned)
from .. import oauth
from ..apikey import APIKey
from .. import user_groups
from ..cloudflare import get_client_ip

claude_bp = Blueprint('claude_compat', __name__)


def _approx_tokens(text: str) -> int:
    return max(1, len(text or '') // 3)


def _anthropic_to_openai_messages(body: dict) -> list:
    """Anthropic messages (+system) → OpenAI messages。"""
    msgs = []
    sys = body.get('system')
    if sys:
        if isinstance(sys, list):
            sys_text = '\n'.join(
                b.get('text', '') for b in sys
                if isinstance(b, dict) and b.get('type') == 'text')
        else:
            sys_text = str(sys)
        if sys_text.strip():
            msgs.append({'role': 'system', 'content': sys_text})
    for m in body.get('messages') or []:
        role = m.get('role')
        content = m.get('content')
        parts = []
        if isinstance(content, str):
            parts = [{'type': 'text', 'text': content}]
        else:
            for b in content or []:
                btype = b.get('type') if isinstance(b, dict) else None
                if btype == 'text':
                    parts.append({'type': 'text', 'text': b.get('text', '')})
                elif btype == 'image':
                    src = b.get('source') or {}
                    if src.get('type') == 'base64':
                        parts.append({'type': 'image_url', 'image_url': {
                            'url': f"data:{src.get('media_type', 'image/png')};base64,{src.get('data', '')}"
                        }})
                    elif src.get('type') == 'url':
                        parts.append({'type': 'image_url', 'image_url': {'url': src.get('url', '')}})
                elif btype in ('tool_use', 'tool_result', 'thinking'):
                    raise ValueError(
                        f"/v1/messages: content block type '{btype}' is not supported yet")
        msgs.append({'role': 'user' if role == 'user' else 'assistant',
                     'content': parts or [{'type': 'text', 'text': ''}]})
    return msgs


def _map_stop_reason(finish_reason: str) -> str:
    return {'stop': 'end_turn', 'length': 'max_tokens',
            'tool_calls': 'tool_use', 'content_filter': 'end_turn'}.get(finish_reason, 'end_turn')


def _openai_to_anthropic(result: dict, model: str, input_text_len: int) -> dict:
    ch = (result.get('choices') or [{}])[0]
    text = ((ch.get('message') or {}).get('content')) or ''
    fr = ch.get('finish_reason') or 'stop'
    u = result.get('usage') or {}
    return {
        'id': 'msg_' + secrets.token_hex(12),
        'type': 'message',
        'role': 'assistant',
        'model': model,
        'content': [{'type': 'text', 'text': text}],
        'stop_reason': _map_stop_reason(fr),
        'stop_sequence': None,
        'usage': {
            'input_tokens': int(u.get('prompt_tokens') or _approx_tokens('x' * input_text_len)),
            'output_tokens': int(u.get('completion_tokens') or _approx_tokens(text)),
        },
    }


def _sse(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@claude_bp.route('/v1/messages', methods=['POST'])
async def claude_messages():
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'type': 'error',
                        'error': {'type': 'rate_limit_error', 'message': 'please slow down'}}), 429

    # ---- 鉴权（与 chat completions 一致）----
    auth = request.headers.get('Authorization') or ''
    # Anthropic SDK 默认头 x-api-key 也接受
    if not auth.startswith('Bearer '):
        xkey = request.headers.get('x-api-key')
        if xkey:
            auth = 'Bearer ' + xkey
    if not auth.startswith('Bearer '):
        return jsonify({'type': 'error',
                        'error': {'type': 'authentication_error',
                                  'message': 'Missing Authorization / x-api-key header'}}), 401
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
                return jsonify({'type': 'error',
                                'error': {'type': 'permission_error',
                                          'message': 'api scope required'}}), 403
            api_key_obj = type('OAuthKey', (), {'owner': oauth_info['user_name'], 'oauth': True})()
        else:
            return jsonify({'type': 'error',
                            'error': {'type': 'authentication_error',
                                      'message': 'Invalid API key'}}), 401
    owner = api_key_obj.owner

    users = await async_db_query("SELECT * FROM users WHERE user_name = ?", (owner,))
    if users:
        is_banned, ban_msg = await _is_user_banned(users[0])
        if is_banned:
            return jsonify({'type': 'error',
                            'error': {'type': 'permission_error',
                                      'message': f'Account banned: {ban_msg}'}}), 403

    # ---- 解析与参数翻译 ----
    body = await request.get_json() or {}
    if not body.get('model'):
        return jsonify({'type': 'error',
                        'error': {'type': 'invalid_request_error',
                                  'message': 'model is required'}}), 400
    if body.get('max_tokens') is None:
        return jsonify({'type': 'error',
                        'error': {'type': 'invalid_request_error',
                                  'message': 'max_tokens is required'}}), 400
    model = body['model']

    # 用户组 + 令牌策略
    _allowed, _reason, _mult = user_groups.check_model_access(owner, model)
    if not _allowed:
        return jsonify({'type': 'error',
                        'error': {'type': 'permission_error', 'message': _reason}}), 403
    _key_hash = None
    if not getattr(api_key_obj, 'oauth', False):
        from .chat_proxy import _token_policy_check
        from ..apikey import _hash_apikey
        from .. import tokenpolicy as _tp
        _kh = _hash_apikey(token_str)
        _ok, _pr = _tp.check_policy(_kh, get_client_ip(), model)
        if not _ok:
            _status = 429 if _pr.startswith('token rate limit') else 403
            return jsonify({'type': 'error',
                            'error': {'type': 'permission_error',
                                      'message': f'token policy rejected: {_pr}'}}), _status
        _key_hash = _kh

    try:
        messages = _anthropic_to_openai_messages(body)
    except ValueError as e:
        return jsonify({'type': 'error',
                        'error': {'type': 'invalid_request_error', 'message': str(e)}}), 400

    input_text_len = sum(len(m.get('content') or '') if isinstance(m.get('content'), str)
                         else sum(len(p.get('text', '')) for p in m['content'] if isinstance(p, dict))
                         for m in messages)

    req_data = {'model': model, 'messages': messages,
                'stream': bool(body.get('stream', False)),
                'max_tokens': int(body['max_tokens'])}
    for k_src, k_dst in (('temperature', 'temperature'), ('top_p', 'top_p'),
                         ('stop_sequences', 'stop')):
        if body.get(k_src) is not None:
            req_data[k_dst] = body[k_src]

    # 请求参数治理：max_tokens 上限 / temperature/top_p 范围
    from .. import parampolicy as _pp
    _ok, _why = _pp.validate(body)
    if not _ok:
        return jsonify({'type': 'error',
                        'error': {'type': 'invalid_request_error',
                                  'message': f'invalid parameter: {_why}'}}), 400

    is_stream = req_data['stream']
    queue = await task_manager.get_queue(owner)

    # ---- 非流式 ----
    if not is_stream:
        future = asyncio.Future()
        task_data = {'stream': False, 'future': future, 'apikey_obj': api_key_obj,
                     'req_data': req_data, 'price_multiplier': _mult, 'key_hash': _key_hash}
        await queue.put(task_data)
        try:
            result = await future
        except ValueError as e:
            return jsonify({'type': 'error',
                            'error': {'type': 'invalid_request_error', 'message': str(e)}}), 400
        except Exception:
            logging.exception("claude messages error")
            return jsonify({'type': 'error',
                            'error': {'type': 'api_error',
                                      'message': 'Service temporarily unavailable'}}), 500
        return jsonify(_openai_to_anthropic(result, model, input_text_len)), 200

    # ---- 流式：OpenAI chunk 流 → Anthropic 事件流 ----
    chunk_queue = asyncio.Queue()
    task_data = {'stream': True, 'chunk_queue': chunk_queue, 'apikey_obj': api_key_obj,
                 'req_data': req_data, 'price_multiplier': _mult, 'key_hash': _key_hash}
    await queue.put(task_data)

    msg_id = 'msg_' + secrets.token_hex(12)
    created = int(time.time())

    async def generate():
        keepalive_timeout = 15
        yield _sse('message_start', {
            'type': 'message_start',
            'message': {'id': msg_id, 'type': 'message', 'role': 'assistant',
                        'model': model, 'content': [], 'stop_reason': None,
                        'stop_sequence': None,
                        'usage': {'input_tokens': _approx_tokens('x' * input_text_len),
                                  'output_tokens': 0}}})
        yield _sse('content_block_start', {
            'type': 'content_block_start', 'index': 0,
            'content_block': {'type': 'text', 'text': ''}})
        out_text = ''
        out_tokens = 0
        while True:
            try:
                ctype, cdata = await asyncio.wait_for(chunk_queue.get(), timeout=keepalive_timeout)
            except asyncio.TimeoutError:
                yield ": ping\n\n"
                continue
            if ctype == 'done':
                break
            if ctype == 'error':
                yield _sse('error', {'type': 'error',
                                     'error': {'type': 'api_error', 'message': str(cdata)}})
                return
            chunk = cdata or {}
            delta = ((chunk.get('choices') or [{}])[0] or {}).get('delta') or {}
            d = delta.get('content')
            if d:
                out_text += d
                out_tokens = _approx_tokens(out_text)
                yield _sse('content_block_delta', {
                    'type': 'content_block_delta', 'index': 0,
                    'delta': {'type': 'text_delta', 'text': d}})
        yield _sse('content_block_stop', {'type': 'content_block_stop', 'index': 0})
        yield _sse('message_delta', {
            'type': 'message_delta',
            'delta': {'stop_reason': 'end_turn', 'stop_sequence': None},
            'usage': {'output_tokens': out_tokens}})
        yield _sse('message_stop', {'type': 'message_stop'})

    return Response(generate(), mimetype='text/event-stream')
