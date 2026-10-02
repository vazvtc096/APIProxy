"""OpenAI 兼容扩展路由：/v1/completions、/v1/embeddings、/v1/images、/v1/audio。

与 /v1/chat/completions 共用同一套机制：Bearer APIKey / OAuth 鉴权、限流、
封禁检查、用户组模型白名单与价格倍率、模型映射、负载均衡故障转移、
预扣费/退款、用量日志。非 chat 端点暂不支持流式（images/audio 本身无流式）。
"""
import asyncio
import json
import logging

from quart import Blueprint, request, jsonify, Response

from ..app import app
from ..core import (task_manager, async_db_query, _check_rate_limit, _is_user_banned)
from .. import oauth
from ..apikey import APIKey, _hash_apikey
from .. import user_groups, tokenpolicy
from .. import parampolicy
from ..cloudflare import get_client_ip

openai_extra_bp = Blueprint('openai_extra', __name__)


async def _authenticate() -> tuple:
    """Bearer 鉴权：APIKey 优先，OAuth 兜底。返回 (api_key_obj, error_response)。"""
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        return None, (jsonify({'error': 'Missing or invalid Authorization header'}), 401)
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
                return None, (jsonify({'error': 'Insufficient scope: api scope required'}), 403)
            api_key_obj = type('OAuthKey', (), {'owner': oauth_info['user_name'], 'oauth': True})()
        else:
            return None, (jsonify({'error': 'Invalid API key or OAuth access token'}), 401)
    return api_key_obj, None


async def _precheck_owner(owner: str, model: str) -> tuple:
    """封禁检查 + 用户组模型白名单 + 令牌策略。
    返回 (price_multiplier, key_hash, error_response)。"""
    users = await async_db_query("SELECT * FROM users WHERE user_name = ?", (owner,))
    if users:
        is_banned, ban_msg = await _is_user_banned(users[0])
        if is_banned:
            return None, None, (jsonify({'error': f'Account banned: {ban_msg}'}), 403)
    allowed, reason, mult = user_groups.check_model_access(owner, model)
    if not allowed:
        return None, None, (jsonify({'error': reason}), 403)
    # 令牌级策略（仅 APIKey）：额度/过期/IP白名单/模型白名单/停用/RPM/TPM限速
    auth = request.headers.get('Authorization') or ''
    if auth.startswith('Bearer '):
        try:
            kh = _hash_apikey(auth.split(' ', 1)[1])
            ok, tp_reason = tokenpolicy.check_policy(kh, get_client_ip(), model)
            if not ok:
                status = 429 if tp_reason.startswith('token rate limit') else 403
                return None, None, (jsonify({'error': f'token policy rejected: {tp_reason}'}), status)
            return mult, kh, None
        except Exception as e:
            logging.error(f"token policy check failed: {e}")
    return mult, None, None


async def _submit(payload: dict, kind: str, api_key_obj, mult: float, key_hash: str = None):
    """提交任务并等待结果（非流式）。返回 (response_dict, None) 或 (None, (resp, status))。"""
    queue = await task_manager.get_queue(api_key_obj.owner)
    future = asyncio.Future()
    task_data = {
        'kind': kind,
        'stream': False,
        'future': future,
        'apikey_obj': api_key_obj,
        'payload': payload,
        'price_multiplier': mult,
        'key_hash': key_hash,
    }
    await queue.put(task_data)
    try:
        return await future, None
    except ValueError as e:
        return None, (jsonify({'error': str(e)}), 400)
    except Exception as e:
        logging.error(f"{kind} API error for user {api_key_obj.owner}: {e}")
        return None, (jsonify({'error': 'Service temporarily unavailable, please try again later'}), 500)


@openai_extra_bp.route('/v1/completions', methods=['POST'])
async def completions_api():
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429
    api_key_obj, err = await _authenticate()
    if err:
        return err
    req_data = await request.get_json() or {}
    if not req_data.get('model'):
        return jsonify({'error': 'model is required'}), 400
    # 请求参数治理：max_tokens 上限 / temperature/top_p 范围
    ok, why = parampolicy.validate(req_data)
    if not ok:
        return jsonify({'error': f'invalid parameter: {why}'}), 400
    mult, _kh, err = await _precheck_owner(api_key_obj.owner, req_data['model'])
    if err:
        return err
    result, err = await _submit(req_data, 'completions', api_key_obj, mult, _kh)
    return err if err else (jsonify(result), 200)


@openai_extra_bp.route('/v1/embeddings', methods=['POST'])
async def embeddings_api():
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429
    api_key_obj, err = await _authenticate()
    if err:
        return err
    req_data = await request.get_json() or {}
    if not req_data.get('model'):
        return jsonify({'error': 'model is required'}), 400
    mult, _kh, err = await _precheck_owner(api_key_obj.owner, req_data['model'])
    if err:
        return err
    result, err = await _submit(req_data, 'embeddings', api_key_obj, mult, _kh)
    return err if err else (jsonify(result), 200)


@openai_extra_bp.route('/v1/images/generations', methods=['POST'])
async def images_generations_api():
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429
    api_key_obj, err = await _authenticate()
    if err:
        return err
    req_data = await request.get_json() or {}
    if not req_data.get('model'):
        return jsonify({'error': 'model is required'}), 400
    mult, _kh, err = await _precheck_owner(api_key_obj.owner, req_data['model'])
    if err:
        return err
    result, err = await _submit(req_data, 'images', api_key_obj, mult, _kh)
    return err if err else (jsonify(result), 200)


@openai_extra_bp.route('/v1/rerank', methods=['POST'])
async def rerank_api():
    """Cohere/Jina 兼容 rerank：{model, query, documents:[...], top_n}"""
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429
    api_key_obj, err = await _authenticate()
    if err:
        return err
    req_data = await request.get_json() or {}
    if not req_data.get('model'):
        return jsonify({'error': 'model is required'}), 400
    if not req_data.get('documents'):
        return jsonify({'error': 'documents is required'}), 400
    mult, _kh, err = await _precheck_owner(api_key_obj.owner, req_data['model'])
    if err:
        return err
    result, err = await _submit(req_data, 'rerank', api_key_obj, mult, _kh)
    return err if err else (jsonify(result), 200)


async def _audio_transcriptions():
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429
    api_key_obj, err = await _authenticate()
    if err:
        return err
    form = await request.form
    files = await request.files
    upload = files.get('file')
    model = form.get('model')
    if not model:
        return jsonify({'error': 'model is required'}), 400
    if upload is None:
        return jsonify({'error': 'file is required'}), 400
    mult, _kh, err = await _precheck_owner(api_key_obj.owner, model)
    if err:
        return err
    data = upload.read()
    filename = upload.filename or 'audio.wav'
    content_type = upload.content_type or 'application/octet-stream'
    payload = {k: v for k, v in form.items() if k not in ('model', 'file')}
    queue = await task_manager.get_queue(api_key_obj.owner)
    future = asyncio.Future()
    task_data = {
        'kind': 'audio_transcriptions',
        'stream': False,
        'future': future,
        'apikey_obj': api_key_obj,
        'payload': payload,
        'price_multiplier': mult,
        'key_hash': _kh,
        'file': (filename, data, content_type),
        'file_bytes': data,
    }
    await queue.put(task_data)
    try:
        result = await future
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logging.error(f"audio_transcriptions error for user {api_key_obj.owner}: {e}")
        return jsonify({'error': 'Service temporarily unavailable, please try again later'}), 500


@openai_extra_bp.route('/v1/audio/transcriptions', methods=['POST'])
async def audio_transcriptions_api():
    return await _audio_transcriptions()


@openai_extra_bp.route('/v1/audio/speech', methods=['POST'])
async def audio_speech_api():
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429
    api_key_obj, err = await _authenticate()
    if err:
        return err
    req_data = await request.get_json() or {}
    if not req_data.get('model'):
        return jsonify({'error': 'model is required'}), 400
    mult, _kh, err = await _precheck_owner(api_key_obj.owner, req_data['model'])
    if err:
        return err
    result, err = await _submit(req_data, 'audio_speech', api_key_obj, mult, _kh)
    if err:
        return err
    if result.get('_binary'):
        data = result.get('_bytes') or b''
        return Response(data, mimetype=result.get('media_type', 'audio/mpeg'))
    return jsonify(result), 200
