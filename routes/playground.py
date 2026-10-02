# -*- coding: utf-8 -*-
"""调用模型（Playground）：面向普通登录用户的对话式模型调试台。

- 页面 /playground（登录即可，非管理员接口）；
- 会话持久化在 playground_conversations / playground_messages（见 playground_chat.py）；
- 聊天端点把「系统提示词 + 持久上下文 + 本条输入」打包为 chat messages，
  提交到 task_manager 全链路队列（映射 / 负载均衡 / 计费 / 参数治理照常生效），
  并把上游流式响应解包为 SSE 转发，结束后回填 assistant 消息与计费明细。
"""
import asyncio
import json
import logging

from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for

from ..core import task_manager, async_db_query, _is_user_banned
from ..core_rate_limit import _check_rate_limit
from .. import playground_chat as pg

playground_bp = Blueprint('playground', __name__)
logger = logging.getLogger(__name__)


def _current_user():
    user = session.get('user')
    return str(user) if user else None


# ============================================================================
# 页面
# ============================================================================
@playground_bp.route('/playground')
async def playground_page():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('playground.html')


# ============================================================================
# 会话 CRUD
# ============================================================================
@playground_bp.route('/api/playground/conversations', methods=['GET'])
async def api_list_conversations():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401
    rows = await asyncio.to_thread(pg.list_conversations, user)
    return jsonify({'conversations': rows})


@playground_bp.route('/api/playground/conversations', methods=['POST'])
async def api_create_conversation():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401
    data = await request.get_json(silent=True) or {}
    conv_id = await asyncio.to_thread(
        pg.create_conversation,
        user,
        title=str(data.get('title') or '新对话'),
        model=str(data.get('model') or ''),
        system_prompt=str(data.get('system_prompt') or ''))
    conv = await asyncio.to_thread(pg.get_conversation, conv_id, user)
    return jsonify({'conversation': conv})


@playground_bp.route('/api/playground/conversations/<int:conv_id>', methods=['POST'])
async def api_update_conversation(conv_id: int):
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401
    data = await request.get_json(silent=True) or {}
    ok = await asyncio.to_thread(
        pg.update_conversation, conv_id, user,
        data.get('title'), data.get('model'), data.get('system_prompt'))
    if not ok:
        return jsonify({'error': 'Conversation not found'}), 404
    conv = await asyncio.to_thread(pg.get_conversation, conv_id, user)
    return jsonify({'conversation': conv})


@playground_bp.route('/api/playground/conversations/<int:conv_id>', methods=['DELETE'])
async def api_delete_conversation(conv_id: int):
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401
    ok = await asyncio.to_thread(pg.delete_conversation, conv_id, user)
    if not ok:
        return jsonify({'error': 'Conversation not found'}), 404
    return jsonify({'ok': True})


@playground_bp.route('/api/playground/conversations/<int:conv_id>/messages', methods=['GET'])
async def api_list_messages(conv_id: int):
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401
    conv = await asyncio.to_thread(pg.get_conversation, conv_id, user)
    if not conv:
        return jsonify({'error': 'Conversation not found'}), 404
    msgs = await asyncio.to_thread(pg.list_messages, conv_id)
    return jsonify({'messages': msgs, 'conversation': conv})


@playground_bp.route('/api/playground/conversations/<int:conv_id>/clear', methods=['POST'])
async def api_clear_conversation(conv_id: int):
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401
    ok = await asyncio.to_thread(pg.clear_messages, conv_id, user)
    if not ok:
        return jsonify({'error': 'Conversation not found'}), 404
    return jsonify({'ok': True})


# ============================================================================
# 聊天（打包上下文 -> 全链路队列 -> 解包流式响应）
# ============================================================================
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


def _extract_full_text(result: dict) -> str:
    try:
        choices = (result or {}).get('choices') or []
        if choices:
            msg = choices[0].get('message') or {}
            return str(msg.get('content') or '')
    except Exception:
        pass
    return ''


async def _last_usage(user: str, retries: int = 10, interval: float = 0.2):
    """取最近一条用量日志。流式路径 done 标记先于计费落库，短暂重试规避竞态。"""
    for i in range(retries):
        log = await async_db_query(
            "SELECT model, input_tokens, output_tokens, cost, upstream FROM usage_logs "
            "WHERE user_name = ? ORDER BY id DESC LIMIT 1", (user,))
        if log:
            return dict(log[0])
        if i < retries - 1:
            await asyncio.sleep(interval)
    return None


@playground_bp.route('/api/playground/chat', methods=['POST'])
async def api_chat():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401

    # 限流（对齐 /v1/chat/completions）
    allowed, _ = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Rate limit exceeded, please slow down'}), 429

    data = await request.get_json(silent=True) or {}
    conv_id = data.get('conversation_id')
    content = str(data.get('content') or '').strip()
    stream = bool(data.get('stream', True))
    if not conv_id:
        return jsonify({'error': 'conversation_id 必填'}), 400
    if not content:
        return jsonify({'error': '消息内容不能为空'}), 400

    # 会话归属校验
    conv = await asyncio.to_thread(pg.get_conversation, int(conv_id), user)
    if not conv:
        return jsonify({'error': 'Conversation not found'}), 404
    conv_id = int(conv['id'])

    model = str(data.get('model') or conv.get('model') or '').strip()
    if not model:
        return jsonify({'error': '请先选择模型'}), 400

    # 落库用户消息 + 组包上下文（系统提示词 + 持久历史，含本条）
    await asyncio.to_thread(pg.add_message, conv_id, 'user', content, model)
    if not (conv.get('title') or '').strip() or conv.get('title') == '新对话':
        await asyncio.to_thread(pg.update_conversation, conv_id, user, content[:40], None, None)
    if model != (conv.get('model') or ''):
        await asyncio.to_thread(pg.update_conversation, conv_id, user, None, model, None)
    messages = await asyncio.to_thread(pg.build_context_messages, conv_id, conv.get('system_prompt') or '')

    # 组包为 OpenAI chat.completions 形状，委托标准 /v1 链路（session 身份复用，billing 记在 user 名下）
    req_data = {'model': model, 'stream': stream, 'messages': messages}
    for k in ('temperature', 'top_p', 'max_tokens'):
        if data.get(k) is not None:
            req_data[k] = data[k]

    sess_key = type('SessKey', (), {'owner': user, 'oauth': True})()
    from .chat_proxy import _dispatch_chat

    if stream:
        # 流式：透传上游 SSE，结束后落库 assistant 消息 + 计费明细（__pg_meta__ 事件）
        async def _on_done(text):
            extra = None
            if text:
                try:
                    await asyncio.to_thread(pg.add_message, conv_id, 'assistant', text, model)
                except Exception as e:
                    logging.error(f"playground save assistant failed: {e}")
            try:
                meta = await _last_usage(user)
                if meta:
                    meta['conversation_id'] = conv_id
                    extra = f"data: {json.dumps({'__pg_meta__': meta}, default=str)}\n\n"
            except Exception:
                pass
            return extra

        dispatch = await _dispatch_chat(user, req_data, sess_key, on_done=_on_done)
        return dispatch['response']

    # 非流式：状态码 + 错误体原样透传（对齐 /v1，不做 playground 私有魔数）
    dispatch = await _dispatch_chat(user, req_data, sess_key)
    if dispatch['status'] != 200:
        return jsonify(dispatch['error']), dispatch['status']

    result = dispatch['result']
    acc = _extract_full_text(result)
    if not acc:
        try:
            acc = str((((result or {}).get('choices') or [{}])[0].get('message') or {}).get('reasoning_content') or '')
        except Exception:
            acc = ''
    if acc:
        await asyncio.to_thread(pg.add_message, conv_id, 'assistant', acc, model)
    meta = await _last_usage(user)
    if meta:
        meta['conversation_id'] = conv_id
    return jsonify({'result': result, 'assistant_text': acc,
                    'conversation_id': conv_id, 'last_usage': meta})
