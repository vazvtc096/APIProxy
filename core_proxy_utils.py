"""代理/协议辅助纯函数：上游 payload 规范化、chat↔responses 转换、SSE 事件。

从 core.py 拆分而来（阶段 2：God module 拆分），保持
`from APIProxy import core; core._chat_to_responses` 等调用兼容。
"""
import json
import secrets
import time


def _neg_time_key(ts: str) -> str:
    """把时间串转成可用于升序排序的「倒序键」（越新越靠前）"""
    if not ts:
        return '~'  # ASCII 中大于数字与字母，排到最后
    # 按字符取补，实现字符串降序
    return ''.join(chr(0x7E - (ord(ch) % 0x5E)) for ch in str(ts))


def _normalize_upstream_payload(data):
    name = (data.get('name') or '').strip()
    if not name:
        return None, 'name is required'
    base_url = (data.get('base_url') or '').strip()
    api_key = (data.get('api_key') or '').strip()
    if not base_url or not api_key:
        return None, 'base_url and api_key are required'
    try:
        priority = int(data.get('priority', 100))
    except (TypeError, ValueError):
        return None, 'priority must be an integer'
    enabled = bool(data.get('enabled', True))
    dm = data.get('disabled_models') or []
    if isinstance(dm, list):
        dm = ','.join([str(x).strip() for x in dm if str(x).strip()])
    elif isinstance(dm, str):
        dm = ','.join([x.strip() for x in dm.split(',') if x.strip()])
    else:
        dm = ''
    # 备用密钥池：列表或逗号/换行分隔字符串 -> 逗号串存储（主 key 不必重复填）
    ak = data.get('api_keys')
    if ak is None:
        ak_str = ''
    elif isinstance(ak, list):
        ak_str = ','.join([str(x).strip() for x in ak if str(x).strip()])
    elif isinstance(ak, str):
        ak_str = ','.join([x.strip() for x in ak.replace('\n', ',').split(',') if x.strip()])
    else:
        return None, 'api_keys must be a list or comma-separated string'
    return {'name': name, 'base_url': base_url, 'api_key': api_key, 'api_keys': ak_str,
            'priority': priority, 'enabled': enabled, 'disabled_models': dm}, None


def _concat_text_parts(parts) -> str:
    """把 content 列表（[{type, text}] 等）拼成纯文本。"""
    if isinstance(parts, str):
        return parts
    out = []
    for p in (parts or []):
        if isinstance(p, dict):
            if 'text' in p:
                out.append(str(p['text']))
            elif 'input' in p:
                out.append(str(p['input']))
        elif isinstance(p, str):
            out.append(p)
    return ''.join(out)


def _responses_input_to_messages(body: dict) -> list:
    """将 Responses 的 input（+instructions）转换为 chat messages 列表。"""
    messages = []
    instructions = body.get('instructions')
    if instructions:
        messages.append({'role': 'system', 'content': str(instructions)})
    inp = body.get('input')
    if isinstance(inp, str):
        messages.append({'role': 'user', 'content': inp})
        return messages
    if isinstance(inp, list):
        for item in inp:
            if not isinstance(item, dict):
                continue
            t = item.get('type')
            if t == 'message':
                role = item.get('role', 'user')
                content = item.get('content')
                messages.append({'role': role, 'content': _concat_text_parts(content)})
            elif t == 'function_call_output':
                messages.append({'role': 'user',
                                 'content': f"[function result] {item.get('output', '')}"})
            # item_reference / 其他类型：简化忽略
        return messages
    return messages


def _chat_to_responses(resp_dict: dict, model: str) -> dict:
    """把 chat.completions 返回字典翻译为 Responses 对象。"""
    choices = resp_dict.get('choices') or []
    msg = (choices[0] or {}).get('message', {}) if choices else {}
    text = msg.get('content') or ''
    usage = resp_dict.get('usage') or {}
    created = resp_dict.get('created', int(time.time()))
    resp_id = 'resp_' + secrets.token_hex(12)
    msg_id = 'msg_' + secrets.token_hex(12)
    return {
        'id': resp_id,
        'object': 'response',
        'created_at': created,
        'status': 'completed',
        'model': resp_dict.get('model', model),
        'output': [{
            'id': msg_id,
            'type': 'message',
            'status': 'completed',
            'role': 'assistant',
            'content': [{'type': 'output_text', 'text': text, 'annotations': []}],
        }],
        'usage': {
            'input_tokens': usage.get('prompt_tokens', 0),
            'output_tokens': usage.get('completion_tokens', 0),
            'total_tokens': usage.get('total_tokens', 0),
        },
        'incomplete_details': None,
    }


def _sse_response_event(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
