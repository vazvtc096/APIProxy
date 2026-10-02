"""多模态请求预检测与净化（modality pre-check & sanitize）。

三个职责：
1. 预检测（scan_modalities）：统计 messages 里的非文本模态（image_url / input_audio /
   input_file 等）。上游未声明支持视觉时（upstreams.upstream_supports_vision），
   core_tasks 会在预扣费之前直接拒绝请求，避免白白走一遍预扣费→上游报错→退款的循环。
2. 计费净化（billing_text）：序列化 messages 时把 base64 大对象替换为短占位符。
   本项目按字符计价（CHAR_PRICE_LOOKUP 逐码点），一张几百 KB 的 base64 图若不处理，
   输入费用会爆炸几个数量级；占位符只保留文本部分按字符计费。
3. 日志净化：同 billing_text 的产物落 usage_logs，防止 base64 大对象撑爆日志表。
   （图片按张计价待视觉上游接入后再加，见 pricing 预留。）
"""
import base64
import json
import re

# data:<mime>;base64,<payload> —— OpenAI 多模态格式的图片/音频内嵌形式
_DATA_URL_RE = re.compile(
    r'data:([-\w.+]+/[-\w.+]+);base64,([A-Za-z0-9+/=\r\n]+)'
)

# JSON 序列化里出现的纯 base64 长字符串字段（input_audio.data / input_file.file_data
# 等不带 data: 前缀的裸 base64）。≥512 字符的纯 base64 几乎不可能是正常业务文本。
_RAW_B64_RE = re.compile(r'([A-Za-z0-9+/]{512,}={0,2})')


def scan_modalities(messages) -> dict:
    """统计 messages 中的多模态部分。

    返回 {'image': int, 'audio': int, 'file': int, 'text': int}。
    只数结构化 content 列表；纯字符串 content 记 text。
    """
    counts = {'image': 0, 'audio': 0, 'file': 0, 'text': 0}

    def walk(content):
        if isinstance(content, str):
            counts['text'] += 1
            return
        if not isinstance(content, list):
            if content is not None:
                counts['text'] += 1
            return
        for part in content:
            if not isinstance(part, dict):
                counts['text'] += 1
                continue
            t = part.get('type')
            if t == 'text':
                counts['text'] += 1
            elif t == 'image_url' or 'image_url' in part:
                counts['image'] += 1
            elif t == 'input_audio' or 'input_audio' in part:
                counts['audio'] += 1
            elif t in ('input_file', 'file') or 'file_id' in part:
                counts['file'] += 1
            else:
                counts['text'] += 1

    if isinstance(messages, list):
        for m in messages:
            if isinstance(m, dict):
                walk(m.get('content'))
    return counts


def has_non_text(counts: dict) -> bool:
    """是否存在任何非文本模态"""
    return bool(counts.get('image') or counts.get('audio') or counts.get('file'))


def _sniff_image_dims(raw: bytes):
    """从图片二进制提取 (宽, 高)。支持 PNG / GIF / JPEG；失败返回 None。"""
    try:
        if raw[:8] == b'\x89PNG\r\n\x1a\n' and raw[12:16] == b'IHDR':
            w = int.from_bytes(raw[16:20], 'big')
            h = int.from_bytes(raw[20:24], 'big')
            return w, h
        if raw[:3] == b'GIF' and len(raw) >= 10:
            w = int.from_bytes(raw[6:8], 'little')
            h = int.from_bytes(raw[8:10], 'little')
            return w, h
        if raw[:2] == b'\xff\xd8':  # JPEG：扫 SOF0-SOF3 段
            i = 2
            while i + 9 < len(raw):
                if raw[i] != 0xFF:
                    i += 1
                    continue
                marker = raw[i + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seglen = int.from_bytes(raw[i + 2:i + 4], 'big')
                if 0xC0 <= marker <= 0xC3 or 0xC5 <= marker <= 0xC7 \
                        or 0xC9 <= marker <= 0xCB or 0xCD <= marker <= 0xCF:
                    h = int.from_bytes(raw[i + 5:i + 7], 'big')
                    w = int.from_bytes(raw[i + 7:i + 9], 'big')
                    return w, h
                i += 2 + seglen
    except Exception:
        pass
    return None


def _sub_data_url(m: re.Match) -> str:
    mime = m.group(1)
    try:
        raw = base64.b64decode(m.group(2), validate=False)
    except Exception:
        return '[data:' + mime + ']'
    kb = max(1, len(raw) // 1024)
    if mime.startswith('image/'):
        dims = _sniff_image_dims(raw)
        if dims:
            return f'[image:{dims[0]}x{dims[1]},{kb}KB]'
        return f'[image:{kb}KB]'
    if mime.startswith('audio/'):
        return f'[audio:{kb}KB]'
    return f'[data:{mime},{kb}KB]'


def billing_text(messages) -> str:
    """计费/日志用序列化文本：base64 大对象替换为短占位符，文本保持原样。"""
    try:
        s = json.dumps(messages, ensure_ascii=False)
    except Exception:
        s = str(messages)
    s = _DATA_URL_RE.sub(_sub_data_url, s)
    # 裸 base64 字段（音频/文件等）：整串替换，保留 JSON 结构可读性
    s = _RAW_B64_RE.sub('[binary]', s)
    return s
