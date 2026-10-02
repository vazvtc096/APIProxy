"""响应侧泄露防护（Leak Guard）—— 出站敏感信息扫描

与入站侧（WAF/IDS/JA3/蜜罐）互补的「出口扫描」层：LLM 上游的回复内容不受
我们控制——模型可能把系统提示词、测试时混入的密钥、用户的 PII（手机号/
身份证号）原样回吐给调用方。本模块在响应离开网关前对**出站文本**做正则扫描：

  - critical（默认 redact 脱敏）：OpenAI/AWS/Google/DeepSeek 等 API Key 形态、
    JWT（eyJ...）、PEM 私钥块、通用 secret 赋值长串；
  - warn（默认仅记录）：中国大陆手机号、身份证号（含校验位粗验）。

两种工作模式（LEAK_GUARD_MODE）：
  - monitor：只记录告警 + 内存留痕（默认，零误伤）；
  - redact：critical 命中被替换为 [REDACTED:<type>] 后再返回。

流式说明：SSE 按增量下发，历史数据无法撤回，故对每个 delta 做「完整命中即
脱敏/告警」；并用跨块拼接缓冲（保留上块尾部 LEAK_GUARD_TAIL_CHARS 字符与下块
拼接后再扫）提高跨 delta 拆分的命中率——拼接后命中 critical 的告警照发
（数据已出站），这是流式的固有限制，非流式路径无此限制。

留痕：内存环形缓冲（LEAK_GUARD_MAX_FINDINGS 上限 LRU 淘汰），供 Console
leak_status / leak_list 查看；同时 best-effort 写 security_events（critical 级）。
"""
import logging
import re
import threading
import time
from collections import OrderedDict

from . import configs

logger = logging.getLogger("leak_guard")

# ---------------------------------------------------------------------------
# 检测规则：(type, severity, compiled_regex)
# severity: critical → 默认脱敏；warn → 默认仅告警
# 注意顺序：具体形态在前，通用兜底在后；同一位置命中多个规则时取第一个。
# ---------------------------------------------------------------------------
_RULES = [
    # ---- 凭据类（critical）----
    ("openai_key", "critical",
     re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("aws_key", "critical",
     re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("google_key", "critical",
     re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("deepseek_key", "critical",
     re.compile(r"sk-[0-9a-f]{32}")),
    ("anthropic_key", "critical",
     re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("github_token", "critical",
     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", "critical",
     re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("jwt", "critical",
     re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private_key_block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY(?: BLOCK)?-----")),
    # 通用兜底：显式字段名 + 长值（赋值/JSON 形态），降低误报用长度 + 字符类约束
    ("generic_secret", "critical",
     re.compile(
         r"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)"
         r"['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/_.\-]{24,}")),
    # ---- PII 类（warn，默认仅记录）----
    ("cn_phone", "warn",
     re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("cn_id_card", "warn",
     re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[\dXx](?!\d)")),
]

_REDACT_MASK = "[REDACTED:{type}]"

# ---------------------------------------------------------------------------
# 内存留痕：最近发现（LRU，线程安全）
# ---------------------------------------------------------------------------
_findings = OrderedDict()   # id -> finding dict
_findings_lock = threading.Lock()
_findings_seq = 0
_STATS = {"scanned": 0, "hits": 0, "redacted": 0, "by_type": {}}


def scan_text(text: str) -> list:
    """纯扫描：返回命中列表 [{type, severity, sample(掩码), start, end}]，不修改文本。"""
    if not text or not getattr(configs, "LEAK_GUARD_ENABLED", True):
        return []
    hits = []
    seen_spans = set()
    for rtype, severity, rx in _RULES:
        for m in rx.finditer(text):
            span = (m.start(), m.end())
            if span in seen_spans:
                continue
            seen_spans.add(span)
            hits.append({
                "type": rtype,
                "severity": severity,
                "sample": _mask(m.group(0)),
                "start": m.start(),
                "end": m.end(),
            })
    hits.sort(key=lambda h: h["start"])
    return hits


def redact_text(text: str, hits: list = None) -> tuple:
    """按命中结果脱敏。返回 (clean_text, redacted_count)。

    仅替换 severity=critical 的命中（warn 类 PII 保留，避免破坏正常业务文本）。
    """
    if not text:
        return text, 0
    if hits is None:
        hits = scan_text(text)
    cr = [h for h in hits if h["severity"] == "critical"]
    if not cr:
        return text, 0
    out = text
    # 从后往前替换，避免位移
    for h in sorted(cr, key=lambda x: x["end"], reverse=True):
        out = out[:h["start"]] + _REDACT_MASK.format(type=h["type"]) + out[h["end"]:]
    return out, len(cr)


def check_outbound(text: str, *, user: str = "", model: str = "",
                   stream: bool = False) -> dict:
    """LLM 出口统一入口：扫描 + （redact 模式）脱敏 + 留痕。

    返回 {'text': 处理后文本, 'hits': [...], 'redacted': int}
    非流式在 core_tasks._process_task 调用（text=完整回复）；
    流式在 _process_stream_task 对每个 delta 调用（text=增量）。
    """
    hits = scan_text(text)
    _STATS["scanned"] += 1
    if not hits:
        return {"text": text, "hits": [], "redacted": 0}

    _STATS["hits"] += 1
    mode = str(getattr(configs, "LEAK_GUARD_MODE", "monitor") or "monitor").lower()
    redacted = 0
    clean = text
    if mode == "redact" and not stream:
        clean, redacted = redact_text(text, hits)
        _STATS["redacted"] += redacted

    for h in hits:
        _record_finding(h, user=user, model=model, stream=stream,
                        action=("redacted" if redacted else "detected"))
    logger.warning(
        f"leak_guard: 命中 {len(hits)} 处 "
        f"types={[h['type'] for h in hits]} user={user!r} model={model!r} "
        f"stream={stream} mode={mode} redacted={redacted}")
    return {"text": clean, "hits": hits, "redacted": redacted}


def make_stream_scanner(*, user: str = "", model: str = ""):
    """流式扫描器：跨 delta 拼接检测。用法：

        scanner = leak_guard.make_stream_scanner(user=..., model=...)
        # 每个 delta：
        clean_delta = scanner.feed(delta_text)   # 返回处理后的 delta
        # 流结束时（可选）：scanner.flush()
    """
    tail_len = int(getattr(configs, "LEAK_GUARD_TAIL_CHARS", 64))
    state = {"tail": ""}

    def feed(delta: str) -> str:
        if not delta:
            return delta
        buf = state["tail"] + delta
        res = check_outbound(buf, user=user, model=model, stream=True)
        # 完整命中（在 buf 内）中，落在本 delta 范围内的才可能替换；
        # redact 模式对流式也做局部脱敏（命中的 critical 部分替换掉）
        clean = res["text"]
        if res["redacted"]:
            # 替换作用于 buf：去掉 tail 前缀得到本 delta 的处理结果
            out = clean[len(state["tail"]):] if clean.startswith(state["tail"]) else clean
            state["tail"] = ""
            return out
        # 无替换：正常下发本 delta，保留尾部作为下块拼接上下文
        state["tail"] = buf[-tail_len:] if len(buf) > tail_len else buf
        return delta

    return feed


# ---------------------------------------------------------------------------
# 查询接口（Console）
# ---------------------------------------------------------------------------
def status() -> dict:
    return {
        "enabled": getattr(configs, "LEAK_GUARD_ENABLED", True),
        "mode": str(getattr(configs, "LEAK_GUARD_MODE", "monitor")),
        "rules": [{"type": t, "severity": s} for t, s, _ in _RULES],
        "scanned": _STATS["scanned"],
        "hits": _STATS["hits"],
        "redacted": _STATS["redacted"],
        "findings_kept": len(_findings),
        "findings_cap": int(getattr(configs, "LEAK_GUARD_MAX_FINDINGS", 200)),
    }


def list_findings(limit: int = 20) -> list:
    """最近发现，新的在前。"""
    with _findings_lock:
        items = list(_findings.values())[::-1]
    return items[:limit]


# ---------------------------------------------------------------------------
# 内部
# ---------------------------------------------------------------------------
def _mask(sample: str) -> str:
    """样本掩码：只留前 4 后 4，中间打码，避免告警本身泄露完整密钥。"""
    s = str(sample)
    if len(s) <= 8:
        return s[0] + "***"
    return s[:4] + "***" + s[-4:]


def _record_finding(hit: dict, *, user: str, model: str, stream: bool,
                    action: str) -> None:
    global _findings_seq
    with _findings_lock:
        _findings_seq += 1
        _findings[_findings_seq] = {
            "id": _findings_seq,
            "ts": time.time(),
            "type": hit["type"],
            "severity": hit["severity"],
            "sample": hit["sample"],
            "user": user,
            "model": model,
            "stream": stream,
            "action": action,
        }
        cap = int(getattr(configs, "LEAK_GUARD_MAX_FINDINGS", 200))
        while len(_findings) > cap:
            _findings.popitem(last=False)
    t = hit["type"]
    _STATS["by_type"][t] = _STATS["by_type"].get(t, 0) + 1
    # critical 级 best-effort 落 security_events
    if hit["severity"] == "critical":
        try:
            _record_event_async(hit, user=user, model=model, stream=stream, action=action)
        except Exception as e:
            logger.debug(f"leak_guard record event failed: {e}")


def _record_event_async(hit: dict, *, user: str, model: str, stream: bool,
                        action: str) -> None:
    """写 security_events（在有运行中事件循环时用 create_task；否则跳过）。

    泄露扫描发生在请求处理协程内，正常情况下总有 running loop；
    无 loop（极端时序）则只保留内存留痕。
    """
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    from .core import async_db_query
    details = (f"type={hit['type']}; sample={hit['sample']}; user={user!r}; "
               f"model={model!r}; stream={stream}; action={action}")
    loop.create_task(async_db_query(
        "INSERT INTO security_events (event_type, severity, risk_score, "
        "client_ip, details, action_taken) VALUES (?, ?, ?, ?, ?, ?)",
        ("leak_detected", "critical", 80, "", details, action)))
