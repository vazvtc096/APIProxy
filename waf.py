"""
WAF（Web 应用防火墙）+ 行为监测（纯逻辑，无 DB 依赖；DB 操作由 __main__ 编排）

职责：
- WAF 规则：对每个进入站点的请求做 SQL 注入 / XSS / 路径遍历 / 常见漏洞扫描器 /
  非法 Host / 超大请求 / 已知扫描器 UA 检测。仅在「未使用 Cloudflare」时启用
  （CF 已提供 L7 WAF）。
- 行为监测：进程内聚合每 IP 的请求频率与 WAF 违规计数，供 __main__ 触发
  全局限流与「违规超阈值自动封禁」。全站 IP 黑名单的强制拦截也由 __main__ 在此之上补齐。

设计约束（避免误杀正常 API 流量）：
- 请求体仅在「非自由文本/非流式/非管理」端点检查；聊天/发帖/转账/好友/社区/充值/
  /api/admin//api/debug-console 的请求体免检，以免把用户正常的 prompt/备注当成攻击拦截。
- 规则正则偏向「结构化攻击特征」，降低对正常文本（如搜索词含 select）的误报。
"""
import re
import time
from typing import Tuple, List, Optional
from urllib.parse import unquote

from .configs import (
    WAF_ENABLED as _CFG_WAF_ENABLED,
    WAF_DISABLE_IF_CLOUDFLARE as _CFG_DISABLE_CF,
    WAF_MAX_BODY_BYTES as _CFG_MAX_BODY,
    WAF_ALLOWED_HOSTS as _CFG_HOSTS,
    WAF_GLOBAL_RPM as _CFG_GLOBAL_RPM,
    WAF_VIOLATIONS_RPM as _CFG_VIOL,
    WAF_BAN_MINUTES as _CFG_BAN,
    CLOUDFLARE_TRUSTED as _CFG_CF_TRUSTED,
)

# ---------- 可运行期配置（configure_waf 可覆盖） ----------
WAF_ENABLED = _CFG_WAF_ENABLED
WAF_DISABLE_IF_CLOUDFLARE = _CFG_DISABLE_CF
WAF_MAX_BODY_BYTES = _CFG_MAX_BODY
WAF_ALLOWED_HOSTS: List[str] = list(_CFG_HOSTS)
WAF_GLOBAL_RPM = _CFG_GLOBAL_RPM
WAF_VIOLATIONS_RPM = _CFG_VIOL
WAF_BAN_MINUTES = _CFG_BAN
CLOUDFLARE_TRUSTED = _CFG_CF_TRUSTED

# 请求体免检路径前缀（承载自由文本 / 流式响应 / 管理类，避免误杀）
BODY_EXEMPT_PREFIXES = (
    '/api/chat', '/api/chat/completions', '/v1/chat', '/v1/chat/completions',
    '/v1/responses', '/v1/messages', '/v1/models', '/api/models', '/api/posts',
    '/api/transfer', '/api/friend', '/api/social', '/api/recharge', '/api/admin/',
    '/api/debug-console', '/v1/completions', '/v1/embeddings', '/v1/rerank',
)


def configure_waf(
    enabled: Optional[bool] = None,
    disable_if_cloudflare: Optional[bool] = None,
    max_body_bytes: Optional[int] = None,
    allowed_hosts: Optional[List[str]] = None,
    global_rpm: Optional[int] = None,
    violations_rpm: Optional[int] = None,
    ban_minutes: Optional[int] = None,
):
    """覆盖运行期配置（数值来自 configs，通常无需手动调用）"""
    global WAF_ENABLED, WAF_DISABLE_IF_CLOUDFLARE, WAF_MAX_BODY_BYTES
    global WAF_ALLOWED_HOSTS, WAF_GLOBAL_RPM, WAF_VIOLATIONS_RPM, WAF_BAN_MINUTES
    if enabled is not None:
        WAF_ENABLED = enabled
    if disable_if_cloudflare is not None:
        WAF_DISABLE_IF_CLOUDFLARE = disable_if_cloudflare
    if max_body_bytes is not None:
        WAF_MAX_BODY_BYTES = max_body_bytes
    if allowed_hosts is not None:
        WAF_ALLOWED_HOSTS = list(allowed_hosts)
    if global_rpm is not None:
        WAF_GLOBAL_RPM = global_rpm
    if violations_rpm is not None:
        WAF_VIOLATIONS_RPM = violations_rpm
    if ban_minutes is not None:
        WAF_BAN_MINUTES = ban_minutes


# ============================================================
# 规则正则（保守，优先结构化攻击特征）
# ============================================================
_SQLI = re.compile(
    r"(?:/\*.*?\*/)"
    r"|\s--\s|\s#\s"
    r"|\b(?:union|select|insert|update|delete|drop|truncate|alter|exec|execute|sleep|benchmark)\b[\s\S]{0,40}?\b(?:from|into|table|database|where|values|set|schema)\b"
    r"|\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"
    r"|;\s*(?:drop|delete|update|insert|truncate|alter)\b"
    r"|\bxp_cmdshell\b|\binformation_schema\b"
    r"|\bcast\s*\([\s\S]{0,30}?as\s+(?:char|int|binary|nchar)\b"
    r"|\bload_file\s*\(|\binto\s+outfile\b"
    r"|\bpg_sleep\b|\bwaitfor\s+delay\b",
    re.I)

_XSS = re.compile(
    r"(?:<script\b)|(?:</script\b)|(?:<iframe\b)|(?:<svg\b[^>]*\bon)"
    r"|\bjavascript\s*:|\bon(?:error|load|mouseover|focus|click)\s*="
    r"|(?:<img\b[^>]*\bsrc\s*=\s*['\"]?\s*javascript)|\bdocument\.cookie\b"
    r"|\beval\s*\([\s\S]{0,20}?\)",
    re.I)

_TRAVERSAL = re.compile(
    r"(?:\.\./)|(?:\.\.\\)|(?:\.\.%2f)|(?:\.\.%5c)"
    r"|(?:%2e%2e)|(?:%252e%252e)|(?:/\.\./)|(?:\.\.%2f)"
    r"|(?:/etc/passwd)|(?:\\windows\\system32)|(?:%00)",
    re.I)

_SCANNER = re.compile(
    r"(?:/\.env\b)|(?:/\.git/)|(?:/\.aws/)|(?:/\.ssh/)|(?:\.env\.txt)"
    r"|(?:/wp-admin/)|(?:/wp-login)|(?:/phpmyadmin/)|(?:/adminer)|(?:/web\.config)"
    r"|(?:/actuator)|(?:/api/swagger)|(?:/v2/api-docs)|(?:/swagger-ui)"
    r"|(?:/boaform/)|(?:/manager/html)|(?:/cgi-bin/)|(?:/config\.php)"
    r"|(?:\.well-known/acme-challenge[^\s]*\.\.)",
    re.I)

_BAD_UA = re.compile(
    r"(?:\bnmap\b)|(?:\bmasscan\b)|(?:\bsqlmap\b)|(?:\bnikto\b)|(?:\bwpscan\b)"
    r"|(?:\bacunetix\b)|(?:\bnetsparker\b)|(?:\bowasp\s*zap\b)|(?:\bdirbuster\b)"
    r"|(?:\bgobuster\b)|(?:\bwfuzz\b)|(?:\bhydra\b)|(?:\bnessus\b)|(?:\bwhatweb\b)"
    r"|(?:\bzgrab\b)|(?:\bfimap\b)|(?:\bscan\b.*\bbot\b)",
    re.I)

# 进程内计数（单进程足够；多进程部署建议换共享存储如 Redis）
_ip_req_ts: dict = {}
_ip_viol_ts: dict = {}
_last_cleanup = 0.0
_CLEANUP_INTERVAL = 60


def _maybe_cleanup(now: float) -> None:
    global _last_cleanup
    if now - _last_cleanup <= _CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    cutoff = now - 120
    for store in (_ip_req_ts, _ip_viol_ts):
        for ip in list(store.keys()):
            lst = store[ip]
            while lst and lst[0] < cutoff:
                lst.pop(0)
            if not lst:
                store.pop(ip, None)


def _decode(s: str) -> str:
    """多次 URL 解码以暴露二次编码的攻击载荷"""
    try:
        prev = None
        cur = s
        for _ in range(3):
            if cur == prev:
                break
            prev = cur
            cur = unquote(cur)
        return cur
    except Exception:
        return s


def _collect_request_strings(request) -> List[str]:
    """收集需检查的目标：path(解码)、query 参数、关键 header"""
    targets: List[str] = []
    targets.append(_decode(request.path or ''))
    try:
        for key in request.args.keys():
            targets.append(_decode(key))
            for val in request.args.getlist(key):
                targets.append(_decode(val))
    except Exception:
        pass
    for h in ('User-Agent', 'Referer', 'Cookie', 'X-Forwarded-For', 'X-Requested-With'):
        val = request.headers.get(h)
        if val:
            targets.append(_decode(val))
    return targets


async def _body_strings(request) -> Optional[List[str]]:
    """按需读取请求体（仅非免检端点、非大体积）。返回待检查文本列表，或 None。"""
    method = (request.method or 'GET').upper()
    if method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    path = request.path or ''
    if any(path.startswith(p) for p in BODY_EXEMPT_PREFIXES):
        return None
    ct = (request.headers.get('Content-Type') or '').lower()
    if not any(t in ct for t in ('application/json', 'x-www-form-urlencoded', 'multipart/form-data')):
        return None
    try:
        raw = await request.get_data(cache=True)
    except Exception:
        return None
    if not raw:
        return None
    if len(raw) > WAF_MAX_BODY_BYTES:
        return ['__OVERSIZED__']
    return [_decode(raw.decode('utf-8', 'ignore'))]


def is_behind_cloudflare(request) -> bool:
    """判定请求是否来自 Cloudflare / cloudflared 隧道（CF 已加 CF-Connecting-IP 头）"""
    if CLOUDFLARE_TRUSTED == 'false':
        return False
    return bool(request.headers.get('CF-Connecting-IP'))


async def waf_inspect_request(request, client_ip: str) -> Tuple[bool, str, int, str]:
    """
    对单个请求做 WAF 规则检查。

    返回: (blocked, reason, status, rule_name)
        blocked=False 时 reason/rule_name 为空串，status=200。
    """
    # 1. Host 头校验（防 Host 注入 / 缓存投毒）
    if WAF_ALLOWED_HOSTS:
        host = (request.headers.get('Host') or '').split(':')[0].lower()
        if host and host not in WAF_ALLOWED_HOSTS:
            return True, f'Invalid Host header: {host}', 403, 'bad_host'

    # 2. path / query / header / body 检查
    targets = _collect_request_strings(request)
    body = await _body_strings(request)
    if body is not None:
        targets.extend(body)

    for s in targets:
        if s == '__OVERSIZED__':
            return True, 'Request body too large', 413, 'oversized'
        if _SQLI.search(s):
            return True, 'SQL injection detected', 403, 'sqli'
        if _XSS.search(s):
            return True, 'XSS / script injection detected', 403, 'xss'
        if _TRAVERSAL.search(s):
            return True, 'Path traversal detected', 403, 'traversal'
        if _SCANNER.search(s):
            return True, 'Malicious scanner path detected', 403, 'scanner'

    # 3. 已知扫描器 UA
    ua = request.headers.get('User-Agent', '')
    if ua and _BAD_UA.search(ua):
        return True, 'Known scanner / malicious user-agent detected', 403, 'bad_ua'

    return False, '', 200, ''


def behavior_record_request(client_ip: str) -> Tuple[bool, str, int]:
    """全局每 IP 请求频率检查。返回 (blocked, reason, status)"""
    now = time.time()
    _maybe_cleanup(now)
    lst = _ip_req_ts.setdefault(client_ip, [])
    lst.append(now)
    cutoff = now - 60
    while lst and lst[0] < cutoff:
        lst.pop(0)
    if len(lst) > WAF_GLOBAL_RPM:
        return True, f'Global rate limit exceeded ({len(lst)} req/min)', 429,
    return False, '', 200


def behavior_record_violation(client_ip: str) -> Tuple[bool, str, int, int]:
    """记录一次 WAF 违规，返回 (should_ban, reason, status, count)"""
    now = time.time()
    _maybe_cleanup(now)
    lst = _ip_viol_ts.setdefault(client_ip, [])
    lst.append(now)
    cutoff = now - 60
    while lst and lst[0] < cutoff:
        lst.pop(0)
    cnt = len(lst)
    if cnt >= WAF_VIOLATIONS_RPM:
        return True, f'Auto-banned: {cnt} WAF violations in 1 min', 403, cnt
    return False, '', 200, cnt
