"""IDS / IPS（入侵检测与防御系统）。

与 WAF（core/waf.py）的关系：
  - WAF 负责「Web 应用层」的结构化攻击（SQLi / XSS / 路径遍历 / 扫描器路径 /
    恶意 UA / Host 头 / 请求体大小 / 全局 RPM）。
  - IDS/IPS 负责「入侵行为」层面、WAF 不覆盖的检测：
      * 签名型：已知漏洞利用载荷（Log4j/JNDI、RCE 命令注入、SSTI 模板注入、
        SSRF、NoSQL 注入、XXE、PHP 包装器、WebShell 名称、HTTP 请求走私、
        异常 HTTP 动词、参数洪水）。
      * 行为型：端口/端点枚举扫描（短时间内大量不同 404）、认证暴破
        （登录类端点短时间大量 401/403）。
  - 双模式：
      * detect  （IDS）：仅记录告警到 security_events，不拦截。
      * prevent （IPS）：命中高危/严重签名立即拦截；行为阈值或累计风险分
        超阈时自动封禁 IP（写入 ip_blacklist，与 WAF 自动封禁共用机制）。

设计约束（避免误杀正常 API 流量）：
  - 请求体仅在「非自由文本/非流式/非管理」端点检查（复用 WAF 的免检前缀）。
  - 行为型检测使用滑动窗口计数，阈值偏保守，且优先针对「扫描/暴破」这类
    明显恶意模式，而非单条正常请求。
  - 所有计数走统一缓存层（cache_store），因此 Redis / LB-as-Redis / 本地内存
    三种后端下都能在集群内共享状态（多 Worker 协同检测）。

接口（供 security_middleware 调用）：
  ids_inspect_request(request, client_ip) -> dict | None
  ids_record_response(client_ip, path, status, request) -> dict | None
  ids_rules() -> list[dict]
"""
import json
import logging
import re
import time
from typing import List, Optional
from urllib.parse import unquote

from . import configs
from . import cache_store

logger = logging.getLogger(__name__)

# severity 等级（数值用于排序/告警）
_SEVERITY_RANK = {"low": 10, "medium": 30, "high": 60, "critical": 100}


# ============================================================================
# 配置读取（运行期动态读取 configs，确保 CLI 覆盖即时生效）
# ============================================================================
def _enabled() -> bool:
    return bool(getattr(configs, "IDS_IPS_ENABLED", True))


def _mode() -> str:
    m = str(getattr(configs, "IDS_IPS_MODE", "prevent")).strip().lower()
    return m if m in ("detect", "prevent") else "prevent"


def _ban_on_critical() -> bool:
    return bool(getattr(configs, "IDS_IPS_BAN_ON_CRITICAL", True))


def _ban_minutes() -> int:
    return int(getattr(configs, "IDS_IPS_BAN_MINUTES", 60))


def _scan_paths_threshold() -> int:
    return int(getattr(configs, "IDS_IPS_SCAN_PATHS", 15))


def _scan_window() -> int:
    return int(getattr(configs, "IDS_IPS_SCAN_WINDOW", 60))


def _authfail_threshold() -> int:
    return int(getattr(configs, "IDS_IPS_AUTHFAIL_THRESHOLD", 20))


def _authfail_window() -> int:
    return int(getattr(configs, "IDS_IPS_AUTHFAIL_WINDOW", 300))


def _block_score() -> int:
    return int(getattr(configs, "IDS_IPS_BLOCK_SCORE", 100))


def _detect_score() -> int:
    return int(getattr(configs, "IDS_IPS_DETECT_SCORE", 40))


def _param_flood() -> int:
    return int(getattr(configs, "IDS_IPS_PARAM_FLOOD", 200))


# ============================================================================
# 请求体免检前缀（承载自由文本 / 流式响应 / 管理类，避免误杀正常 prompt/备注）
# ============================================================================
BODY_EXEMPT_PREFIXES = (
    '/api/chat', '/api/chat/completions', '/v1/chat', '/v1/chat/completions',
    '/v1/responses', '/v1/models', '/api/models', '/api/posts', '/api/transfer',
    '/api/friend', '/api/social', '/api/recharge', '/api/admin/', '/api/debug-console',
    '/api/console',
)

# 认证类端点（用于暴破检测）
AUTH_PATHS = (
    '/login', '/api/user/login', '/api/login', '/cluster/login',
    '/oauth/token', '/oauth/authorize', '/oauth/register',
    '/api/admin/login', '/api/user/register', '/register',
)

_SUSPICIOUS_VERBS = {"TRACE", "TRACK"}


# ============================================================================
# 签名规则（偏保守，命中即视为入侵特征）
# ============================================================================
_LOG4J = re.compile(
    r"\$\{(?:[^{}]*:)?jndi:(?:ldap|rmi|dns|iiop|nds|corba):", re.I)
_RCE = re.compile(
    r";\s*(?:/bin/|cmd\.exe|powershell|pwsh|curl|wget|fetch|bash|sh|nc|netcat|"
    r"telnet|ncat|python\d?|perl|ruby|php)\b"
    r"|`[^`]{0,80}?`"                       # 反引号命令执行
    r"|\$\([^)]{0,80}?\)"                  # $(...) 命令替换
    r"|\|\s*/bin/(?:ba)?sh\b"              # |/bin/sh 管道执行
    r"|\b(?:/bin/|/usr/bin/)(?:ba)?sh\b",
    re.I)
_SSTI = re.compile(
    r"\{\{.*?\}\}"                         # {{...}}  Jinja/Twig/Go
    r"|\$\{[^{}]{0,40}\}"                  # ${...}   FreeMarker/Mako/Angular（含 ${7*7}）
    r"|\$\{\{|\#\{"                        # ${{ / #{
    r"|\b__import__\b|\bos\.system\b|\bsubprocess\b"
    r"|\{\{[^}]*?(?:config|self|request|globals|class)\b",
    re.I)
# ============================================================================
# SSRF 上下文感知检测
#   - 仅当 IP 出现在「URL 字段」（带 http(s):// 协议，且地址为内网/保留/云元数据）
#     时才判定 SSRF；普通文本字段（无协议头）中出现内网 IP 不阻断，仅记录告警。
#   - 请求自身的 Host / Referer / Origin / X-Forwarded-* 等地址头不视为 SSRF
#     目标，以兼容用户用本机地址（如 127.0.0.1）访问/重定向的正常场景。
# ============================================================================
_INTERNAL_IP = re.compile(
    r"(?:127(?:\.\d{1,3}){3}"                       # loopback 127.0.0.0/8
    r"|0\.0\.0\.0"
    r"|10(?:\.\d{1,3}){3}"                           # RFC1918 A 类
    r"|192\.168(?:\.\d{1,3}){2}"                     # RFC1918 C 类
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"    # RFC1918 B 类
    r"|169\.254(?:\.\d{1,3}){2}"                     # 链路本地（含云元数据 169.254.169.254）
    r"|\[?::1\]?)"                                   # IPv6 loopback
    , re.I)
# 敏感 IP（仅用于「普通文本」场景：loopback / 链路本地 / 云元数据；
# 不把 192.168 等常见私网地址纳入文本告警，避免正常讨论刷屏）。
_SENSITIVE_IP = re.compile(
    r"(?:127(?:\.\d{1,3}){3}"
    r"|0\.0\.0\.0"
    r"|169\.254(?:\.\d{1,3}){2}"
    r"|\[?::1\]?)", re.I)
# URL 字段中的 SSRF：内网地址 URL、云元数据主机名、危险伪协议（file:// 等）。
_SSRF_URL = re.compile(
    r"https?://" + _INTERNAL_IP.pattern + r"(?::\d+)?(?:/|\?|#|\b|$)"
    r"|https?://(?:metadata\.google\.internal|metadata\.azure|100\.100\.100\.200)"
      r"(?::\d+)?(?:/|\?|#|\b|$)"
    r"|(?:file|dict|gopher|ftp|tftp)://",
    re.I)
# 普通文本中的敏感 IP（带负向前后查，避免误匹配 http://ip 这种 URL 形式）。
_PLAIN_SENSITIVE_IP = re.compile(
    r"(?<!/)" + _SENSITIVE_IP.pattern + r"(?!/|:\d)", re.I)
# 不视为 SSRF 目标的客户端/服务端自身地址头。
_SSRF_SKIP_HEADERS = {
    "host", "referer", "origin", "x-forwarded-for", "x-real-ip",
    "forwarded", "x-forwarded-host", "x-client-ip", "x-forwarded-proto",
}
_NOSQL = re.compile(
    r"(?:\$gt|\$gte|\$lt|\$lte|\$ne|\$eq|\$regex|\$where|\$exists|\$in|\$nin)\s*[:=]",
    re.I)
_XXE = re.compile(
    r"<!ENTITY\b[^>]*SYSTEM\b|\bSYSTEM\s+[\"'](?:file|http|https|ftp):"
    r"|<\?xml\b.*(?:ENTITY|DOCTYPE)",
    re.I)
_PHP_WRAP = re.compile(
    r"(?:php://|expect://|phar://|zip://|data://|glob://|\{?\{?\$\{?\{?IMPORT)",
    re.I)
_WEBSHELL = re.compile(
    r"/(?:shell|c99|r57|b374k|simatt|spy|antSword|caidao|\.ws?shell)\.php"
    r"|/eval-stdin\.php|/(?:.*?)\.jsp\?.*(?:cmd=|command=)",
    re.I)
# HTTP 请求走私（重复 Content-Length 或 CL + TE 并存，由 inspect_request 特判）

# 风险评分权重
_SIGNATURE_RULES = [
    ("log4j_jndi", _LOG4J, "critical", 100,
     "Log4j / JNDI 注入（CVE-2021-44228 类 RCE 载荷）"),
    ("rce_cmd_injection", _RCE, "high", 70,
     "命令注入 / 远程命令执行特征"),
    ("ssti", _SSTI, "high", 60,
     "服务端模板注入（SSTI）特征"),
    ("ssrf", None, "high", 60,
     "服务端请求伪造（SSRF）：仅当 IP 出现在 URL 字段(http(s)://内网地址)时判定；"
     "普通文本中的 IP 仅告警不阻断"),
    ("xxe", _XXE, "medium", 50,
     "XML 外部实体注入（XXE）特征"),
    ("nosql_injection", _NOSQL, "medium", 40,
     "NoSQL 注入操作符（MongoDB 类）"),
    ("php_wrapper", _PHP_WRAP, "medium", 40,
     "PHP 封装器 / 伪协议利用（php://、expect:// 等）"),
    ("webshell", _WEBSHELL, "high", 70,
     "WebShell 文件 / 命令执行后门路径"),
]


def ids_rules() -> List[dict]:
    """返回当前启用的签名规则清单（供 Console `ids rules`）。"""
    rules = [{
        "name": n, "severity": sev, "score": sc, "description": desc,
        "type": "signature",
    } for (n, _re, sev, sc, desc) in _SIGNATURE_RULES]
    rules += [
        {"name": "http_smuggling", "severity": "high", "score": 70,
         "description": "HTTP 请求走私（重复 Content-Length 或 CL+TE 并存）", "type": "signature"},
        {"name": "suspicious_verb", "severity": "medium", "score": 30,
         "description": "异常 HTTP 动词（TRACE / TRACK）", "type": "signature"},
        {"name": "param_flood", "severity": "medium", "score": 30,
         "description": "参数洪水（疑似 DoS / 参数污染）", "type": "signature"},
        {"name": "endpoint_scan", "severity": "medium", "score": 50,
         "description": f"端点枚举扫描（{_scan_paths_threshold()} 秒内超 "
                        f"{_scan_paths_threshold()} 个不同 404 路径）", "type": "behavior"},
        {"name": "auth_bruteforce", "severity": "high", "score": 70,
         "description": f"认证暴破（{_authfail_window()} 秒内登录类端点超 "
                        f"{_authfail_threshold()} 次 401/403）", "type": "behavior"},
    ]
    return rules


# ============================================================================
# 工具
# ============================================================================
def _decode(s: str) -> str:
    """多次 URL 解码以暴露二次编码的攻击载荷。"""
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


async def _collect_strings(request) -> List[str]:
    """收集待检查字符串：解码后的 path / query / 全部请求头值 / 请求体。"""
    targets: List[str] = []
    try:
        targets.append(_decode(request.path or ''))
        for key in request.args.keys():
            targets.append(_decode(key))
            for val in request.args.getlist(key):
                targets.append(_decode(val))
    except Exception:
        pass
    # 扫描全部请求头值（Log4j 等常隐藏在任意头中）
    try:
        for h in request.headers.keys():
            v = request.headers.get(h)
            if v:
                targets.append(_decode(v))
    except Exception:
        pass
    body = await _body_strings(request)
    if body:
        targets.extend(body)
    return targets


async def _body_strings(request) -> Optional[List[str]]:
    """按需读取请求体（仅非免检端点、受大小限制）。返回待检查文本列表。"""
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
    if len(raw) > 262144:  # 256KB 上限，避免大文件拖慢
        return ['__OVERSIZED__']
    return [_decode(raw.decode('utf-8', 'ignore'))]


def _cache():
    return cache_store.get_cache()


# ============================================================================
# 签名型检测（before_request 调用）
# ============================================================================
async def ids_inspect_request(request, client_ip: str) -> Optional[dict]:
    """对单个请求做 IDS/IPS 签名检测。

    返回 None 表示放行；否则返回事件字典：
      {rule, severity, score, reason, status, action}
        action: 'block'（prevent 模式且高危/严重，应拦截）或 'alert'（仅记录）
    """
    if not _enabled():
        return None
    try:
        # ---- 异常 HTTP 动词 ----
        method = (request.method or 'GET').upper()
        if method in _SUSPICIOUS_VERBS:
            return _mk_event("suspicious_verb", "medium", 30,
                             f"异常 HTTP 动词：{method}", "TRACE/TRACK 已被禁用",
                             request)

        # ---- HTTP 请求走私 ----
        cl_vals = [v for v in (request.headers.getlist('Content-Length')
                               if hasattr(request.headers, 'getlist')
                               else [request.headers.get('Content-Length')]) if v]
        has_te = bool(request.headers.get('Transfer-Encoding'))
        if len(cl_vals) > 1 or (cl_vals and has_te):
            return _mk_event("http_smuggling", "high", 70,
                             "HTTP 请求走私特征：重复 Content-Length 或 CL+TE 并存",
                             "可能的请求走私", request)

        # ---- 参数洪水 ----
        try:
            nparams = sum(1 for _ in request.args.keys())
        except Exception:
            nparams = 0
        if nparams > _param_flood():
            return _mk_event("param_flood", "medium", 30,
                             f"参数数量过多：{nparams}", "疑似参数污染 / DoS", request)

        # ---- 签名正则（ssrf 由 _ssrf_inspect 上下文感知处理，此处跳过）----
        targets = await _collect_strings(request)
        for s in targets:
            if s == '__OVERSIZED__':
                return _mk_event("oversized_body", "low", 10,
                                 "请求体过大", "请求体超过 IDS 检查上限", request)
            for (name, rgx, sev, sc, desc) in _SIGNATURE_RULES:
                if rgx is None:
                    continue
                if rgx.search(s):
                    return _mk_event(name, sev, sc, desc,
                                     f"{desc}（匹配片段已脱敏）", request)

        # ---- SSRF 上下文感知（不扫请求自身地址头，避免误杀正常导航）----
        ssrf = await _ssrf_inspect(request)
        if ssrf:
            return ssrf
    except Exception as e:
        logger.error(f"IDS/IPS signature inspect failed: {e}")
        return None
    return None


async def _ssrf_inspect(request) -> Optional[dict]:
    """上下文感知 SSRF 检测（替代原先对全字段纯 IP 字符串的匹配）。

    判定逻辑：
      1) URL 字段（带 http(s):// 且地址为内网/保留/云元数据，或危险伪协议
         file:/// 等）中出现受限地址 → 高危 SSRF（prevent 模式拦截）。
         扫描来源：解码后的 path（可能内嵌 URL）、查询参数值、请求体。
      2) 普通文本字段中出现敏感内网 IP（无协议头）→ 仅记录告警，不阻断。
         扫描来源：查询参数、非自身地址头、请求体；排除 Host/Referer/Origin/
         X-Forwarded-* 等客户端/服务端自身地址头。
    """
    # 1) 收集「URL 字段」
    url_bearing: List[str] = []
    try:
        url_bearing.append(_decode(request.path or ''))
    except Exception:
        pass
    try:
        for key in request.args.keys():
            for val in request.args.getlist(key):
                url_bearing.append(_decode(val))
    except Exception:
        pass
    body = await _body_strings(request)
    if body:
        url_bearing.extend(body)

    for s in url_bearing:
        if _SSRF_URL.search(s):
            return _mk_event("ssrf", "high", 60,
                             "服务端请求伪造（SSRF）：URL 字段含受限/内网/云元数据地址",
                             "URL 内含受限地址（已脱敏）", request)

    # 2) 普通文本中的敏感 IP → 仅告警、不阻断
    plain: List[str] = []
    try:
        for key in request.args.keys():
            plain.append(_decode(key))
            plain.append(_decode(request.args.get(key, '')))
    except Exception:
        pass
    try:
        for h in request.headers.keys():
            if h.lower() in _SSRF_SKIP_HEADERS:
                continue
            v = request.headers.get(h)
            if v:
                plain.append(_decode(v))
    except Exception:
        pass
    if body:
        plain.extend(body)
    for s in plain:
        if _PLAIN_SENSITIVE_IP.search(s):
            # 仅记录（detect / prevent 模式均为 alert，不阻断）
            return _mk_event("ip_mention_text", "low", 5,
                             "普通文本字段含内部 IP 地址（疑似讨论/误报，仅记录不阻断）",
                             "该 IP 出现在非 URL 文本字段，未触发阻断", request)
    return None


def _mk_event(rule: str, severity: str, score: int, reason: str, detail: str,
              request) -> dict:
    """构造检测结果事件，并根据当前模式决定 action。"""
    mode = _mode()
    action = "block" if (mode == "prevent" and severity in ("high", "critical")) else "alert"
    status = 403
    return {
        "rule": rule, "severity": severity, "score": score,
        "reason": reason, "detail": detail, "action": action, "status": status,
    }


# ============================================================================
# 行为型检测（after_request 调用，基于响应状态）
# ============================================================================
def ids_record_response(client_ip: str, path: str, status: int, request) -> Optional[dict]:
    """基于响应状态做行为型检测，更新滑动窗口计数。

    返回 None 表示无事件；否则返回：
      {event: {rule, severity, score, reason, detail}, ban: bool, ban_reason: str}
    """
    if not _enabled():
        return None
    try:
        # ---- 端点枚举扫描：大量不同 404 ----
        if status == 404 and not path.startswith('/static/'):
            key = f"ids:scan:{client_ip}"
            raw = _cache().get(key)
            paths = json.loads(raw) if raw else []
            norm = (path or '').split('?')[0][:200]
            if norm not in paths:
                paths.append(norm)
            cap = _scan_paths_threshold() * 4
            if len(paths) > cap:
                paths = paths[-cap:]
            _cache().setex(key, _scan_window(), json.dumps(paths))
            if len(paths) >= _scan_paths_threshold():
                return _mk_behavior("endpoint_scan", "medium", 50,
                                    f"端点枚举扫描：{len(paths)} 个不同 404 路径", client_ip)

        # ---- 认证暴破：登录类端点大量 401/403 ----
        if status in (401, 403) and _is_auth_path(path):
            key = f"ids:authfail:{client_ip}"
            n = _cache().incr(key)
            _cache().expire(key, _authfail_window())
            if n >= _authfail_threshold():
                return _mk_behavior("auth_bruteforce", "high", 70,
                                    f"认证暴破：登录类端点 {n} 次 401/403", client_ip)
    except Exception as e:
        logger.error(f"IDS/IPS behavior record failed: {e}")
        return None
    return None


def _is_auth_path(path: str) -> bool:
    p = path or ''
    return any(p == a or p.startswith(a) for a in AUTH_PATHS)


def _mk_behavior(rule: str, severity: str, score: int, reason: str, client_ip: str) -> dict:
    """构造行为事件，并按模式决定是否自动封禁（累计风险分超阈）。"""
    mode = _mode()
    # 累计风险分（滑动窗口）
    skey = f"ids:score:{client_ip}"
    try:
        cur = int(_cache().get(skey) or 0)
    except Exception:
        cur = 0
    cur += score
    _cache().setex(skey, 600, cur)

    ban = False
    ban_reason = ""
    if mode == "prevent":
        if cur >= _block_score():
            ban = True
            ban_reason = f"IDS 累计风险分 {cur} 超阈值 {_block_score()}（{rule}）"
        elif severity == "high":
            # 高危行为（暴破）直接封禁，不等累计
            ban = True
            ban_reason = f"IDS 行为检测：{reason}"
    elif cur >= _detect_score():
        # detect 模式：仅记录，但累计达 detect 阈值时也可升级为告警（不封禁）
        pass
    return {
        "event": {"rule": rule, "severity": severity, "score": score,
                  "reason": reason, "detail": f"累计风险分 {cur}"},
        "ban": ban, "ban_reason": ban_reason,
    }


# ============================================================================
# 状态查询（供 Console `ids status`）
# ============================================================================
def ids_status() -> dict:
    return {
        "enabled": _enabled(),
        "mode": _mode(),
        "ban_on_critical": _ban_on_critical(),
        "ban_minutes": _ban_minutes(),
        "scan_paths_threshold": _scan_paths_threshold(),
        "scan_window": _scan_window(),
        "authfail_threshold": _authfail_threshold(),
        "authfail_window": _authfail_window(),
        "block_score": _block_score(),
        "detect_score": _detect_score(),
        "param_flood": _param_flood(),
        "signature_rules": len(_SIGNATURE_RULES) + 3,
        "backend": _cache().ping() and "ok" or "down",
    }
