"""
安全检测模块 — 设备类型识别、风险评分、异常事件引擎

功能:
- 解析 User-Agent 识别设备类型 (PC/Mobile/Tablet/Bot/API)
- 计算登录风险评分 (0~100)
- 检测异常行为并触发自动临时封禁
- 记录安全事件供管理员审查
"""

import re
import logging
import time
from typing import Literal, Optional
from dataclasses import dataclass

# ============================================================
# 设备类型定义
# ============================================================

DeviceType = Literal["pc", "mobile", "tablet", "bot", "api_client", "unknown"]

@dataclass
class DeviceInfo:
    """设备解析结果"""
    device_type: DeviceType
    os_name: str          # Windows, macOS, Linux, Android, iOS, Unknown
    os_version: str       # 版本号
    browser_name: str     # Chrome, Firefox, Safari, Edge, ...
    browser_version: str
    is_automation: bool   # 是否为自动化工具 (curl, python-requests, wget, selenium, puppeteer)
    risk_tags: list[str]  # 风险标签列表
    raw_ua: str           # 原始 UA

    @property
    def display_name(self) -> str:
        """人类可读的设备描述"""
        if self.is_automation:
            return f"[自动化工具] {self.browser_name}"
        parts = []
        if self.os_name != "Unknown":
            parts.append(f"{self.os_name} {self.os_version}")
        if self.browser_name != "Unknown":
            parts.append(f"{self.browser_name} {self.browser_version}")
        if not parts:
            return "未知设备"
        return f"{self.device_type.upper()} - {', '.join(parts)}"


# ============================================================
# UA 解析引擎
# ============================================================

# 自动化工具 UA 特征
AUTOMATION_PATTERNS = [
    (r'curl/',                   'curl'),
    (r'python-requests/',        'python-requests'),
    (r'python urllib',           'python-urllib'),
    (r'wget/',                   'wget'),
    (r'Java/',                   'Java-HTTP'),
    (r'\.NET/',                  'dotnet-HTTP'),
    (r'Go-http-client',          'Go-HTTP'),
    (r'node-fetch',              'node-fetch'),
    (r'axios/',                  'axios'),
    (r'httpie/',                 'httpie'),
    (r'PostmanRuntime/',         'Postman'),
    (r'selenium',                'Selenium'),
    (r'puppeteer',               'Puppeteer'),
    (r'HeadlessChrome',          'Headless-Chrome'),
    (r'phantomjs',               'PhantomJS'),
    (r'playwright',              'Playwright'),
    (r'bot',                     'Bot-Agent'),
    (r'scraper',                 'Scraper'),
    (r'spider',                  'Spider-Agent'),
]

# OS 解析规则 (优先级从高到低)
OS_RULES = [
    (r'Windows NT (\d+\.\d+)',           'Windows',    lambda v: {'10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7', '6.0': 'Vista', '5.1': 'XP'}.get(v, v)),
    (r'Mac OS X (\d+[.\d]*)',            'macOS',      lambda v: v.replace('_', '.')),
    (r'Android (\d+[.\d]*)',             'Android',    lambda v: v),
    (r'iPhone OS (\d+[.\d]*)',           'iOS',        lambda v: v),
    (r'iPad.*OS (\d+[.\d]*)',            'iOS',        lambda v: v),
    (r'Linux',                            'Linux',      lambda v: v),
    (r'CrOS',                             'ChromeOS',   lambda v: v),
]

# 浏览器解析规则 (优先级从高到低，Edge/Brave 等基于 Chromium 的需优先匹配)
BROWSER_RULES = [
    (r'Edge/(\d+[.\d]*)',                'Edge'),
    (r'Edg/(\d+[.\d]*)',                 'Edge'),
    (r'Brave/(\d+[.\d]*)',               'Brave'),
    (r'OPR/(\d+[.\d]*)',                 'Opera'),
    (r'Opera.*Version/(\d+[.\d]*)',      'Opera'),
    (r'Vivaldi/(\d+[.\d]*)',             'Vivaldi'),
    (r'Firefox/(\d+[.\d]*)',             'Firefox'),
    (r'Safari/(\d+[.\d]*)',              'Safari'),    # 注意：Chrome 也含 Safari，需后处理
    (r'Chrome/(\d+[.\d]*)',              'Chrome'),    # Chrome 必须在 Safari 之后
]


def parse_user_agent(ua: str) -> DeviceInfo:
    """解析 User-Agent 字符串，返回设备信息"""
    if not ua or ua == 'unknown':
        return DeviceInfo(
            device_type="unknown", os_name="Unknown", os_version="",
            browser_name="Unknown", browser_version="",
            is_automation=False, risk_tags=["empty-ua"], raw_ua=ua or ""
        )

    risk_tags: list[str] = []
    is_automation = False

    # 1. 检查自动化工具
    for pattern, tool_name in AUTOMATION_PATTERNS:
        if re.search(pattern, ua, re.IGNORECASE):
            is_automation = True
            risk_tags.append(f"automation:{tool_name}")
            break

    # 2. 解析 OS
    os_name = "Unknown"
    os_version = ""
    for pattern, name, version_fn in OS_RULES:
        match = re.search(pattern, ua)
        if match:
            os_name = name
            raw_ver = match.group(1) if match.lastindex else ""
            os_version = version_fn(raw_ver) if raw_ver and version_fn else raw_ver
            break

    # 3. 解析浏览器
    browser_name = "Unknown"
    browser_version = ""
    for pattern, name in BROWSER_RULES:
        match = re.search(pattern, ua)
        if match:
            browser_name = name
            browser_version = match.group(1) if match.lastindex else ""
            break

    # 特殊处理：如果 UA 含 Chrome 但不含 Safari/Edge/OPR 等，是真正 Chrome
    # 如果含 Safari 但不含 Chrome，是真正 Safari（macOS/iOS）
    if browser_name == "Safari" and "Chrome" in ua:
        # 这个 Safari 是 Chrome 内部的兼容标识，回退到 Chrome
        chrome_match = re.search(r'Chrome/(\d+[.\d]*)', ua)
        if chrome_match:
            browser_name = "Chrome"
            browser_version = chrome_match.group(1)

    # 4. 判断设备类型
    if is_automation:
        device_type: DeviceType = "bot"
    elif any(kw in ua for kw in ['Mobile', 'iPhone', 'Android (Mobile', 'Opera Mini']):
        device_type = "mobile"
    elif any(kw in ua for kw in ['iPad', 'Tablet', 'Android (Tablet']):
        device_type = "tablet"
    elif any(kw in ua for kw in ['Windows', 'Macintosh', 'Linux', 'X11', 'CrOS']):
        device_type = "pc"
    else:
        device_type = "unknown"
        risk_tags.append("unrecognized-device")

    # 5. 额外风险标记
    if "HeadlessChrome" in ua:
        risk_tags.append("headless-browser")
    if device_type == "bot":
        risk_tags.append("non-browser-access")

    return DeviceInfo(
        device_type=device_type,
        os_name=os_name,
        os_version=os_version,
        browser_name=browser_name,
        browser_version=browser_version,
        is_automation=is_automation,
        risk_tags=risk_tags,
        raw_ua=ua
    )


# ============================================================
# 风险评分引擎
# ============================================================

# 封禁策略配置
SECURITY_CONFIG = {
    # 单项风险评分阈值
    "risk_threshold_warn":     30,     # ≥30: 警告（仅邮件通知）
    "risk_threshold_restrict": 60,     # ≥60: 限制（临时封禁 1 小时）
    "risk_threshold_ban":      80,     # ≥80: 严重（临时封禁 24 小时）

    # 临时封禁时长（秒）
    "restrict_duration":       3600,   # 限制级封禁: 1 小时
    "ban_duration":            86400,  # 严重级封禁: 24 小时

    # 连续失败登录自动封禁
    "max_failed_per_ip":       10,     # 同一 IP 10 次失败 → 封禁该 IP 来源 1 小时
    "max_failed_per_user":     5,      # 同一用户 5 次失败 → 临时封禁账号 1 小时

    # 多 IP 并发检测
    "max_ips_per_hour":        5,      # 1 小时内 ≥5 个不同 IP → 高风险
    "max_ips_per_day":         10,     # 1 天内 ≥10 个不同 IP → 自动封禁

    # 设备突变检测
    "device_change_score":     40,     # 设备类型突变（PC→Mobile 等）基础评分
}


def calculate_login_risk(
    device: DeviceInfo,
    client_ip: str,
    user_data: dict,
    recent_login_logs: list[dict],
) -> tuple[int, list[str], str]:
    """
    计算登录风险评分

    参数:
        device:       当前设备信息
        client_ip:    当前 IP
        user_data:    用户数据 (包含 last_login_ip, last_device_type 等)
        recent_login_logs: 最近 24 小时的登录日志

    返回:
        (risk_score, risk_details, severity)
        severity: "safe" | "warn" | "restrict" | "ban"
    """
    score = 0
    details: list[str] = []
    cfg = SECURITY_CONFIG

    # ----- 1. 自动化工具检测 (高风险) -----
    if device.is_automation:
        score += 50
        details.append(f"自动化工具访问: {device.browser_name}")
        # curl/python-requests 等直接登录接口是非常可疑的
        if device.browser_name in ("curl", "python-requests", "python-urllib",
                                    "Go-HTTP", "Java-HTTP", "dotnet-HTTP", "wget"):
            score += 20
            details.append(f"非浏览器客户端: {device.browser_name}")

    # ----- 2. 空或异常 UA -----
    if device.device_type == "unknown" and not device.is_automation:
        score += 15
        details.append("无法识别的设备类型")

    # ----- 3. IP 变化检测 -----
    last_ip = user_data.get("last_login_ip", "")
    if last_ip and last_ip != client_ip:
        score += 10
        details.append(f"IP 变化: {last_ip} → {client_ip}")

    # ----- 4. 设备类型突变检测 -----
    last_device_type = user_data.get("last_device_type", "")
    current_device_type = device.device_type
    if last_device_type and last_device_type != current_device_type:
        # 同一用户从 PC 突变到 Mobile/Bot，比从 PC 到 PC 更可疑
        score += cfg["device_change_score"]
        details.append(f"设备类型突变: {last_device_type} → {current_device_type}")

    # ----- 5. 多 IP 并发检测 -----
    # 只统计「成功登录」来自的不同 IP。失败尝试（输错密码）不应算入，
    # 否则用户反复输错密码时，不同出口 IP 会累积成"多 IP"误封正确密码。
    recent_ips = set()
    for log in recent_login_logs:
        if log.get("status") != "success":
            continue
        log_ip = log.get("login_ip", "")
        if log_ip and log_ip != client_ip:
            recent_ips.add(log_ip)
    # 这里用简单计数（后续可优化为时间窗口精确过滤）
    distinct_ip_count = len(recent_ips) + 1  # +1 包含当前 IP
    if distinct_ip_count >= cfg["max_ips_per_hour"]:
        score += 30
        details.append(f"短时间多 IP 登录: {distinct_ip_count} 个不同 IP")

    # ----- 6. 连续失败登录检测 (从 recent_login_logs) -----
    recent_failures_for_user = sum(
        1 for log in recent_login_logs
        if log.get("status") == "failed" and log.get("user_name") == user_data.get("user_name")
    )
    if recent_failures_for_user >= cfg["max_failed_per_user"]:
        score += 30
        details.append(f"连续失败登录: {recent_failures_for_user} 次")

    # ----- 7. OS 突变检测 -----
    last_os = user_data.get("last_device_os", "")
    current_os = device.os_name
    if last_os and last_os != current_os and last_os != "Unknown" and current_os != "Unknown":
        score += 15
        details.append(f"操作系统突变: {last_os} → {current_os}")

    # ----- 8. 风险标签叠加 -----
    for tag in device.risk_tags:
        if tag == "headless-browser":
            score += 25
            details.append("无头浏览器 (自动化爬虫)")
        if tag == "non-browser-access":
            score += 10  # 已在自动化检测中计入，这里追加少量

    # 评分上限 100
    score = min(score, 100)

    # ----- 判定严重级别 -----
    if score >= cfg["risk_threshold_ban"]:
        severity = "ban"
    elif score >= cfg["risk_threshold_restrict"]:
        severity = "restrict"
    elif score >= cfg["risk_threshold_warn"]:
        severity = "warn"
    else:
        severity = "safe"

    return score, details, severity


# ============================================================
# 安全事件记录与自动封禁
# ============================================================

async def record_security_event(
    db_query_func,
    user_uid: str,
    user_name: str,
    event_type: str,
    severity: str,
    risk_score: int,
    details: list[str],
    client_ip: str,
    device_info: DeviceInfo,
    action_taken: str = "",
) -> None:
    """记录安全事件到数据库"""
    try:
        details_json = json.dumps(details) if details else "[]"
        device_json = json.dumps({
            "device_type": device_info.device_type,
            "os": f"{device_info.os_name} {device_info.os_version}",
            "browser": f"{device_info.browser_name} {device_info.browser_version}",
            "is_automation": device_info.is_automation,
            "risk_tags": device_info.risk_tags,
            "raw_ua": device_info.raw_ua[:200],
        })
        await db_query_func(
            """INSERT INTO security_events
               (user_uid, user_name, event_type, severity, risk_score,
                details, client_ip, device_info, action_taken)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_uid, user_name, event_type, severity, risk_score,
             details_json, client_ip, device_json, action_taken)
        )
    except Exception as e:
        logging.error(f"Record security event failed: {e}")


async def auto_temp_ban(
    db_query_func,
    user_name: str,
    severity: str,
    reason: str,
) -> tuple[int, str]:
    """
    执行自动临时封禁

    返回: (封禁时长秒, 封禁原因文本)
    """
    cfg = SECURITY_CONFIG
    import datetime

    if severity == "restrict":
        duration = cfg["restrict_duration"]
        ban_label = "1 小时"
    elif severity == "ban":
        duration = cfg["ban_duration"]
        ban_label = "24 小时"
    else:
        return 0, ""

    expire_at = datetime.datetime.now() + datetime.timedelta(seconds=duration)
    expire_str = expire_at.isoformat(timespec='seconds')

    ban_reason = f"[自动封禁] {reason} (临时封禁 {ban_label}, 到 {expire_str} 自动解封)"

    try:
        await db_query_func(
            """UPDATE users
               SET is_banned = 1,
                   ban_reason = ?,
                   ban_expire_at = ?
               WHERE user_name = ?""",
            (ban_reason, expire_str, user_name)
        )
        logging.warning(f"Auto temp-ban: {user_name}, reason: {reason}, duration: {ban_label}")
        return duration, ban_reason
    except Exception as e:
        logging.error(f"Auto temp-ban failed for {user_name}: {e}")
        return 0, ""


# ============================================================
# 可配置封禁规则引擎（三规则）
#   failed_login_ip       多次输错密码 → 封 IP
#   success_login_account 多次连续登录成功 → 封账号
#   bulk_request_device   大批量请求 → 封设备（浏览器指纹）
# 每条规则的「触发次数」「封禁时长表达式」均可单独自定义。
# 时长表达式支持变量 n（=触发次数），结果为分钟；特殊值 never / always。
# 约束：封账号最低 10min；其他最低 never（可关闭）、最高 always（永久）。
# ============================================================

import ast as _ast
import copy as _copy
import datetime as _dt
import hashlib as _hashlib
import time as _time

DEFAULT_BAN_RULES = {
    "failed_login_ip": {
        "label": "多次输错密码 → 封 IP",
        "enabled": True,
        "trigger_count": 5,
        "window_sec": 3600,
        "duration_expr": "n * 10",
        "min": "never",
        "max": "always",
    },
    "success_login_account": {
        "label": "多次连续登录成功 → 封账号",
        "enabled": True,
        "trigger_count": 10,
        "window_sec": 86400,
        "duration_expr": "n * 15",
        "min": 10,
        "max": 1440,
    },
    "bulk_request_device": {
        "label": "大批量请求 → 封设备（浏览器指纹）",
        "enabled": True,
        "trigger_count": 1000,
        "window_sec": 60,
        "duration_expr": "n * 2",
        "min": "never",
        "max": "always",
    },
}

_BAN_RULES_CACHE = None


def get_ban_rules() -> dict:
    """返回当前生效的封禁规则（合并默认，保证新增字段存在）"""
    global _BAN_RULES_CACHE
    base = _copy.deepcopy(DEFAULT_BAN_RULES)
    if _BAN_RULES_CACHE:
        for k, v in _BAN_RULES_CACHE.items():
            if k in base and isinstance(v, dict):
                base[k].update(v)
            else:
                base[k] = v
    return base


def set_ban_rules(rules: dict) -> dict:
    """更新并持久化封禁规则（由 __main__ 从 config_kv 加载/保存）"""
    global _BAN_RULES_CACHE
    merged = _copy.deepcopy(DEFAULT_BAN_RULES)
    if isinstance(rules, dict):
        for k, v in rules.items():
            if k in merged and isinstance(v, dict):
                merged[k].update(v)
            else:
                merged[k] = v
    _BAN_RULES_CACHE = merged
    return merged


def eval_duration(expr: str, n: int):
    """解析时长表达式。
    返回 ('never', None) | ('always', None) | ('minutes', float_minutes)
    n = 触发次数。仅允许 + - * / // % **、括号、变量 n、函数 min/max/abs。
    """
    s = (expr or "").strip()
    low = s.lower()
    if low in ("never", "off", "disabled", "false", "none", "0"):
        return ("never", None)
    if low in ("always", "permanent", "true", "inf", "-1"):
        return ("always", None)
    try:
        tree = _ast.parse(s, mode="eval")
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call):
                if not isinstance(node.func, _ast.Name) or node.func.id not in ("min", "max", "abs"):
                    raise ValueError("不支持的函数调用")
            elif not isinstance(node, (
                _ast.Expression, _ast.BinOp, _ast.UnaryOp, _ast.Constant,
                _ast.Name, _ast.Load, _ast.Add, _ast.Sub, _ast.Mult,
                _ast.Div, _ast.FloorDiv, _ast.Mod, _ast.Pow,
                _ast.USub, _ast.UAdd,
            )):
                raise ValueError(f"不支持的表达式元素: {type(node).__name__}")
        env = {"n": float(n), "min": min, "max": max, "abs": abs, "__builtins__": {}}
        val = float(eval(compile(tree, "<duration>", "eval"), env))
        if val != val or val < 0:  # NaN / 负数
            return ("never", None)
        return ("minutes", val)
    except Exception as e:
        logging.error(f"eval_duration 解析失败 expr={expr!r} n={n}: {e}")
        return ("never", None)


def resolve_rule_duration(rule_key: str, n: int):
    """按规则约束收敛时长，返回 ('never'|'always'|'minutes', value)"""
    rules = get_ban_rules()
    rule = rules.get(rule_key)
    if not rule or not rule.get("enabled", True):
        return ("never", None)
    kind, val = eval_duration(rule.get("duration_expr", "never"), n)
    if kind == "never":
        return ("never", None)
    if kind == "always":
        # 封账号不允许永久，收敛到上限
        if rule_key == "success_login_account":
            return ("minutes", float(rule.get("max", 1440)))
        return ("always", None)
    minutes = float(val)
    mn = rule.get("min")
    mx = rule.get("max")
    if rule_key == "success_login_account":
        if isinstance(mn, (int, float)):
            minutes = max(minutes, float(mn))
        if isinstance(mx, (int, float)):
            minutes = min(minutes, float(mx))
    else:
        # ip / device：最低为 never（已是 minutes 时仅收敛上限）
        if isinstance(mx, (int, float)):
            minutes = min(minutes, float(mx))
    return ("minutes", minutes)


def _expire_str(minutes: float) -> str:
    return (_dt.datetime.now() + _dt.timedelta(minutes=float(minutes))).isoformat(timespec="seconds")


async def ban_ip_auto(db, ip: str, kind, val, reason: str):
    # ip_blacklist.ban_expire_at 必须存 epoch 秒级浮点，与 admin 手动封禁、hooks._act_block_ip
    # 以及登录校验/中间件的 `ban_expire_at > time.time()` 比对保持一致。
    # 注意：绝不能存 ISO 字符串——SQLite 中 TEXT > REAL 恒为真，会导致该 IP 永远无法自动解封，
    # 且管理员列表页 float() 解析会抛 ValueError。val 单位为分钟（来自 _parse_ban_duration）。
    expire = None if kind == "always" else (time.time() + float(val) * 60)
    await db(
        "INSERT INTO ip_blacklist (ip, reason, ban_expire_at) VALUES (?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, ban_expire_at=excluded.ban_expire_at",
        (ip, reason, expire),
    )


async def ban_account_with_duration(db, user_name: str, minutes: float, reason: str):
    expire = _expire_str(minutes)
    await db(
        "UPDATE users SET is_banned=1, ban_reason=?, ban_expire_at=? WHERE user_name=?",
        (reason, expire, user_name),
    )


async def ban_device(db, fingerprint: str, kind, val, reason: str):
    expire = None if kind == "always" else _expire_str(val)
    await db(
        "INSERT INTO device_ban (fingerprint, reason, ban_expire_at) VALUES (?,?,?) "
        "ON CONFLICT(fingerprint) DO UPDATE SET reason=excluded.reason, ban_expire_at=excluded.ban_expire_at",
        (fingerprint, reason, expire),
    )


async def is_device_banned(db, fingerprint: str) -> bool:
    rows = await db("SELECT ban_expire_at FROM device_ban WHERE fingerprint=?", (fingerprint,))
    if not rows:
        return False
    exp = rows[0].get("ban_expire_at")
    if not exp:
        return True
    try:
        if _dt.datetime.now() > _dt.datetime.fromisoformat(str(exp)):
            return False
    except Exception:
        pass
    return True


async def enforce_failed_login_ip(db, ip: str, owner: str):
    """R1：统计该 IP 失败登录次数，超阈值则封 IP"""
    rule = get_ban_rules()["failed_login_ip"]
    if not rule.get("enabled", True):
        return
    window = int(rule.get("window_sec", 3600))
    try:
        rows = await db(
            "SELECT COUNT(*) AS c FROM login_logs "
            "WHERE login_ip=? AND status='failed' AND created_at>=datetime('now', ?)",
            (ip, f"-{window} seconds"),
        )
        cnt = rows[0]["c"] if rows else 0
    except Exception as e:
        logging.error(f"enforce_failed_login_ip query failed: {e}")
        return
    if cnt < int(rule.get("trigger_count", 5)):
        return
    kind, val = resolve_rule_duration("failed_login_ip", cnt)
    if kind == "never":
        return
    reason = f"[自动封禁-IP] {cnt} 次失败登录（窗口 {window}s）"
    try:
        await ban_ip_auto(db, ip, kind, val, reason)
        logging.warning(reason)
    except Exception as e:
        logging.error(f"ban_ip_auto failed: {e}")


async def enforce_success_login_account(db, user_name: str, client_ip: str):
    """R2：统计该账号成功登录的不同 IP 数，超阈值则封账号（最低 10min）"""
    rule = get_ban_rules()["success_login_account"]
    if not rule.get("enabled", True):
        return
    window = int(rule.get("window_sec", 86400))
    try:
        rows = await db(
            "SELECT COUNT(DISTINCT login_ip) AS c FROM login_logs "
            "WHERE user_name=? AND status='success' AND created_at>=datetime('now', ?)",
            (user_name, f"-{window} seconds"),
        )
        cnt = rows[0]["c"] if rows else 0
    except Exception as e:
        logging.error(f"enforce_success_login_account query failed: {e}")
        return
    if cnt < int(rule.get("trigger_count", 10)):
        return
    kind, val = resolve_rule_duration("success_login_account", cnt)
    if kind == "never":
        return
    reason = f"[自动封禁-账号] {cnt} 次连续成功登录(不同IP)（窗口 {window}s）"
    try:
        await ban_account_with_duration(db, user_name, val, reason)
        logging.warning(reason)
    except Exception as e:
        logging.error(f"ban_account_with_duration failed: {e}")


# R3 设备请求计数（进程内，单进程足够；重启后清零）
_device_req_counter = {}


def compute_request_fingerprint(req) -> str:
    """服务端浏览器指纹：基于稳定的请求头组合哈希（无需 JS）"""
    h = req.headers
    parts = [
        h.get("User-Agent", ""),
        h.get("Accept-Language", ""),
        h.get("Accept-Encoding", ""),
        h.get("Accept", ""),
        h.get("sec-ch-ua", ""),
        h.get("sec-ch-ua-platform", ""),
        h.get("sec-ch-ua-mobile", ""),
    ]
    return _hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


def record_device_request(fingerprint: str, window_sec: int, trigger_count: int):
    """记录一次请求并检查是否超阈值。返回 (是否触发封禁, 当前窗口内计数)"""
    now = _time.time()
    lst = _device_req_counter.setdefault(fingerprint, [])
    lst.append(now)
    cutoff = now - window_sec
    while lst and lst[0] < cutoff:
        lst.pop(0)
    return (len(lst) >= trigger_count, len(lst))


# ============================================================
# 辅助函数
# ============================================================

# 需要 json 来序列化 details
import json


def get_device_fingerprint(device: DeviceInfo) -> str:
    """
    生成设备指纹 (轻量级, 仅基于 UA 解析结果, 不涉及浏览器 JS 指纹)
    用于快速比对设备是否变化
    """
    import hashlib
    # 将设备关键特征拼接后哈希
    raw = f"{device.device_type}|{device.os_name}|{device.browser_name}|{device.is_automation}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def build_enhanced_alert_details(
    device: DeviceInfo,
    client_ip: str,
    risk_score: int,
    risk_details: list[str],
    severity: str,
    action_taken: str,
) -> dict:
    """
    构建增强版安全告警信息 (用于邮件和前端展示)
    """
    severity_labels = {
        "safe": "安全",
        "warn": "警告",
        "restrict": "限制",
        "ban": "严重",
    }
    return {
        "device_display": device.display_name,
        "device_type": device.device_type,
        "os": f"{device.os_name} {device.os_version}",
        "browser": f"{device.browser_name} {device.browser_version}",
        "is_automation": device.is_automation,
        "ip": client_ip,
        "risk_score": risk_score,
        "risk_details": risk_details,
        "severity": severity_labels.get(severity, severity),
        "action_taken": action_taken,
    }
