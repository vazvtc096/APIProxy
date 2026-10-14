"""上网行为管理（Web 行为过滤 + 全站上网行为审计）。

与 WAF / IDS/IPS 的关系与边界：
  - WAF     管「Web 应用层攻击」（SQLi/XSS/路径遍历…）。
  - IDS/IPS 管「入侵行为」（漏洞利用/扫描/暴破）。
  - 本模块 管「用户上网内容合规与行为留痕」：
      * 分类过滤：把请求 URL 按预置分类（恶意/钓鱼/赌博/成人/代理匿名…）
        归类，命中「封禁分类」且处于 block 模式时拦截（403）。
      * 行为审计：全站每一条访问（方法/路径/分类/状态/用户/IP/字节）写入
        web_access_log，形成可审计的上网行为轨迹。

设计约束（避免误杀正常 API 流量）：
  - 仅对「站点浏览类」路径做内容分类，对 /api/*、/v1/* 等程序化接口跳过分类
    （这些不是「上网行为」范畴，交给 WAF/IDS 处理）。
  - 管理员默认豁免「内容拦截」但照常记录（WEB_FILTER_BYPASS_ADMIN）。
  - 分类用保守的关键词子串匹配，且只拦 WEB_FILTER_BLOCK 中显式列出的分类。

接口（供 security_middleware 调用）：
  wf_inspect_request(request, client_ip, is_admin) -> dict | None
  wf_record_access(request, client_ip, user, status, nbytes) -> None   # 异步写库
  wf_categories() / wf_status() / wf_policy()
"""
import logging
import re
from typing import List, Optional
from urllib.parse import urlparse, unquote

from . import configs
from .core_db import async_db_query

logger = logging.getLogger(__name__)


# ============================================================================
# 配置读取（运行期动态读取 configs，确保 CLI 覆盖即时生效）
# ============================================================================
def _enabled() -> bool:
    return bool(getattr(configs, "WEB_FILTER_ENABLED", True))


def _mode() -> str:
    m = str(getattr(configs, "WEB_FILTER_MODE", "block")).strip().lower()
    return m if m in ("monitor", "block") else "block"


def _log_all() -> bool:
    return bool(getattr(configs, "WEB_FILTER_LOG_ALL", True))


def _bypass_admin() -> bool:
    return bool(getattr(configs, "WEB_FILTER_BYPASS_ADMIN", True))


def _block_list() -> List[str]:
    bl = getattr(configs, "WEB_FILTER_BLOCK", None)
    if isinstance(bl, (list, tuple)):
        return [str(c).strip().lower() for c in bl]
    if isinstance(bl, str):
        return [c.strip().lower() for c in bl.split(",") if c.strip()]
    return []


# ============================================================================
# 分类关键词（保守、可扩展）
# ============================================================================
_CATEGORY_KEYWORDS = {
    "malware":   ["malware", "virus", "trojan", "exploit", "botnet", "c2",
                  "shellcode", "payload", "webshell", "后门", "木马", "病毒"],
    "phishing":  ["phishing", "account-verify", "verify-bank", "secure-signin",
                  "login-secure", "账户验证", "钓鱼", "冒充"],
    "gambling":  ["casino", "bet365", "gambling", "poker", "lottery", "博彩",
                  "百家乐", "彩票", "赌博", "赌球"],
    "adult":     ["porn", "xxx", "adult", "sex", "色情", "成人", "av"],
    "proxy":     ["free-proxy", "anonymizer", "shadowsocks", "v2ray", "trojan-go",
                  "翻墙", "科学上网", "自由门", "VPN下载", "代理服务器"],
    "social":    ["facebook", "twitter", "instagram", "tiktok", "weibo",
                  "douyin", "qq", "wechat", "微信", "微博", "社交"],
    "streaming": ["youtube", "netflix", "bilibili", "iqiyi", "youku", "爱奇艺",
                  "优酷", "视频"],
    "ads":       ["doubleclick", "adsense", "banner-ad", "广告联盟"],
}

# 浏览类路径前缀（仅这些走内容分类；程序化 API 跳过）
_BROWSING_PREFIXES = ("/",)
_API_PREFIXES = ("/api/", "/v1/", "/oauth/", "/internal/", "/cluster/",
                 "/admin", "/static/", "/api/console", "/api/debug-console")


# ============================================================================
# 分类
# ============================================================================
def classify(text: str) -> Optional[str]:
    """把一段文本（path+query）归类到第一个命中的分类；未命中返回 None。

    纯 ASCII 且长度 <= 3 的短关键词（如 "av"、"c2"）按词边界匹配，
    避免 URL 子串误伤（如 favicon.ico / java / save 命中 "av"）。
    """
    if not text:
        return None
    low = text.lower()
    for cat, kws in _CATEGORY_KEYWORDS.items():
        for kw in kws:
            k = kw.lower()
            if len(k) <= 3 and k.isascii():
                if re.search(r'(?<![a-z0-9])' + re.escape(k) + r'(?![a-z0-9])', low):
                    return cat
            elif k in low:
                return cat
    return None


def _is_browsing_path(path: str) -> bool:
    if any(path.startswith(p) for p in _API_PREFIXES):
        return False
    return True


def _request_text(request) -> str:
    try:
        path = request.path or ""
        q = request.query_string.decode("utf-8", "ignore") if hasattr(request, "query_string") else ""
        # 还原一次 URL 解码以暴露混淆的分类词
        try:
            q = unquote(q)
        except Exception:
            pass
        return (path + "?" + q).lower()
    except Exception:
        return ""


# ============================================================================
# 请求期检测（before_request 调用）
# ============================================================================
def wf_inspect_request(request, client_ip: str, is_admin: bool = False) -> Optional[dict]:
    """返回 None 表示放行或仅记录；返回 dict 表示应当拦截（block 模式）。

    dict: {rule, category, reason, status, action}
    """
    if not _enabled():
        return None
    path = request.path or ""
    if not _is_browsing_path(path):
        return None  # 程序化 API 不分类，交给 WAF/IDS
    text = _request_text(request)
    cat = classify(text)
    if not cat:
        return None
    # 分类命中：管理员豁免「拦截」但照常记录（记录由 after_request 完成）
    if is_admin and _bypass_admin():
        return None
    if cat in _block_list() and _mode() == "block":
        return {
            "rule": "web_filter_category",
            "category": cat,
            "reason": f"上网行为管理：命中封禁分类「{cat}」",
            "status": 403,
            "action": "block",
        }
    return None


# ============================================================================
# 行为审计（after_request 调用，异步写库）
# ============================================================================
async def wf_record_access(request, client_ip: str, user: str,
                           status: int, nbytes: int) -> None:
    """把一次访问写入 web_access_log（全站行为留痕）。"""
    if not _enabled() or not _log_all():
        return
    try:
        path = request.path or ""
        if path.startswith("/static/"):
            return
        q = request.query_string.decode("utf-8", "ignore") if hasattr(request, "query_string") else ""
        cat = classify(_request_text(request)) or ""
        # 程序化 API 访问仍记录（仅类别留空），用于完整行为轨迹
        action = "blocked" if status == 403 else "allowed"
        await async_db_query(
            "INSERT INTO web_access_log "
            "(user_uid, user_name, client_ip, method, path, query, category, action, status, bytes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (None, user or "", client_ip, (request.method or "GET").upper(),
             path[:500], q[:500], cat, action, int(status or 0), int(nbytes or 0))
        )
    except Exception as e:
        logger.error(f"web_filter record failed: {e}")


# ============================================================================
# 运行期策略调整（供 Console wf_block / wf_unblock）
# ============================================================================
def wf_add_block(cat: str) -> bool:
    cat = (cat or "").strip().lower()
    if not cat:
        return False
    bl = _block_list()
    if cat not in bl:
        bl.append(cat)
        configs.WEB_FILTER_BLOCK = bl
    return True


def wf_remove_block(cat: str) -> bool:
    cat = (cat or "").strip().lower()
    bl = [c for c in _block_list() if c != cat]
    configs.WEB_FILTER_BLOCK = bl
    return True


# ============================================================================
# 状态 / 清单（供 Console）
# ============================================================================
def wf_status() -> dict:
    return {
        "enabled": _enabled(),
        "mode": _mode(),
        "log_all": _log_all(),
        "bypass_admin": _bypass_admin(),
        "block_list": _block_list(),
        "total_categories": len(_CATEGORY_KEYWORDS),
    }


def wf_categories() -> List[dict]:
    bl = set(_block_list())
    return [
        {"category": c, "keywords": kws, "blocked": c in bl}
        for c, kws in _CATEGORY_KEYWORDS.items()
    ]


def wf_policy() -> dict:
    return {"mode": _mode(), "block_list": _block_list()}
