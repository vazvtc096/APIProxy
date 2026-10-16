# -*- coding: utf-8 -*-
"""Cloudflare 支持 + 官方 IP 段自动拉取。

当 APIProxy 部署在 Cloudflare 之后时，真实访客 IP 由 Cloudflare 通过
`CF-Connecting-IP` 头携带。本模块统一解析真实客户端 IP，并周期从 Cloudflare
官方地址拉取最新的边缘节点 IPv4/IPv6 段（缓存到本地文件，离线/失败回退内置列表），
避免硬编码段过期导致误判。

安全：仅当请求确实来自 Cloudflare 边缘节点（或显式配置信任）时才采信客户端可控头，
避免攻击者直连源站伪造 `CF-Connecting-IP` / `X-Forwarded-For`。
"""
import ipaddress
import json
import os
import threading
import time
import logging
import urllib.request

from quart import request, g
from .configs import (
    CLOUDFLARE_TRUSTED,
    CLOUDFLARE_IP_REFRESH_ENABLED,
    CLOUDFLARE_IP_REFRESH_HOURS,
)

logger = logging.getLogger(__name__)

CLOUDFLARE_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPS_V6_URL = "https://www.cloudflare.com/ips-v6"
CLOUDFLARE_IPS_CACHE_FILE = os.path.join(os.path.dirname(__file__), "cloudflare_ips.json")

# 内置兜底列表（与 Cloudflare 官方段一致；离线或拉取失败时使用）
DEFAULT_CLOUDFLARE_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

DEFAULT_CLOUDFLARE_IPV6_RANGES = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

_lock = threading.Lock()
_CLOUDFLARE_NETWORKS = []
_ranges_source = "default"   # 'default' | 'cache' | 'fetched'
_ranges_updated_at = None
_refresh_thread = None
_refresh_stop = threading.Event()


def _build_networks(v4, v6):
    """从 CIDR 字符串列表构建 ip_network 列表，跳过无效的。"""
    nets = []
    for cidr in list(v4) + list(v6):
        cidr = (cidr or "").strip()
        if not cidr or cidr.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("忽略无效的 Cloudflare 段: %s", cidr)
    return nets


def _load_cached_or_default():
    """启动时：优先用本地缓存，否则回退内置兜底列表。"""
    global _CLOUDFLARE_NETWORKS, _ranges_source, _ranges_updated_at
    # 尝试本地缓存
    try:
        if os.path.exists(CLOUDFLARE_IPS_CACHE_FILE):
            with open(CLOUDFLARE_IPS_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            v4 = data.get("v4") or []
            v6 = data.get("v6") or []
            if v4 or v6:
                nets = _build_networks(v4, v6)
                if nets:
                    with _lock:
                        _CLOUDFLARE_NETWORKS = nets
                        _ranges_source = data.get("source", "cache")
                        _ranges_updated_at = data.get("updated_at")
                    logger.info("已加载缓存的 Cloudflare IP 段（%d 条，来源 %s）", len(nets), _ranges_source)
                    return
    except Exception as e:
        logger.warning("读取 Cloudflare IP 缓存失败，回退内置列表: %s", e)

    # 回退内置
    nets = _build_networks(DEFAULT_CLOUDFLARE_IPV4_RANGES, DEFAULT_CLOUDFLARE_IPV6_RANGES)
    with _lock:
        _CLOUDFLARE_NETWORKS = nets
        _ranges_source = "default"
        _ranges_updated_at = None
    logger.info("使用内置兜底 Cloudflare IP 段（%d 条）", len(nets))


def fetch_cloudflare_ranges(timeout=10):
    """从 Cloudflare 官方地址拉取最新 IPv4/IPv6 段。失败抛异常。"""
    def _get(url):
        req = urllib.request.Request(url, headers={"User-Agent": "APIProxy-Cloudflare-Sync/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
        return [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    v4 = _get(CLOUDFLARE_IPS_V4_URL)
    v6 = _get(CLOUDFLARE_IPS_V6_URL)
    if not v4 and not v6:
        raise ValueError("Cloudflare 官方地址返回为空")
    return v4, v6


def refresh_cloudflare_ranges():
    """拉取最新段并热更新 + 写缓存。成功返回 True。"""
    global _CLOUDFLARE_NETWORKS, _ranges_source, _ranges_updated_at
    try:
        v4, v6 = fetch_cloudflare_ranges()
        nets = _build_networks(v4, v6)
        if not nets:
            logger.warning("Cloudflare IP 拉取结果为空，保持现状")
            return False
        with _lock:
            _CLOUDFLARE_NETWORKS = nets
            _ranges_source = "fetched"
            _ranges_updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            with open(CLOUDFLARE_IPS_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({"v4": v4, "v6": v6, "source": "fetched",
                           "updated_at": _ranges_updated_at}, f)
        except Exception as e:
            logger.warning("写入 Cloudflare IP 缓存失败: %s", e)
        logger.info("已更新 Cloudflare IP 段（%d 条）", len(nets))
        return True
    except Exception as e:
        logger.warning("拉取 Cloudflare IP 段失败，保持现有段: %s", e)
        return False


def get_ranges_status():
    """返回当前使用的 IP 段状态（供管理接口展示）。"""
    with _lock:
        nets = _CLOUDFLARE_NETWORKS
        source = _ranges_source
        updated = _ranges_updated_at
    return {
        "source": source,
        "updated_at": updated,
        "count": len(nets),
        "v4": [str(n) for n in nets if n.version == 4],
        "v6": [str(n) for n in nets if n.version == 6],
        "refresh_enabled": CLOUDFLARE_IP_REFRESH_ENABLED,
        "refresh_hours": CLOUDFLARE_IP_REFRESH_HOURS,
    }


def _refresh_loop(interval_seconds):
    """后台循环：每隔 interval_seconds 拉取一次，直到收到停止信号。"""
    while not _refresh_stop.is_set():
        if _refresh_stop.wait(interval_seconds):
            break
        refresh_cloudflare_ranges()


def start_cloudflare_refresh(interval_hours=None):
    """启动后台定时拉取线程（守护线程）。重复调用安全。"""
    global _refresh_thread
    if not CLOUDFLARE_IP_REFRESH_ENABLED:
        logger.info("Cloudflare IP 自动刷新已关闭（CLOUDFLARE_IP_REFRESH_ENABLED=false）")
        return
    if _refresh_thread and _refresh_thread.is_alive():
        return
    if interval_hours is None:
        interval_hours = CLOUDFLARE_IP_REFRESH_HOURS
    interval = max(1, int(interval_hours * 3600))
    _refresh_stop.clear()
    _refresh_thread = threading.Thread(target=_refresh_loop, args=(interval,), daemon=True)
    _refresh_thread.start()
    logger.info("Cloudflare IP 自动刷新已启动（每 %d 小时）", interval_hours)


def stop_cloudflare_refresh():
    """停止后台定时拉取线程。"""
    _refresh_stop.set()


# ---------- 请求级 IP 解析 ----------
def is_cloudflare_ip(ip_str: str) -> bool:
    """判断给定 IP 是否属于 Cloudflare 官方边缘节点段。"""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    nets = _CLOUDFLARE_NETWORKS
    return any(ip in net for net in nets)


def is_cloudflare_request() -> bool:
    """判断当前请求是否应采信 Cloudflare 提供的头。

    - CLOUDFLARE_TRUSTED == 'true'  -> 始终采信（需自行用防火墙限制仅 Cloudflare 可达源站）
    - CLOUDFLARE_TRUSTED == 'false' -> 不采信
    - 'auto'（默认）-> 仅当 remote_addr 命中 Cloudflare 段时采信
    """
    if CLOUDFLARE_TRUSTED == "true":
        return True
    if CLOUDFLARE_TRUSTED == "false":
        return False
    return is_cloudflare_ip(request.remote_addr or "")


def get_client_ip() -> str:
    """获取真实客户端 IP，兼容 Cloudflare / 自有反代 / 直连。

    安全前提：仅当请求确实来自可信代理（Cloudflare 或直连/内部反代）时，
    才信任客户端可控头（CF-Connecting-IP / X-Forwarded-For / X-Real-IP）。

    性能：中间件同一请求内多处调用本函数，此处做请求级缓存，
    避免每处都重新解析 XFF 并扫描 Cloudflare 网段。
    """
    _MISS = object()
    try:
        cached = getattr(g, "_client_ip_cached", _MISS)
        if cached is not _MISS:
            return cached
    except RuntimeError:
        pass  # 无请求上下文（后台任务等），直接解析

    ip = _resolve_client_ip()

    try:
        g._client_ip_cached = ip
    except RuntimeError:
        pass
    return ip


def _is_valid_ip(v: str) -> bool:
    if not v:
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _pick_proxy_ip(headers, remote: str) -> str:
    """本机可信代理（cloudflared / tls_front，均从 127.0.0.1 连入）场景下解析真实客户端 IP。

    优先级：
      1. CF-Connecting-IP —— 经 CF 隧道时由边缘权威覆盖（客户端伪造值到不了这里）；
      2. X-Forwarded-For 取【最右】合法 IP —— CF 边缘把真实直连者追加在末尾，
         客户端自带的伪造段在前部；tls_front 则只注入单个真实 peer；
         绝不能取最左项（那正是客户端可控的伪造位）。
      3. X-Real-IP —— tls_front 强制覆盖注入，可信。
    所有取出的值必须能解析为合法 IP，否则继续降级，最终回落 remote。
    """
    cf_ip = (headers.get("CF-Connecting-IP") or "").strip()
    if _is_valid_ip(cf_ip):
        return cf_ip
    xff = (headers.get("X-Forwarded-For") or "").strip()
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for p in reversed(parts):
            if _is_valid_ip(p):
                return p
    xri = (headers.get("X-Real-IP") or "").strip()
    if _is_valid_ip(xri):
        return xri
    return remote or "unknown"


def _resolve_client_ip() -> str:
    """实际解析逻辑（由 get_client_ip 包裹请求级缓存）。

    安全核心：客户端可控头（CF-Connecting-IP / X-Forwarded-For / X-Real-IP）
    仅当请求来自【本机回环】这一可信代理时才解析。历史版本曾对一切来源取
    XFF 最左项——任何直连/经隧道的攻击者带一个伪造 XFF 就能冒充任意 IP
    （限流、封禁、ip_audit 的 IP 绑定全部失效），已修复。
    """
    remote = request.remote_addr or ""

    if is_cloudflare_request():
        # remote 落在 CF 官方网段：CF 头权威
        cf_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
        if cf_ip:
            return cf_ip
        return _pick_proxy_ip(request.headers, remote)

    # 本机回环 = 唯一可信代理链路（cloudflared / tls_front 都从 127.0.0.1 连入）
    try:
        raddr = ipaddress.ip_address(remote)
    except ValueError:
        raddr = None
    if raddr is not None and raddr.is_loopback:
        return _pick_proxy_ip(request.headers, remote)

    # 其余一切来源（公网直连 / 局域网直连）：客户端可控头一律无视
    return remote or "unknown"


def is_loopback_client() -> bool:
    """本次请求的【真实客户端】是否来自回环地址。

    用于集群内部端点（/internal/*）在【未配置共享密钥】时的信任回退判定。

    必须基于 get_client_ip() 这一"可信解析"结果，绝不能直接读 X-Forwarded-For ——
    该头客户端完全可控，否则任意公网请求只要带上 `X-Forwarded-For: 127.0.0.1`
    就能冒充集群内部节点。非可信链路（公网直连 / 局域网直连 + 经隧道）下
    客户端可控头一律被忽略，故伪造头不会让本函数返回 True。
    """
    ip = (get_client_ip() or "").strip()
    if ip == "localhost":
        return True
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def is_private_client() -> bool:
    """本次请求的【真实客户端】是否来自回环 / 私网 / 链路本地。

    用于把运维面只读端点（/metrics、健康自检明细）限制在内网：
    get_client_ip() 是可信解析结果——经 Cloudflare 隧道时会还原为真实公网 IP，
    故公网请求不会被误判为内网。
    """
    ip = (get_client_ip() or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_loopback or addr.is_private or addr.is_link_local)


def get_client_country() -> str:
    """返回 Cloudflare 提供的客户端国家代码（ISO 3166-1 alpha-2）。"""
    return (request.headers.get("CF-IPCountry") or "").strip()


# 模块导入时加载一次（缓存优先，否则内置兜底）
_load_cached_or_default()
