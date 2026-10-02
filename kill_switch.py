"""全局熔断开关（Kill Switch）—— 安全运营的「最后一道闸」

定位：与逐项安全开关（sec_set）互补的**全局紧急开关**。当站点正在被攻击、
出现疑似数据泄露、上游失控等紧急情况时，一条命令把全站对外流量熔断成 503，
为管理员争取处置时间。区别于 maintenance_on（正常维护公告，用户体验友好），
kill switch 是**应急止血**：立即生效、支持 TTL 自动解除、带操作留痕。

设计约束：
  - 纯内存状态，零依赖、零 DB 往返：熔断检查在每个请求的最前面执行，
    必须是 O(1)；不落库（重启即解除——误操作重启自愈，这是特性不是缺陷）；
  - 豁免策略：默认放行本机回环（127.0.0.1/::1）与内网网段，保证管理员
    在熔断后仍能登进后台排查；可经 KILL_SWITCH_ALLOW_PRIVATE 关闭严格模式；
  - 所有 CLI：kill_on / kill_off / kill_status（tier=2 admin，属高危命令，
    由 bastion BASTION_RISK_COMMANDS 记录/审批）；
  - 激活/解除时写 security_events 留痕（best-effort，DB 挂了也要能熔断）。
"""
import ipaddress
import logging
import threading
import time

from . import configs

logger = logging.getLogger("kill_switch")

_state_lock = threading.Lock()
_state = {
    "active": False,
    "reason": "",
    "activated_at": 0.0,
    "expire_at": 0.0,      # 0 = 手动解除前一直生效
    "activated_by": "console",
}

# 豁免网段（KILL_SWITCH_ALLOW_PRIVATE=true 时放行）
_LOOPBACK_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128")]
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10")]


def activate(reason: str = "", ttl_min: int = 0, by: str = "console") -> dict:
    """激活全局熔断。ttl_min>0 时到期自动解除；ttl_min=0 需手动 kill_off。"""
    now = time.time()
    with _state_lock:
        _state.update({
            "active": True,
            "reason": str(reason or "").strip(),
            "activated_at": now,
            "expire_at": now + ttl_min * 60 if ttl_min and ttl_min > 0 else 0.0,
            "activated_by": by,
        })
    logger.warning(f"KILL SWITCH 已激活 reason={reason!r} ttl_min={ttl_min} by={by}")
    _record_event("kill_switch_on", f"reason={reason}; ttl_min={ttl_min}; by={by}")
    return status()


def deactivate(by: str = "console") -> dict:
    """解除全局熔断。"""
    with _state_lock:
        _state["active"] = False
        _state["expire_at"] = 0.0
    logger.warning(f"KILL SWITCH 已解除 by={by}")
    _record_event("kill_switch_off", f"by={by}")
    return status()


def check(client_ip: str = "") -> dict:
    """每个请求最前面的熔断判定（O(1)，无 IO）。

    返回 {'blocked': bool, 'reason': str, 'bypass': str}
    bypass: 'loopback' | 'private' | 'disabled' | ''（空 = 被熔断）
    """
    with _state_lock:
        if not _state["active"]:
            return {"blocked": False, "reason": "", "bypass": "disabled"}
        # TTL 自动过期（惰性解除：发现过期即顺手关掉）
        exp = _state["expire_at"]
        if exp and time.time() >= exp:
            _state["active"] = False
            _state["expire_at"] = 0.0
            logger.warning("KILL SWITCH TTL 已到，自动解除")
            return {"blocked": False, "reason": "", "bypass": "expired"}
        reason = _state["reason"]

    # 豁免：本机回环 + （可选）内网网段
    if client_ip:
        raw = client_ip.split("%")[0]  # 去掉 IPv6 zone
        # 双栈监听下 IPv4 客户端可能是 ::ffff:a.b.c.d 映射形式，先归一化
        if raw.startswith("::ffff:") and "." in raw:
            raw = raw[7:]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            ip = None
        if ip is not None:
            if any(ip in n for n in _LOOPBACK_NETS):
                return {"blocked": False, "reason": reason, "bypass": "loopback"}
            if getattr(configs, "KILL_SWITCH_ALLOW_PRIVATE", True):
                if any(ip in n for n in _PRIVATE_NETS):
                    return {"blocked": False, "reason": reason, "bypass": "private"}

    return {"blocked": True, "reason": reason, "bypass": ""}


def is_ip_exempt(client_ip: str) -> bool:
    """供 Console 提示用：该 IP 是否属于熔断豁免范围。"""
    return not check(client_ip)["blocked"] if _state["active"] else False


def status() -> dict:
    with _state_lock:
        active = _state["active"]
        exp = _state["expire_at"]
        remain = max(0, int(exp - time.time())) if (active and exp) else 0
        return {
            "active": active,
            "reason": _state["reason"],
            "activated_at": _state["activated_at"],
            "expire_at": exp,
            "remain_sec": remain,
            "activated_by": _state["activated_by"],
            "allow_private": getattr(configs, "KILL_SWITCH_ALLOW_PRIVATE", True),
        }


def _record_event(event_type: str, details: str) -> None:
    """熔断动作留痕到 security_events（best-effort：同步 try，失败只打日志）。"""
    try:
        import asyncio
        from .core import async_db_query
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            loop.create_task(async_db_query(
                "INSERT INTO security_events (event_type, severity, risk_score, "
                "client_ip, details, action_taken) VALUES (?, ?, ?, ?, ?, ?)",
                (event_type, "critical", 100, "127.0.0.1", details, "kill_switch")))
        else:
            # 无运行中事件循环（CLI 同步上下文）：开临时循环执行
            asyncio.run(async_db_query(
                "INSERT INTO security_events (event_type, severity, risk_score, "
                "client_ip, details, action_taken) VALUES (?, ?, ?, ?, ?, ?)",
                (event_type, "critical", 100, "127.0.0.1", details, "kill_switch")))
    except Exception as e:
        logger.error(f"kill switch record event failed: {e}")
