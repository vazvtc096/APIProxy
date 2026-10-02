"""
JA3 维度限流 + 凭证填充（credential stuffing）检测 —— 行为/追溯层的「攻击识别」组件

与 ja3.py（指纹提取/登记）、honeypot.py（诱捕）互补，本模块负责「同一 JA3 指纹
表现出来的攻击性流量模式」识别：

  1) JA3 维度限流（JA3 rate limiting）
     正常情况下，同一 TLS 客户端实现（同一 JA3）的流量来自有限个 IP。若某个 JA3 在
     滑动窗口内出现大量请求、或横跨大量不同 IP（分布式扫描器/脚本换 IP 但 TLS 栈不变），
     即判定为「跨 IP 同指纹刷流量」，可限速/封禁。这能打中「换 IP 但 TLS 栈不变」的脚本。

  2) 凭证填充检测（credential stuffing）
     同一 JA3 在短窗口内尝试登录大量「不同账号」→ 典型的 stuffing 扫描器（从泄露库里
     批量试用户名）。检测到即对当前账号布设蜜罐/告警/封禁（默认 detect-only，仅告警+蜜罐）。

设计约束（与 seq_anomaly 一致）：
  - 纯内存滑动窗口追踪器，零外部依赖（不引入 torch/numpy）；
  - 默认 detect-only：只返回 verdict 与记录安全事件，是否拦截由 config 开关控制，
    避免误伤正常流量（尤其 JA3_RL_BLOCK / CRED_STUFFING_BLOCK 默认关闭）；
  - 所有运营动作（限速/封 IP/布蜜罐/告警）由调用方（中间件、登录流程）按 config 决定，
    本模块只算「该不该」。
"""
import logging
import time
from collections import OrderedDict, deque

from . import configs

logger = logging.getLogger("ja3_threat")

# 内存追踪器：ja3_hash -> {'req_ts': deque[ts], 'ip_ts': {ip: last_ts}, 'user_ts': [(ts, username)]}
# 用 OrderedDict 做 LRU 上限淘汰，避免海量不同 JA3 把内存吃爆。
_trackers = OrderedDict()
_CAP = 20000


def _get_tracker(ja3_hash: str) -> dict:
    t = _trackers.get(ja3_hash)
    if t is None:
        t = {"req_ts": deque(), "ip_ts": {}, "user_ts": []}
        _trackers[ja3_hash] = t
        if len(_trackers) > _CAP:
            # 淘汰最久未更新的指纹追踪器
            _trackers.popitem(last=False)
    else:
        _trackers.move_to_end(ja3_hash)
    return t


def _evict(deq, now, window):
    """原地丢弃窗口外的旧时间戳（deque 头元素较旧）。"""
    while deq and now - deq[0] > window:
        deq.popleft()


# ===========================================================================
# 1) JA3 维度限流
# ===========================================================================
def record_request(ja3_hash: str, client_ip: str = "") -> dict:
    """记录一次请求，返回限流判定。

    判定（任一满足即 blocked）：
      - 窗口内同 JA3 请求数 > JA3_RL_MAX_REQ       （请求突发）
      - 窗口内同 JA3 出现的不同 IP 数 >= JA3_RL_MAX_IPS（分布式/换 IP 脚本）

    注意：本函数无 await，纯 Python 操作，在 async 协程中运行于两次 await 之间，
    天然原子，无需加锁。
    """
    if not ja3_hash or not getattr(configs, "JA3_RL_ENABLED", True):
        return {"blocked": False, "reason": "", "req_count": 0, "distinct_ips": 0}
    now = time.time()
    win = float(getattr(configs, "JA3_RL_WINDOW", 60))
    t = _get_tracker(ja3_hash)

    t["req_ts"].append(now)
    if client_ip:
        t["ip_ts"][client_ip] = now

    _evict(t["req_ts"], now, win)
    # 清理窗口外的 IP 记录（保持 distinct_ips 反映窗口内真实分布）
    for ip in list(t["ip_ts"].keys()):
        if now - t["ip_ts"][ip] > win:
            del t["ip_ts"][ip]

    blocked = False
    reason = ""
    if len(t["req_ts"]) > int(getattr(configs, "JA3_RL_MAX_REQ", 120)):
        blocked = True
        reason = "ja3_req_burst"
    max_ips = int(getattr(configs, "JA3_RL_MAX_IPS", 8))
    if len(t["ip_ts"]) >= max_ips:
        blocked = True
        reason = reason or "ja3_distributed_ips"

    return {
        "blocked": blocked,
        "reason": reason,
        "req_count": len(t["req_ts"]),
        "distinct_ips": len(t["ip_ts"]),
    }


# ===========================================================================
# 2) 凭证填充检测
# ===========================================================================
def record_login_attempt(ja3_hash: str, client_ip: str = "", username: str = "",
                         success: bool = False) -> dict:
    """记录一次登录尝试（失败），返回凭证填充判定。

    仅统计「失败」尝试；对同一 (JA3, username) 在窗口内只计一次，避免同一账号反复
    输错密码把计数抬高（那是暴破，不是 stuffing；暴破由 security.py 的 IP 规则处理）。
    stuffing 的判定是：窗口内「尝试的不同账号数」>= CRED_STUFFING_MAX_USERS。
    """
    if not ja3_hash or not getattr(configs, "CRED_STUFFING_ENABLED", True):
        return {"stuffing": False, "distinct_users": 0}
    if success:
        return {"stuffing": False, "distinct_users": 0}
    if not username:
        return {"stuffing": False, "distinct_users": 0}
    now = time.time()
    win = float(getattr(configs, "CRED_STUFFING_WINDOW", 300))
    t = _get_tracker(ja3_hash)

    # 清理窗口外的尝试记录，并对当前窗口内用户名去重
    recent = [(ts, u) for (ts, u) in t["user_ts"] if now - ts <= win]
    seen = {u for (_, u) in recent}
    if username not in seen:
        recent.append((now, username))
    t["user_ts"] = recent

    distinct = len({u for (_, u) in t["user_ts"]})
    max_users = int(getattr(configs, "CRED_STUFFING_MAX_USERS", 10))
    stuffing = distinct >= max_users

    return {
        "stuffing": stuffing,
        "distinct_users": distinct,
        "max_users": max_users,
        "window": win,
    }


# ===========================================================================
# 3) WAF 命中联动（WAF-feed）
# ===========================================================================
def record_waf_hit(ja3_hash: str, client_ip: str = "", rule: str = "") -> int:
    """记录一次 WAF 拦截，计入该 JA3 的风险分。

    同一 TLS 指纹反复被 WAF 拦截（规则可不同）= 高危攻击者指纹。命中记录进
    滑动窗口（JA3_RL_WINDOW），在 list_threats 中作为独立风险维度参与排序，
    供管理员决定是否对该指纹升级处置（开 JA3_RL_BLOCK / ban_ip）。
    返回窗口内累计 WAF 命中次数。
    """
    if not ja3_hash:
        return 0
    now = time.time()
    win = float(getattr(configs, "JA3_RL_WINDOW", 60))
    t = _get_tracker(ja3_hash)
    t["waf_ts"] = [ts for ts in t.get("waf_ts", []) if now - ts <= win]
    t["waf_ts"].append(now)
    if client_ip:
        t["ip_ts"][client_ip] = now
    return len(t["waf_ts"])


# ===========================================================================
# 状态与查询（供 Console 命令）
# ===========================================================================
def status() -> dict:
    return {
        "ja3_rl_enabled": getattr(configs, "JA3_RL_ENABLED", True),
        "ja3_rl_block": getattr(configs, "JA3_RL_BLOCK", False),
        "ja3_rl_window": getattr(configs, "JA3_RL_WINDOW", 60),
        "ja3_rl_max_req": getattr(configs, "JA3_RL_MAX_REQ", 120),
        "ja3_rl_max_ips": getattr(configs, "JA3_RL_MAX_IPS", 8),
        "cred_stuffing_enabled": getattr(configs, "CRED_STUFFING_ENABLED", True),
        "cred_stuffing_block": getattr(configs, "CRED_STUFFING_BLOCK", False),
        "cred_stuffing_window": getattr(configs, "CRED_STUFFING_WINDOW", 300),
        "cred_stuffing_max_users": getattr(configs, "CRED_STUFFING_MAX_USERS", 10),
        "waf_feed_ja3_threat": getattr(configs, "WAF_FEED_JA3_THREAT", True),
        "tracked_fingerprints": len(_trackers),
    }


def list_threats(limit: int = 30) -> list:
    """返回当前风险最高的 JA3 指纹（按 不同账号数 > 不同 IP 数 > 请求数 排序）。"""
    now = time.time()
    win_rl = float(getattr(configs, "JA3_RL_WINDOW", 60))
    win_cs = float(getattr(configs, "CRED_STUFFING_WINDOW", 300))
    out = []
    for h, t in _trackers.items():
        req = sum(1 for ts in t["req_ts"] if now - ts <= win_rl)
        ips = sum(1 for ts in t["ip_ts"].values() if now - ts <= win_rl)
        users = len({u for (ts, u) in t["user_ts"] if now - ts <= win_cs})
        waf = sum(1 for ts in t.get("waf_ts", []) if now - ts <= win_rl)
        if req == 0 and ips == 0 and users == 0 and waf == 0:
            continue
        out.append({
            "ja3_hash": h,
            "req_count": req,
            "distinct_ips": ips,
            "distinct_users": users,
            "waf_hits": waf,
        })
    out.sort(key=lambda x: (x["distinct_users"], x["distinct_ips"],
                            x.get("waf_hits", 0), x["req_count"]),
             reverse=True)
    return out[:limit]
