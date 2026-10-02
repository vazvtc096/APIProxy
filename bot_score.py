"""bot_score.py — 自动化/bot 评分 + 同 Token(会话) 多 JA3/IP 并发检测

把分散在前几层的信号聚合成一个 0~100 的「机器人可能性分」，并直接识别
「同一个会话 token 出现在多个不同 TLS 栈（多 JA3）/ 多个不同 IP」这种会话
被盗用的强特征。

信号来源：
  - JA3 合成 / 陌生（来自 ja3.extract_ja3）
  - 序列异常 surprise（来自 seq_anomaly.record_and_score）
  - 同 token 跨 JA3 / 跨 IP（本模块维护的会话绑定表）
  - Cloudflare cf-bot-score / cf-verified-bot（若开启 Bot Management）

默认 detect-only：BOT_SCORE_BLOCK=false 时只评分 + 告警；确认无误伤后再开拦截。
"""

import logging
import threading
import time

from . import configs

logger = logging.getLogger("bot_score")

# 会话 -> 指纹绑定（纯内存，与 seq_anomaly / ja3_threat 同范式）
_session_fp = {}  # session_id -> {"ja3": set, "ips": set, "user": str, "first": float, "last": float}
_lock = threading.Lock()


def _cap() -> None:
    cap = max(1000, int(getattr(configs, "BOT_SCORE_MAX_SESSIONS", 20000)))
    if len(_session_fp) > cap:
        # 淘汰最久未活动的会话绑定（LRU）
        oldest_key = min(_session_fp, key=lambda k: _session_fp[k]["last"])
        _session_fp.pop(oldest_key, None)


def record_token_binding(session_id: str, ja3_hash: str, ip: str, user: str = "") -> dict:
    """记录某会话在 (ja3, ip) 上的出现；返回是否跨 JA3 / 跨 IP。

    无 session_id 时返回空结果（仅登录态会话参与 token 复用检测）。
    """
    if not session_id:
        return {"session_id": "", "shared_ja3": False, "shared_ip": False,
                "distinct_ja3": 0, "distinct_ips": 0}
    with _lock:
        now = time.time()
        rec = _session_fp.get(session_id)
        if rec is None:
            rec = {"ja3": set(), "ips": set(), "user": user, "first": now, "last": now}
            _session_fp[session_id] = rec
        if ja3_hash:
            rec["ja3"].add(ja3_hash)
        if ip:
            rec["ips"].add(ip)
        if user:
            rec["user"] = user
        rec["last"] = now
        _cap()
        return {
            "session_id": session_id,
            "shared_ja3": len(rec["ja3"]) > 1,
            "shared_ip": len(rec["ips"]) > 1,
            "distinct_ja3": len(rec["ja3"]),
            "distinct_ips": len(rec["ips"]),
        }


def score_bot(ja3_info=None, seq_surprise=0.0, token_binding=None,
              cf_bot_score=None, cf_verified_bot=False) -> dict:
    """综合评分。返回 {score, is_bot, reasons}。

    - Cloudflare cf-verified-bot=true：已验证的良好 bot（如 Google/百度 爬虫），不计入恶意分。
    - cf-bot-score：1(人) ~ 99(bot)，直接作为上限分。
    - 合成 JA3：+45（无真实 TLS 可见性，近似指纹，脚本概率高）。
    - 序列异常 surprise：线性映射到 0~100（surprise*30）。
    - 同 token 跨 JA3 / 跨 IP：会话被盗用强特征，+75 / +60。
    """
    score = 0
    reasons = []
    thr = int(getattr(configs, "BOT_SCORE_THRESHOLD", 60))

    # Cloudflare Bot Management 直采
    if cf_verified_bot:
        reasons.append("cf_verified_bot")  # 良好 bot，不加分
    elif cf_bot_score is not None:
        try:
            cbs = int(cf_bot_score)
            score = max(score, cbs)
            if cbs >= 30:
                reasons.append(f"cf_bot_score={cbs}")
        except (TypeError, ValueError):
            pass

    # 合成 JA3（无真实 TLS 可见性，近似指纹）
    if ja3_info and ja3_info.get("synthetic"):
        score = max(score, 45)
        reasons.append("synthetic_ja3")

    # 序列异常 surprise（>2 视为显著；线性映射到 0~100）
    try:
        s = float(seq_surprise or 0.0)
    except (TypeError, ValueError):
        s = 0.0
    if s > 0:
        mapped = min(100, int(s * 30))
        if mapped >= 40:
            score = max(score, mapped)
            reasons.append(f"seq_surprise={s:.2f}")

    # 同 token 跨 JA3 / 跨 IP（会话被盗用强特征）
    if token_binding:
        if token_binding.get("shared_ja3"):
            score = max(score, 75)
            reasons.append("token_multi_ja3")
        if token_binding.get("shared_ip"):
            score = max(score, 60)
            reasons.append("token_multi_ip")

    score = min(100, max(0, int(score)))
    return {"score": score, "is_bot": score >= thr, "reasons": reasons}


def status() -> dict:
    with _lock:
        tracked = len(_session_fp)
    return {
        "enabled": getattr(configs, "BOT_SCORE_ENABLED", True),
        "threshold": int(getattr(configs, "BOT_SCORE_THRESHOLD", 60)),
        "block": getattr(configs, "BOT_SCORE_BLOCK", False),
        "tracked_sessions": tracked,
        "max_sessions": max(1000, int(getattr(configs, "BOT_SCORE_MAX_SESSIONS", 20000))),
    }


def list_risky(limit: int = 20) -> list:
    """返回风险最高的会话绑定（仅含跨 JA3/跨 IP 的项，按风险降序）。"""
    with _lock:
        items = []
        for sid, rec in _session_fp.items():
            risk = 0
            if len(rec["ja3"]) > 1:
                risk = max(risk, 75)
            if len(rec["ips"]) > 1:
                risk = max(risk, 60)
            if risk:
                items.append({
                    "session_id": (sid[:16] + "…") if len(sid) > 16 else sid,
                    "user": rec.get("user", "") or "",
                    "distinct_ja3": len(rec["ja3"]),
                    "distinct_ips": len(rec["ips"]),
                    "risk": risk,
                })
        items.sort(key=lambda x: x["risk"], reverse=True)
        return items[:limit]
