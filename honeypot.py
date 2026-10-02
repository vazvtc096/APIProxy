"""
蜜罐账号 —— 诱捕自动化登录 / 凭据填充攻击

思路:
  当检测到「自动化程序」尝试登录（尤其是针对不存在的用户名，典型的凭据填充 / 用户名枚举 /
  扫描器行为）时，不再简单返回 "Invalid credentials"，而是**动态创建一个临时的蜜罐账号**：
    - 用攻击者提交的（用户名, 密码）作为凭据，使其「登录成功」进入诱饵环境；
    - 账号标记 is_honeypot=1，余额设为假值（不会消耗真实资金），无管理员权限，
      不出现在好友推荐/通知投递中；
    - 记录攻击者目标用户名、来源 IP、JA3 指纹、UA，便于追溯与关联；
    - 蜜罐账号带 TTL，到期经 expire_honeypots() 自动销毁。
  后续该攻击者在此账号下的所有行为被全程记录（security_events: honeypot_activity），
  真实用户不受任何影响（蜜罐用户名是攻击者的尝试名，真用户可用别的用户名注册；即便
  重名，is_honeypot 标记使该账号永远是诱饵，不会被当成真实账号升级）。

安全默认值:
  - HONEYPOT_ON_UNKNOWN_USER=True  ：自动化 + 用户不存在 → 布设蜜罐（主要场景）。
  - HONEYPOT_ON_AUTOMATION_LOGIN=False：自动化登录「已存在」真实账号默认**不**布设，
    以免误伤（仅记录告警）。该开关留给运维按需开启。
  - 每 IP 最多 HONEYPOT_MAX_PER_IP 个活跃蜜罐，防止攻击者用海量用户名刷爆数据库。
  - 蜜罐会话在中间件中被限制敏感操作（HONEYPOT_TRAP_ACTIONS），活动全程留痕。
"""
import logging
import time as _time
from datetime import datetime, timedelta

from . import configs
from .core_db import async_db_query, _get_conn
from .security import record_security_event

logger = logging.getLogger("honeypot")


def _now_iso():
    return datetime.now().isoformat(timespec="seconds")


# ===========================================================================
# 布设
# ===========================================================================
async def _count_active_baits_for_ip(client_ip: str) -> int:
    try:
        rows = await async_db_query(
            "SELECT COUNT(*) AS c FROM honeypot_accounts "
            "WHERE attacker_ip=? AND is_disarmed=0",
            (client_ip,)
        )
        return rows[0]["c"] if rows else 0
    except Exception:
        return 0


async def deploy_honeypot(username: str, password_hash: str, client_ip: str,
                          ja3_hash: str, user_agent: str, reason: str) -> dict:
    """创建一个临时蜜罐账号。

    返回 {deployed, bait_username, reason, error?}。
    若同名蜜罐已存在，视为同一攻击者再次尝试，直接返回已存在的诱饵（不重复创建）。
    """
    if not getattr(configs, "HONEYPOT_ENABLED", True):
        return {"deployed": False, "reason": "disabled"}
    username = (username or "").strip()
    if not username:
        return {"deployed": False, "reason": "empty-username"}

    # 每 IP 活跃蜜罐上限
    try:
        cap = int(configs.HONEYPOT_MAX_PER_IP)
    except Exception:
        cap = 3
    active = await _count_active_baits_for_ip(client_ip)
    if active >= cap:
        return {"deployed": False, "reason": f"per-ip bait cap reached ({cap})"}

    # 已存在同名蜜罐？
    try:
        existing = await async_db_query(
            "SELECT user_name FROM users WHERE user_name=? AND is_honeypot=1", (username,)
        )
        if existing:
            # 更新攻击计数并续期
            await async_db_query(
                "UPDATE honeypot_accounts SET last_seen=CURRENT_TIMESTAMP "
                "WHERE bait_username=?", (username,)
            )
            return {"deployed": False, "reason": "bait-exists", "bait_username": username}
    except Exception as e:
        logger.debug(f"honeypot existing check failed: {e}")

    try:
        from .apikey import generate_uid
        uid = generate_uid()
        try:
            fake_bal = float(configs.HONEYPOT_FAKE_BALANCE)
        except Exception:
            fake_bal = 0.0
        ttl_min = int(configs.HONEYPOT_TTL_MIN)
        expire = (datetime.now() + timedelta(minutes=ttl_min)).isoformat(timespec="seconds")

        await async_db_query(
            "INSERT INTO users (user_name, user_password, balence, uid, is_honeypot, "
            "is_admin, created_at, honeypot_expire_at) "
            "VALUES (?, ?, ?, ?, 1, 0, CURRENT_TIMESTAMP, ?)",
            (username, password_hash, fake_bal, uid, expire)
        )
        await async_db_query(
            """INSERT INTO honeypot_accounts
               (bait_username, target_username, attacker_ip, ja3_hash, user_agent,
                reason, created_at, last_seen, expires_at, is_disarmed)
               VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, 0)""",
            (username, username, client_ip, ja3_hash or "", user_agent or "", reason, expire)
        )
        logger.warning(f"蜜罐账号已布设: {username} (来源 {client_ip}, JA3 {ja3_hash})")
        return {"deployed": True, "bait_username": username, "uid": uid,
                "fake_balance": fake_bal, "expire_at": expire, "reason": reason}
    except Exception as e:
        logger.error(f"deploy_honeypot failed: {e}")
        return {"deployed": False, "error": str(e)}


async def maybe_bait(username: str, password_hash: str, client_ip: str,
                     ja3_hash: str, user_agent: str, is_automation: bool,
                     user_exists: bool) -> dict:
    """登录流程便捷判定：是否布设蜜罐。

    返回 deploy_honeypot 的结果（{deployed:False,...} 表示不布设）。
    """
    if not getattr(configs, "HONEYPOT_ENABLED", True):
        return {"deployed": False, "reason": "disabled"}
    if user_exists:
        if not getattr(configs, "HONEYPOT_ON_AUTOMATION_LOGIN", False):
            return {"deployed": False, "reason": "real-account-skip"}
        reason = "自动化登录真实账号（已开启诱捕）"
    else:
        if not getattr(configs, "HONEYPOT_ON_UNKNOWN_USER", True):
            return {"deployed": False, "reason": "unknown-skip"}
        if not is_automation:
            return {"deployed": False, "reason": "not-automation"}
        reason = "自动化程序尝试登录不存在的用户（疑似凭据填充/枚举）"
    return await deploy_honeypot(username, password_hash, client_ip, ja3_hash,
                                 user_agent, reason)


# ===========================================================================
# 判定与活动记录
# ===========================================================================
async def is_honeypot_account(username: str) -> bool:
    try:
        rows = await async_db_query(
            "SELECT is_honeypot FROM users WHERE user_name=?", (username,)
        )
        return bool(rows and rows[0].get("is_honeypot"))
    except Exception:
        return False


async def record_honeypot_activity(bait_username: str, action: str,
                                   client_ip: str, ja3_hash: str,
                                   detail: str = "") -> None:
    """记录蜜罐账号下的攻击者行为（全程留痕）。"""
    try:
        await record_security_event(
            async_db_query, "", bait_username,
            "honeypot_activity", "info", 0,
            [f"action={action}", f"ip={client_ip}", f"ja3={ja3_hash}", detail],
            client_ip,
            _dummy_device(), action_taken="monitored"
        )
        await async_db_query(
            "UPDATE honeypot_accounts SET last_seen=CURRENT_TIMESTAMP WHERE bait_username=?",
            (bait_username,)
        )
    except Exception as e:
        logger.debug(f"record_honeypot_activity failed: {e}")


def _dummy_device():
    from .security import DeviceInfo
    return DeviceInfo("unknown", "Unknown", "", "", "", "", False, [], "")


# ===========================================================================
# 列出 / 拆除 / 过期清理
# ===========================================================================
def list_honeypots(limit: int = 50) -> list:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT h.bait_username, h.target_username, h.attacker_ip, h.ja3_hash,
                      h.reason, h.created_at, h.last_seen, h.expires_at, h.is_disarmed,
                      u.balence
               FROM honeypot_accounts h
               LEFT JOIN users u ON u.user_name = h.bait_username
               ORDER BY h.created_at DESC LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error(f"list_honeypots failed: {e}")
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


async def disarm_honeypot(bait_username: str) -> dict:
    """拆除一个蜜罐：标记 disarmed 并删除诱饵账号（攻击者会话随之失效）。"""
    try:
        await async_db_query(
            "UPDATE honeypot_accounts SET is_disarmed=1 WHERE bait_username=?",
            (bait_username,)
        )
        # 删除诱饵用户（及其会话，避免残留登录）
        await async_db_query("DELETE FROM users WHERE user_name=? AND is_honeypot=1",
                             (bait_username,))
        await async_db_query("DELETE FROM sessions WHERE user_name=?", (bait_username,))
        logger.warning(f"蜜罐已拆除: {bait_username}")
        return {"disarmed": True, "bait_username": bait_username}
    except Exception as e:
        logger.error(f"disarm_honeypot failed: {e}")
        return {"disarmed": False, "error": str(e)}


async def expire_honeypots() -> int:
    """清理已过期的蜜罐账号。返回清理数量。"""
    try:
        now = _time.time()
        # honeypot_expire_at 在 users 表为 ISO 字符串；用 datetime 比较
        rows = await async_db_query(
            "SELECT bait_username, expires_at FROM honeypot_accounts "
            "WHERE is_disarmed=0 AND expires_at IS NOT NULL"
        )
        expired = []
        for r in rows:
            exp = r.get("expires_at")
            if not exp:
                continue
            try:
                if datetime.fromisoformat(str(exp)) < datetime.now():
                    expired.append(r["bait_username"])
            except Exception:
                continue
        for name in expired:
            await async_db_query(
                "UPDATE honeypot_accounts SET is_disarmed=1 WHERE bait_username=?", (name,)
            )
            await async_db_query(
                "DELETE FROM users WHERE user_name=? AND is_honeypot=1", (name,)
            )
            await async_db_query("DELETE FROM sessions WHERE user_name=?", (name,))
        if expired:
            logger.info(f"已清理 {len(expired)} 个过期蜜罐账号")
        return len(expired)
    except Exception as e:
        logger.error(f"expire_honeypots failed: {e}")
        return 0


def status() -> dict:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS c, SUM(is_disarmed) AS d FROM honeypot_accounts")
        row = cur.fetchone()
        active = (row["c"] if row else 0) - (row["d"] if row and row["d"] else 0)
        return {
            "enabled": getattr(configs, "HONEYPOT_ENABLED", True),
            "total": row["c"] if row else 0,
            "active": active,
            "on_unknown_user": getattr(configs, "HONEYPOT_ON_UNKNOWN_USER", True),
            "on_automation_login": getattr(configs, "HONEYPOT_ON_AUTOMATION_LOGIN", False),
            "ttl_min": int(configs.HONEYPOT_TTL_MIN),
            "max_per_ip": int(configs.HONEYPOT_MAX_PER_IP),
            "fake_balance": float(configs.HONEYPOT_FAKE_BALANCE),
        }
    except Exception:
        return {"enabled": getattr(configs, "HONEYPOT_ENABLED", True), "active": 0}
    finally:
        try:
            conn.close()
        except Exception:
            pass
