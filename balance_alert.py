"""余额预警：扣费后余额低于阈值时，给用户发站内通知 + 邮件。

设计要点：
- 触发点在各计费路径扣费落点（core_tasks 三条路径），属热路径旁路，
  任何异常都吞掉记日志，绝不影响主链路。
- 冷却期去重用 cache_store（Redis/集群共享），同一用户在 cooldown_hours
  内只提醒一次，防止低余额用户每次请求都被轰炸。
- 余额不低于阈值（含负数已低于）只在跨过阈值时提醒——判断即
  new_balance < threshold；冷却期负责抑制重复。
"""
import logging

from . import configs


def _cache():
    from . import cache_store
    return cache_store.get_cache()


async def maybe_alert(owner: str, new_balance: float) -> bool:
    """余额低于阈值时提醒（站内 + 可选邮件）。返回是否实际发出了提醒。

    owner: 用户名；new_balance: 本次扣费后的最新余额（¥）。
    """
    cfg = getattr(configs, 'BALANCE_ALERT', None) or {}
    if not cfg.get('enabled'):
        return False
    threshold = float(cfg.get('threshold') or 0)
    if threshold <= 0 or new_balance is None or float(new_balance) >= threshold:
        return False

    # 冷却期去重（检查 + 占位在同一把锁语义下不严格原子，最多重复提醒一次，可接受）
    cache = _cache()
    key = f"bal:alert:{owner}"
    try:
        if cache.get(key) is not None:
            return False
        cooldown = int(cfg.get('cooldown_hours') or 24)
        cache.set(key, '1', cooldown * 3600)
    except Exception as e:
        logging.warning(f"balance alert dedup failed (continue): {e}")

    # 查 uid + email
    uid = email = None
    try:
        from . import db
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT uid, email FROM users WHERE user_name = ?", (owner,))
            row = cur.fetchone()
            if row:
                d = dict(row) if not isinstance(row, dict) else row
                uid, email = d.get('uid'), d.get('email')
        finally:
            conn.close()
    except Exception as e:
        logging.error(f"balance alert user lookup failed for {owner}: {e}")

    bal_str = f"{float(new_balance):.4f}"
    title = f"余额不足提醒：当前 {bal_str} 元"
    body = (f"您的账户余额已低于 {threshold:.2f} 元（当前 {bal_str} 元），"
            f"请及时充值，以免影响 API 调用。")

    # 站内通知
    if uid:
        try:
            from . import notifications
            await notifications.add_notification(uid, title, body, level='warning',
                                                 link='/dashboard')
        except Exception as e:
            logging.error(f"balance alert notification failed for {owner}: {e}")

    # 邮件（可选；SMTP 未配置时 email_utils 会自行拒绝）
    if cfg.get('email', True) and email:
        try:
            import asyncio
            from .email_utils import send_low_balance_email
            await asyncio.to_thread(send_low_balance_email, email, owner,
                                    float(new_balance), threshold)
        except Exception as e:
            logging.error(f"balance alert email failed for {owner}: {e}")

    # QQ 推送（NapCat；推给管理端配置的接收人，与站内/邮件互不影响）
    try:
        from . import notify
        notify.notify('余额预警',
                      f"用户 {owner} 余额 {bal_str} 元，已低于阈值 {threshold:.2f} 元")
    except Exception as e:
        logging.error(f"balance alert napcat push failed: {e}")

    logging.info(f"balance alert sent to {owner} (balance={bal_str}, threshold={threshold})")
    return True
