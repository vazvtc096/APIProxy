# -*- coding: utf-8 -*-
"""套餐 / 订阅（花账户余额）。

- subscription_plans：套餐定义（价格、周期、权益），由管理员维护，首次初始化写入默认三档。
- user_subscriptions：用户生效中的订阅，按 expires_at 判定是否在期内。
- 订阅即「从账户余额扣费 → 写入/续期一条 active 订阅」，全程单事务原子完成，
  余额不足（含超支限额）则整体回滚，绝不产生「扣了钱没订阅」的中间态。
"""
import json
import logging
import time

from . import db
from .core_db import _get_conn, async_db_query

logger = logging.getLogger('subscription')

__all__ = [
    'get_plans', 'get_plan', 'get_active_subscription', 'list_my_subscriptions',
    'subscribe', 'cancel_subscription',
]

_DEFAULT_PLANS = [
    {'id': 'free', 'name': '体验版', 'description': '零门槛体验全部基础能力', 'price': 0.0,
     'period_days': 30, 'features': ['基础模型访问', '社区支持', '标准速率'], 'active': 1},
    {'id': 'standard', 'name': '标准版', 'description': '个人高频使用的均衡之选', 'price': 30.0,
     'period_days': 30, 'features': ['全部模型访问', '更高并发额度', '优先工单支持'], 'active': 1},
    {'id': 'pro', 'name': '专业版', 'description': '团队与生产环境的强力支撑', 'price': 99.0,
     'period_days': 30, 'features': ['全部模型与高配额', '最高并发', 'API 优先支持', '专属客服通道'], 'active': 1},
]


def _parse_features(raw) -> list:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else [str(v)]
    except Exception:
        return [str(raw)]


async def get_plans(only_active: bool = True) -> list:
    sql = "SELECT * FROM subscription_plans"
    if only_active:
        sql += " WHERE active = 1"
    sql += " ORDER BY price ASC, id ASC"
    rows = await async_db_query(sql)
    out = []
    for r in rows:
        r = dict(r)
        r['features'] = _parse_features(r.get('features'))
        out.append(r)
    return out


async def get_plan(plan_id: str) -> dict | None:
    rows = await async_db_query("SELECT * FROM subscription_plans WHERE id = ?", (plan_id,))
    if not rows:
        return None
    r = dict(rows[0])
    r['features'] = _parse_features(r.get('features'))
    return r


async def list_my_subscriptions(user_name: str) -> list:
    now = int(time.time())
    rows = await async_db_query(
        "SELECT s.*, p.name AS plan_name, p.features AS plan_features, p.price AS plan_price "
        "FROM user_subscriptions s JOIN subscription_plans p ON s.plan_id = p.id "
        "WHERE s.user_name = ? ORDER BY s.expires_at DESC", (user_name,))
    out = []
    for r in rows:
        r = dict(r)
        r['features'] = _parse_features(r.get('plan_features'))
        r['is_active'] = (r.get('status') == 'active' and int(r.get('expires_at') or 0) > now)
        out.append(r)
    return out


async def get_active_subscription(user_name: str) -> dict | None:
    now = int(time.time())
    rows = await async_db_query(
        "SELECT s.*, p.name AS plan_name, p.features AS plan_features, p.price AS plan_price "
        "FROM user_subscriptions s JOIN subscription_plans p ON s.plan_id = p.id "
        "WHERE s.user_name = ? AND s.status = 'active' AND s.expires_at > ? "
        "ORDER BY s.expires_at DESC LIMIT 1", (user_name, now))
    if not rows:
        return None
    r = dict(rows[0])
    r['features'] = _parse_features(r.get('plan_features'))
    return r


async def subscribe(user_name: str, plan_id: str) -> tuple:
    """订阅套餐：从余额扣费并写入/续期订阅。返回 (ok, msg, subscription_dict|None)。

    余额不足（含超支超限）时整体回滚，不产生中间态。已生效的同套餐订阅会被顺延周期。
    """
    plan = await get_plan(plan_id)
    if not plan or not int(plan.get('active') or 0):
        return False, '套餐不存在或已下架', None
    price = round(float(plan.get('price') or 0.0), 6)
    period_days = int(plan.get('period_days') or 30)
    now = int(time.time())
    expires = now + period_days * 86400

    conn = _get_conn()
    existing = None
    try:
        db.begin_write(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT balence, allow_overdraft, max_overdraft FROM users WHERE user_name = ?",
            (user_name,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return False, '用户不存在', None
        bal = float(row['balence'] or 0.0)
        allow_od = bool(row['allow_overdraft'])
        max_od = float(row['max_overdraft'] or 0.0)
        new_bal = round(bal - price, 6)
        overdraft = max(0.0, -new_bal)
        if not allow_od and new_bal < 0:
            conn.rollback()
            return False, f'余额不足：需 ¥{price:.2f}，当前 ¥{bal:.2f}', None
        if overdraft > max_od + 1e-9:
            conn.rollback()
            return False, f'余额不足（超支超限）：需 ¥{price:.2f}，当前 ¥{bal:.2f}，限额 ¥{max_od:.2f}', None
        cur.execute("UPDATE users SET balence = ? WHERE user_name = ?", (new_bal, user_name))

        # 已有同套餐生效订阅 → 顺延；否则新建
        cur.execute(
            "SELECT id, expires_at FROM user_subscriptions "
            "WHERE user_name = ? AND plan_id = ? AND status = 'active' AND expires_at > ?",
            (user_name, plan_id, now))
        existing = cur.fetchone()
        if existing:
            new_expires = int(existing['expires_at']) + period_days * 86400
            cur.execute(
                "UPDATE user_subscriptions SET expires_at = ?, updated_at = ? WHERE id = ?",
                (new_expires, now, existing['id']))
        else:
            cur.execute(
                "INSERT INTO user_subscriptions "
                "(user_uid, user_name, plan_id, started_at, expires_at, status, auto_renew, created_at) "
                "VALUES ((SELECT uid FROM users WHERE user_name = ?), ?, ?, ?, ?, 'active', 0, ?)",
                (user_name, user_name, plan_id, now, expires, now))
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.error(f"subscribe failed for {user_name}/{plan_id}: {e}")
        return False, f'订阅失败：{e}', None
    finally:
        conn.close()

    sub = await get_active_subscription(user_name)
    return True, '订阅成功' + ('（已续期）' if existing else ''), sub


async def cancel_subscription(user_name: str, sub_id: int | None = None) -> tuple:
    """取消订阅：仅终止未来权益（不退款），已付周期内的权益保留到 expires_at。"""
    if sub_id:
        await async_db_query(
            "UPDATE user_subscriptions SET status = 'cancelled', auto_renew = 0, updated_at = ? "
            "WHERE id = ? AND user_name = ?", (int(time.time()), sub_id, user_name))
    else:
        await async_db_query(
            "UPDATE user_subscriptions SET status = 'cancelled', auto_renew = 0, updated_at = ? "
            "WHERE user_name = ? AND status = 'active'", (int(time.time()), user_name))
    return True, '已取消订阅（当前周期权益保留至到期）', None
