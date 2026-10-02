"""用户级月度消费预算（对齐 NewAPI 的用户维度花费上限）。

与令牌级 quota（apikeys.used）互补：令牌额度管单个 Key，本模块管用户整体——
- monthly_budget  本月消费上限（¥），0 = 不限
- budget_spent    本月已消费累计（自然月，跨月自动清零）
- budget_month    累计所属月份（'YYYY-MM'），与 budget_spent 同行更新

语义（与 tokenpolicy 一致的软限制）：
- 请求入口（core_tasks 三条计费路径预扣费前）调用 check_owner，超限抛
  ValueError -> 客户端收到 400 业务错误；单次请求可能略超预算（当次不回滚），
  超限在下次请求拦截。
- 计费落点调用 accrue_usage，把本次 total_cost 累计进当月；
  原子单语句 UPDATE（CASE 判月），无读-改-写竞态。
"""
import logging

from . import db


def _get_conn():
    return db.get_conn()


_BUDGET_COLUMNS = (
    ("monthly_budget", "REAL DEFAULT 0"),
    ("budget_spent", "REAL DEFAULT 0"),
    ("budget_month", "TEXT DEFAULT ''"),
)


def ensure_budget_columns():
    """幂等补列（PG 抛 DuplicateColumn / SQLite 抛 OperationalError 均吞掉）"""
    conn = _get_conn()
    if db.is_postgres():
        conn.set_autocommit(True)
    cur = conn.cursor()
    for col, defn in _BUDGET_COLUMNS:
        try:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
        except Exception:
            pass
    try:
        conn.commit()
    except Exception:
        pass
    conn.close()


ensure_budget_columns()


def current_month() -> str:
    import datetime
    return datetime.datetime.now().strftime('%Y-%m')


def get_budget(owner: str) -> dict:
    """读取用户预算与本月消费（跨月时返回的 spent 视为 0，但不落库——
    落库重置由 check/accrue 顺带完成，避免只读路径写库）"""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT monthly_budget, budget_spent, budget_month "
            "FROM users WHERE user_name = ?", (owner,))
        row = cur.fetchone()
        if not row:
            return {}
        d = dict(row)
        spent = float(d.get('budget_spent') or 0.0)
        if (d.get('budget_month') or '') != current_month():
            spent = 0.0
        return {
            'monthly_budget': float(d.get('monthly_budget') or 0.0),
            'budget_spent': round(spent, 6),
            'budget_month': current_month(),
        }
    finally:
        conn.close()


def set_budget(owner: str, value) -> tuple:
    """设置月度预算。value<=0 或空 = 取消限制。返回 (ok, err)。"""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False, 'monthly_budget must be a number'
    if v != v or v in (float('inf'), float('-inf')):
        return False, 'monthly_budget must be a finite number'
    v = max(0.0, round(v, 6))
    if v > 1e9:
        return False, 'monthly_budget too large (max 1e9)'
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET monthly_budget = ? WHERE user_name = ?",
                        (v, owner))
            conn.commit()
            if cur.rowcount == 0:
                conn.rollback()
                return False, 'user not found'
        return True, ''
    finally:
        conn.close()


def check_owner(owner: str) -> tuple:
    """校验用户本月消费是否超预算。返回 (ok, reason)；reason 空串 = 通过。
    跨月自动清零 budget_spent（落库）。"""
    if not owner:
        return True, ''
    try:
        conn = _get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT monthly_budget, budget_spent, budget_month "
                "FROM users WHERE user_name = ?", (owner,))
            row = cur.fetchone()
        finally:
            conn.close()
        if not row:
            return True, ''
        d = dict(row)
        budget = float(d.get('monthly_budget') or 0.0)
        if budget <= 0:
            return True, ''
        cur_month = current_month()
        spent = float(d.get('budget_spent') or 0.0)
        if (d.get('budget_month') or '') != cur_month:
            spent = 0.0
            _reset_month(owner, cur_month)
        if spent >= budget:
            return False, (f"monthly budget exceeded: spent {spent:.4f} / "
                           f"budget {budget:.4f} CNY this month ({cur_month})")
        return True, ''
    except Exception as e:
        # 预算层故障不阻断主链路（与令牌策略层 fail-open 一致）
        logging.warning(f"budget.check_owner failed (fail-open): {e}")
        return True, ''


def _reset_month(owner: str, cur_month: str):
    """跨月清零（幂等，best-effort）。"""
    try:
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET budget_spent = 0, budget_month = ? "
                "WHERE user_name = ? AND (budget_month IS NULL OR budget_month != ?)",
                (cur_month, owner, cur_month))
            conn.commit()
    except Exception as e:
        logging.warning(f"budget month reset failed for {owner}: {e}")


def check_or_raise(owner: str):
    """供 core_tasks 调用：超预算抛 ValueError（业务错误 -> 客户端 400）。"""
    ok, reason = check_owner(owner)
    if not ok:
        raise ValueError(reason)


def accrue_usage(owner: str, cost: float):
    """把一次请求的费用累计进当月消费（原子单语句，跨月自动换月重算）。

    SQL 用 CASE 判月：同行 budget_month 已是当月则累加，否则以本次费用
    作为新月起点——无需读-改-写，天然并发安全。
    """
    if not owner or not cost:
        return
    try:
        cur_month = current_month()
        cost = round(float(cost), 6)
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET "
                "budget_spent = CASE WHEN budget_month = ? "
                "  THEN COALESCE(budget_spent, 0) + ? ELSE ? END, "
                "budget_month = ? "
                "WHERE user_name = ?",
                (cur_month, cost, cost, cur_month, owner))
            conn.commit()
    except Exception as e:
        logging.error(f"budget.accrue_usage failed for {owner}: {e}")
