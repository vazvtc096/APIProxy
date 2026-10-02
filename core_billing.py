"""计费与余额：用量记录、原子扣费/退还、费用计算。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
import asyncio
import logging
from typing import Literal

from . import db
from . import configs
from . import pricing
from .apikey import generate_uid
from .constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR
from .core_db import _get_conn, async_db_query


def _ensure_real_token_columns():
    """幂等补列：上游真实 usage token（NULL = 该次请求未捕获到上游 usage）。

    与字符计费口径并存：input_tokens/output_tokens 继续存字符数（计费口径），
    real_prompt_tokens/real_completion_tokens 存上游返回的真实 token 数，
    供管理端做「字符估算 vs 真实 token」偏差校准报表。
    """
    try:
        conn = _get_conn()
        from . import db as _db
        if _db.is_postgres():
            conn.set_autocommit(True)
        cur = conn.cursor()
        for col in ('real_prompt_tokens', 'real_completion_tokens',
                    'real_reasoning_tokens', 'real_cache_hit_tokens'):
            try:
                cur.execute(f"ALTER TABLE usage_logs ADD COLUMN {col} INTEGER")
            except Exception:
                pass
        try:
            conn.commit()
        except Exception:
            pass
        conn.close()
    except Exception as e:
        logging.warning(f"ensure real token columns failed: {e}")


_ensure_real_token_columns()


async def _record_usage_log(owner: str, model: str, input_text: str, output_text: str,
                            total_cost: float, is_stream: bool, upstream_name: str,
                            status: str = 'success', endpoint: str = 'chat.completions',
                            real_prompt_tokens: int = None, real_completion_tokens: int = None,
                            real_reasoning_tokens: int = None, real_cache_hit_tokens: int = None):
    """写入一条用量与费用明细到 usage_logs（统计图表的数据源）

    input_tokens/output_tokens 存字符数（计费口径）；real_* 存上游真实
    token 数（未捕获到时为 NULL）：prompt/completion 为基本用量，
    reasoning 为推理思考量（completion 的子集），cache_hit 为缓存命中输入
    （prompt 的子集，按 token_billing.cache_hit_ratio 折扣计价）。
    """
    try:
        in_chars = len(input_text or '')
        out_chars = len(output_text or '')
        await async_db_query(
            """INSERT INTO usage_logs
               (log_id, user_uid, user_name, model, endpoint, input_tokens, output_tokens,
                total_tokens, cost, is_stream, status, upstream, created_at,
                real_prompt_tokens, real_completion_tokens,
                real_reasoning_tokens, real_cache_hit_tokens)
               SELECT ?, (SELECT uid FROM users WHERE user_name = ?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?""",
            ('ul_' + generate_uid(), owner, owner, model, endpoint,
             in_chars, out_chars, in_chars + out_chars,
             round(float(total_cost or 0.0), 6), 1 if is_stream else 0, status,
             upstream_name or '',
             int(real_prompt_tokens) if real_prompt_tokens is not None else None,
             int(real_completion_tokens) if real_completion_tokens is not None else None,
             int(real_reasoning_tokens) if real_reasoning_tokens is not None else None,
             int(real_cache_hit_tokens) if real_cache_hit_tokens is not None else None)
        )
    except Exception as e:
        logging.error(f'record usage_log failed: {e}')


async def async_db_update_balence(owner: str, new_balence: float):
    """更新余额（供 Worker 调用）
    不再使用密码作为查询条件，直接按用户名更新
    """
    def _update():
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET balence = ? WHERE user_name = ?",
                (new_balence, owner)
            )
            conn.commit()
    await asyncio.to_thread(_update)


def _atomic_pre_deduct_balence(owner: str, amount: float) -> tuple[bool, float, str]:
    """事务中原子预扣费（BEGIN IMMEDIATE 锁定行），防止并发竞态超支
    返回: (success, current_balance, message)
    - 检查当前余额，不足且不允许超支则拒绝
    - 超支超过限额则拒绝
    """
    if amount <= 0:
        return True, 0.0, "OK"
    conn = _get_conn()
    try:
        db.begin_write(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT balence, allow_overdraft, max_overdraft FROM users WHERE user_name = ?",
            (owner,)
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return False, 0.0, "User not found"
        balence = float(row['balence'] or 0.0)
        allow_od = bool(row['allow_overdraft'])
        max_od = float(row['max_overdraft'] or 0.0)
        new_balence = round(balence - amount, 6)
        overdraft = max(0.0, -new_balence)
        # 不允许超支且结果负 → 拒绝
        if not allow_od and new_balence < 0:
            conn.rollback()
            return False, balence, f"余额不足：需 {amount:.6f}，当前 {balence:.6f}"
        # 超支超过限额 → 拒绝
        if overdraft > max_od + 1e-9:
            conn.rollback()
            return False, balence, f"余额不足（超支超限）：需 {amount:.6f}，当前 {balence:.6f}，限额 {max_od:.6f}"
        cur.execute("UPDATE users SET balence = ? WHERE user_name = ?", (new_balence, owner))
        conn.commit()
        return True, new_balence, "OK"
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        return False, 0.0, f"扣费失败: {e}"
    finally:
        conn.close()


def _atomic_force_deduct_balence(owner: str, amount: float) -> float:
    """事务中原子强制扣费（输出已产生，必须扣），BEGIN IMMEDIATE 锁定行
    返回扣费后的余额
    """
    if amount <= 0:
        return 0.0
    conn = _get_conn()
    try:
        db.begin_write(conn)
        cur = conn.cursor()
        cur.execute("SELECT balence FROM users WHERE user_name = ?", (owner,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return 0.0
        balence = float(row['balence'] or 0.0)
        new_balence = round(balence - amount, 6)
        cur.execute("UPDATE users SET balence = ? WHERE user_name = ?", (new_balence, owner))
        conn.commit()
        return new_balence
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logging.error(f"Force deduct failed for {owner}: {e}")
        return 0.0
    finally:
        conn.close()


def _atomic_add_balence(owner: str, amount: float) -> float:
    """事务中原子退还余额（API 调用失败时回退预扣费用），BEGIN IMMEDIATE 锁定行
    返回退还后的余额
    """
    if amount <= 0:
        return 0.0
    conn = _get_conn()
    try:
        db.begin_write(conn)
        cur = conn.cursor()
        cur.execute("SELECT balence FROM users WHERE user_name = ?", (owner,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return 0.0
        balence = float(row['balence'] or 0.0)
        new_balence = round(balence + amount, 6)
        cur.execute("UPDATE users SET balence = ? WHERE user_name = ?", (new_balence, owner))
        conn.commit()
        return new_balence
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logging.error(f"Add balence failed for {owner}: {e}")
        return 0.0
    finally:
        conn.close()


def _token_based_cost(model: str, upstream_name: str, real_in, real_out,
                      cache_hit) -> float | None:
    """按上游真实 usage 计算费用（每百万 token 口径，复用 pricing 时段/DB 兜底价）。

    - 输入：(real_in - cache_hit) + cache_hit * cache_hit_ratio
      （缓存命中输入按折扣计，DeepSeek 缓存命中价约为未命中 1/10）
    - 输出：real_out（reasoning_tokens 已包含在 completion_tokens 内，无需另算）
    - TOKEN_BILLING.enabled 为 False 或缺少真实 usage 时返回 None（沿用字符计费）。
    """
    tb = getattr(configs, 'TOKEN_BILLING', None) or {}
    if not tb.get('enabled'):
        return None
    if real_in is None and real_out is None:
        return None
    try:
        ratio = float(tb.get('cache_hit_ratio', 0.1) or 0.1)
        ratio = min(max(ratio, 0.0), 1.0)
        rin = max(0, int(real_in or 0))
        rout = max(0, int(real_out or 0))
        chit = min(max(0, int(cache_hit or 0)), rin)   # 命中数不能超过输入总量
        eff_in = (rin - chit) + chit * ratio
        in_price, out_price = pricing.resolve_price(model, upstream_name)
        return round((eff_in * in_price + rout * out_price) / 1_000_000.0, 6)
    except Exception as e:
        logging.error(f"token-based cost calc failed for {model}: {e}")
        return None


def reconcile_token_billing(owner: str, model: str, upstream_name: str,
                            real_in, real_out, cache_hit,
                            charged_cost: float, mult: float = 1.0) -> dict | None:
    """真实 token 计费对账：响应完成后按真实 usage 多退少补。

    - charged_cost: 已按字符口径扣掉的总费用（含分组倍率）
    - 返回 {'token_cost', 'delta', 'effective_cost', 'balance'}；
      未启用/无真实 usage/差额可忽略时返回 None（保持字符计费结果）。
    - 幂等旁路：任何异常只记日志不抛出，绝不影响主链路。
    """
    try:
        tc = _token_based_cost(model, upstream_name, real_in, real_out, cache_hit)
        if tc is None:
            return None
        if mult != 1.0:
            tc = round(tc * mult, 6)
        delta = round(tc - float(charged_cost or 0.0), 6)
        if abs(delta) < 1e-6:
            return None
        if delta > 0:
            balance = _atomic_force_deduct_balence(owner, delta)
        else:
            balance = _atomic_add_balence(owner, -delta)
        logging.info(f"token billing reconcile {owner}/{model}: char={charged_cost} "
                     f"token={tc} delta={delta}")
        return {'token_cost': tc, 'delta': delta,
                'effective_cost': round(float(charged_cost or 0.0) + delta, 6),
                'balance': balance}
    except Exception as e:
        logging.error(f"token billing reconcile failed for {owner}: {e}")
        return None


def _calculate_cost(content: str, model: str, type: Literal["input", "output"] = "input",
                   upstream_name: str = None) -> float:
    total = 0.0
    lookup = CHAR_PRICE_LOOKUP
    unexcept = UNEXCEPT_CHAR
    for ch in content:
        code = ord(ch)
        if code < 0x10000:
            total += lookup[code]
        else:
            total += unexcept
    million_total = total / 1_000_000.0
    in_price, out_price = pricing.resolve_price(model, upstream_name)
    money_per_million = in_price if type == "input" else out_price
    return round(million_total * money_per_million, 6)
