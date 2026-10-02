# -*- coding: utf-8 -*-
"""按时段计费解析。

配置来源：configs.PRICING
  pricing:
    default: {input, output}                 # 未配置模型的兜底单价（每百万 token）
    models:
      <model>:
        input: ...                            # 统一单价
        output: ...
        schedules:                           # 可选：按时段切换（命中优先于 input/output）
          - start: "HH:MM:SS"
            end:   "HH:MM:SS"
            input: ...
            output: ...
      "<model>@<upstream>":                  # 可选：绑定特定上游 Key 的专属单价

解析规则：
  - 先试 <model>@<upstream_name>（若传入上游名），再试 <model>，最后兜底 default。
  - 含 schedules：取「当前本地时间」命中的第一个时段价；都不命中则用该模型的 input/output 兜底价。
  - 时段支持跨午夜（start > end 视为 wrap，如 22:00:00-06:00:00）。
  - 配置中完全没有该模型时，回退到 DB model_prices（管理员定价表，无时段），再回退 default。
"""
import time
import json
import logging

from . import configs

# 兜底（与历史 UNEXCEPT_MODEL 一致）
_FALLBACK = {"input": 2.0, "output": 4.0}


def _parse_hms(s) -> int:
    """'HH:MM:SS' 或 'HH:MM' -> 当日秒数；解析失败返回 -1。"""
    if s is None:
        return -1
    s = str(s).strip()
    parts = s.split(":")
    try:
        h, m = int(parts[0]), int(parts[1])
        sec = int(parts[2]) if len(parts) > 2 else 0
        return h * 3600 + m * 60 + sec
    except (ValueError, IndexError):
        return -1


def _in_window(now_sec: int, start_sec: int, end_sec: int) -> bool:
    """判断 now_sec 是否落在 [start, end]；支持跨午夜（start > end）。"""
    if start_sec < 0 or end_sec < 0:
        return False
    if start_sec <= end_sec:
        return start_sec <= now_sec <= end_sec
    # 跨午夜：22:00:00 - 06:00:00
    return now_sec >= start_sec or now_sec <= end_sec


def _num(v, default):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _holiday_today(now) -> bool:
    """今天是否命中 pricing.holidays（YYYY-MM-DD 一次性 / MM-DD 每年循环）。"""
    holidays = (configs.PRICING or {}).get("holidays") or []
    if not isinstance(holidays, list):
        return False
    today = time.strftime("%Y-%m-%d", now)
    month_day = time.strftime("%m-%d", now)
    for h in holidays:
        h = str(h).strip()
        if h and h in (today, month_day):
            return True
    return False


def _match_schedules(entry: dict, now):
    """遍历 schedules，返回第一个命中时段的 (input, output, tier)；无命中返回 None。

    - sch.days: 可选 [0..6]（周一=0），缺省每天生效；
    - 全局 pricing.holidays 命中当天 -> 跳过所有时段（落到 base 价，即空闲/谷价）。
    """
    now_sec = now.tm_hour * 3600 + now.tm_min * 60 + now.tm_sec
    base_in = _num(entry.get("input"), _FALLBACK["input"])
    base_out = _num(entry.get("output"), _FALLBACK["output"])
    schedules = entry.get("schedules")
    if not isinstance(schedules, list) or _holiday_today(now):
        return None
    for sch in schedules:
        if not isinstance(sch, dict):
            continue
        days = sch.get("days")
        if isinstance(days, list) and days:
            try:
                allow = {int(d) for d in days}
            except (TypeError, ValueError):
                allow = None
            if allow is not None and now.tm_wday not in allow:
                continue
        s = _parse_hms(sch.get("start"))
        e = _parse_hms(sch.get("end"))
        if _in_window(now_sec, s, e):
            inp = _num(sch.get("input"), base_in)
            outp = _num(sch.get("output"), base_out)
            tier = "peak" if (inp > base_in or outp > base_out) else "offpeak"
            return inp, outp, tier
    return None


def _resolve_entry(entry: dict, now):
    """从单个模型计费条目解析出 (input, output)。entry 可能含 schedules。"""
    if not isinstance(entry, dict):
        return None
    hit = _match_schedules(entry, now)
    if hit is not None:
        return hit[0], hit[1]
    # 无时段命中 -> 用该条目 base input/output
    if "input" in entry or "output" in entry:
        return _num(entry.get("input"), _FALLBACK["input"]), _num(entry.get("output"), _FALLBACK["output"])
    return None


def _db_price(model: str):
    """回退：从 DB model_prices 表取（管理员定价，无时段）。返回 (input, output) 或 None。"""
    try:
        from . import db
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT input, output FROM model_prices WHERE model = ? AND priced = 1",
                (model,),
            )
            row = cur.fetchone()
            if row:
                return _num(row["input"], _FALLBACK["input"]), _num(row["output"], _FALLBACK["output"])
        finally:
            conn.close()
    except Exception as e:
        logging.debug(f"pricing DB fallback failed for {model}: {e}")
    return None


def reload_pricing_from_db():
    """从 DB 加载时段计费与节假日，合并进 configs.PRICING（热加载，无 DB 表则保留 yaml 原值）。

    - pricing_schedules：对 DB 中有行的模型，用 DB schedules（含 days 生效星期）覆盖
      configs.PRICING 中同模型的 schedules；DB 无行的模型保留 config.yaml 原值。
    - pricing_holidays：有表则以 DB 为准整体覆盖 configs.PRICING['holidays']；无表保留 yaml。
    - 返回加载的 schedule 行数（-1 表示表不存在或读取失败）。
    """
    try:
        from . import db
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                'SELECT model, "start", "end", input, output, enabled, days FROM pricing_schedules'
            )
            rows = cur.fetchall()
            try:
                cur.execute("SELECT day FROM pricing_holidays ORDER BY day ASC")
                hol_rows = [r["day"] for r in cur.fetchall()]
            except Exception:
                hol_rows = None  # 表不存在：保留 config.yaml 的 holidays
        finally:
            conn.close()
    except Exception as e:
        logging.debug(f"reload_pricing_from_db: table missing or error: {e}")
        return -1

    pricing = configs.PRICING
    if not isinstance(pricing, dict):
        configs.PRICING = {}
        pricing = configs.PRICING
    models = pricing.setdefault("models", {})

    # 节假日（DB 为准）
    if hol_rows is not None:
        pricing["holidays"] = [str(h) for h in hol_rows if str(h or "").strip()]

    # 按模型分组
    by_model = {}
    for r in rows:
        m = r["model"]
        if m not in by_model:
            by_model[m] = []
        if r["enabled"]:
            sch = {
                "start": r["start"],
                "end": r["end"],
                "input": r["input"],
                "output": r["output"],
            }
            # days：JSON 数组字符串（[0..6]，周一=0）；NULL/解析失败 = 每天生效
            days_raw = None
            try:
                days_raw = r["days"]
            except (KeyError, IndexError):
                days_raw = None
            if days_raw:
                try:
                    _d = json.loads(days_raw) if isinstance(days_raw, str) else days_raw
                    if isinstance(_d, list):
                        _d = sorted({int(x) for x in _d if 0 <= int(x) <= 6})
                        if _d:
                            sch["days"] = _d
                except (ValueError, TypeError):
                    pass
            by_model[m].append(sch)

    # 合并：DB 有行的模型 -> 覆盖；config.yaml 保留 base input/output
    for m, scheds in by_model.items():
        if m not in models or not isinstance(models[m], dict):
            models[m] = {"schedules": scheds}
        else:
            models[m]["schedules"] = scheds

    logging.info(f"reload_pricing_from_db: loaded {len(rows)} schedule rows for {len(by_model)} models")
    return len(rows)


def resolve_price(model: str, upstream_name: str = None, now=None):
    """返回 (input_per_million, output_per_million)。

    - model: 模型名（必填）
    - upstream_name: 命中配置中的 <model>@<upstream> 专属价（可选）
    - now: time.struct_time（本地），默认 time.localtime()
    """
    if now is None:
        now = time.localtime()

    pricing = configs.PRICING or {}
    models = pricing.get("models") or {}

    # 1) 绑定上游的专属价（命中优先）
    if upstream_name:
        entry = models.get(f"{model}@{upstream_name}")
        if entry is not None:
            r = _resolve_entry(entry, now)
            if r is not None:
                return r

    # 2) 通用模型价
    entry = models.get(model)
    if entry is not None:
        r = _resolve_entry(entry, now)
        if r is not None:
            return r

    # 3) DB 管理员定价兜底
    db = _db_price(model)
    if db is not None:
        return db

    # 4) 全局 default
    default = pricing.get("default") or _FALLBACK
    return _num(default.get("input"), _FALLBACK["input"]), _num(default.get("output"), _FALLBACK["output"])


def resolve_price_tier(model: str, upstream_name: str = None, now=None):
    """返回 (input_per_million, output_per_million, tier)。

    tier:
      - 'peak'    ：命中 schedules 中价格高于 base 的时段（峰价）
      - 'offpeak' ：命中 schedules 中价格低于 base 的时段（谷价）
      - None      ：该模型无 schedules（或配置缺失），用 base/default 价，无峰谷区分
    - now: time.struct_time（本地），默认 time.localtime()
    """
    if now is None:
        now = time.localtime()

    pricing = configs.PRICING or {}
    models = pricing.get("models") or {}

    entry = None
    if upstream_name:
        e = models.get(f"{model}@{upstream_name}")
        if isinstance(e, dict):
            entry = e
    if entry is None:
        e = models.get(model)
        if isinstance(e, dict):
            entry = e

    # 模型未配置 -> 回退 DB / default（无时段概念）
    if not isinstance(entry, dict):
        db = _db_price(model)
        if db is not None:
            return db[0], db[1], None
        default = pricing.get("default") or _FALLBACK
        return (_num(default.get("input"), _FALLBACK["input"]),
                _num(default.get("output"), _FALLBACK["output"]), None)

    base_in = _num(entry.get("input"), _FALLBACK["input"])
    base_out = _num(entry.get("output"), _FALLBACK["output"])

    hit = _match_schedules(entry, now)
    if hit is not None:
        return hit

    # 无时段命中 -> base 价（无峰谷）
    return base_in, base_out, None


def current_tier_label(tier):
    """把 tier 转换为中文标签。"""
    return {"peak": "峰价", "offpeak": "谷价", None: "标准价"}.get(tier, "标准价")
