"""定时任务调度器单元测试（纯逻辑，不涉及真实 DB）。"""
import datetime

import pytest

from APIProxy import scheduler as sched

# 基线取一个明确的星期五，便于验证「日/周」语义
BASE = datetime.datetime(2026, 10, 16, 10, 30)


def test_calculate_next_run_once_is_none():
    now = datetime.datetime(2026, 1, 1, 0, 0)
    assert sched.calculate_next_run("once", now) is None


def test_calculate_next_run_intervals():
    now = datetime.datetime(2026, 1, 1, 0, 0)
    assert sched.calculate_next_run("minute", now) == now + datetime.timedelta(minutes=1)
    assert sched.calculate_next_run("hourly", now) == now + datetime.timedelta(hours=1)
    assert sched.calculate_next_run("daily", now) == now + datetime.timedelta(days=1)
    assert sched.calculate_next_run("weekly", now) == now + datetime.timedelta(weeks=1)
    assert sched.calculate_next_run("monthly", now) == now + datetime.timedelta(days=30)


def test_calculate_next_run_unknown_returns_none():
    now = datetime.datetime(2026, 1, 1, 0, 0)
    assert sched.calculate_next_run("bogus", now) is None


# ============================================================================
# cron 表达式
# 回归背景：calculate_next_run 的 cron 分支曾为占位实现，无论表达式写什么
# 一律返回「当前时间 + 1 分钟」，导致用户配 `0 9 * * *`（每天 9 点）实际被
# 当成每分钟执行；而 Java 侧 SchedulerService 用的是 Spring CronExpression，
# 两边语义不一致。以下用例锁定真解析后的行为。
# ============================================================================

def test_cron_requires_expression():
    """cron 频率缺少表达式时返回 None，而不是静默按每分钟跑。"""
    now = datetime.datetime(2026, 1, 1, 0, 0)
    assert sched.calculate_next_run("cron", now) is None
    assert sched.calculate_next_run("cron", now, "") is None
    assert sched.calculate_next_run("cron", now, "   ") is None


def test_cron_invalid_expression_degrades_without_raising():
    """非法表达式降级为 None（仅记 warning），不能把调度线程炸掉。"""
    assert sched.calculate_next_run("cron", BASE, "not a cron") is None
    assert sched.calculate_next_run("cron", BASE, "60 * * * *") is None
    assert sched.calculate_next_run("cron", BASE, "* * *") is None


@pytest.mark.parametrize("expr,expected", [
    # 每天 9:00 —— 基线 10:30 已过，滚到次日
    ("0 9 * * *", datetime.datetime(2026, 10, 17, 9, 0)),
    # 每 15 分钟
    ("*/15 * * * *", datetime.datetime(2026, 10, 16, 10, 45)),
    # 每月 1 号 0 点
    ("0 0 1 * *", datetime.datetime(2026, 11, 1, 0, 0)),
    # 每周一 2:30
    ("30 2 * * MON", datetime.datetime(2026, 10, 19, 2, 30)),
    # 工作日 9:00（基线是周五且 9 点已过 → 下周一）
    ("0 9 * * 1-5", datetime.datetime(2026, 10, 19, 9, 0)),
    # 周日 0 点
    ("0 0 * * SUN", datetime.datetime(2026, 10, 18, 0, 0)),
    # 周字段 7 等价于周日（对齐 Spring 语义）
    ("0 9 * * 7", datetime.datetime(2026, 10, 18, 9, 0)),
    # 逗号列表
    ("5,35 * * * *", datetime.datetime(2026, 10, 16, 10, 35)),
    # 6 字段（含秒）兼容 Spring/Quartz 习惯，秒段不参与计算
    ("0 0 0 1 * *", datetime.datetime(2026, 11, 1, 0, 0)),
])
def test_cron_next_run_matches(expr, expected):
    assert sched.cron_next_run(expr, BASE) == expected


def test_cron_handles_leap_day():
    """2 月 29 日只在闰年命中，搜索必须有界、不能死循环。"""
    assert sched.cron_next_run("0 0 29 2 *", BASE) == datetime.datetime(2028, 2, 29, 0, 0)


def test_cron_next_run_is_strictly_after():
    """已命中时刻必须严格向后推进，否则任务会在原地反复触发。"""
    t = datetime.datetime(2026, 10, 17, 9, 0)
    assert sched.cron_next_run("0 9 * * *", t) == datetime.datetime(2026, 10, 18, 9, 0)


def test_cron_next_run_normalizes_seconds():
    t = datetime.datetime(2026, 10, 16, 10, 30, 45, 123456)
    assert sched.cron_next_run("*/15 * * * *", t) == datetime.datetime(2026, 10, 16, 10, 45)


def test_cron_day_and_weekday_are_or_combined():
    """日字段与周字段同时受限时取「或」（Unix 经典语义）。"""
    # 每月 1 号 或 每周一 → 10-19（周一）比 11-01（1 号）更近
    assert sched.cron_next_run("0 0 1 * MON", BASE) == datetime.datetime(2026, 10, 19, 0, 0)


@pytest.mark.parametrize("bad", [
    "", "* * *", "60 * * * *", "* 25 * * *", "0 0 32 * *",
    "0 0 * 13 *", "0 0 * * 8", "*/0 * * * *", "a b c d e", "0 9 * * FOO",
])
def test_parse_cron_rejects_invalid(bad):
    with pytest.raises(sched.CronError):
        sched.parse_cron(bad)


def test_parse_cron_normalizes_weekday_7_to_sunday():
    spec = sched.parse_cron("0 0 * * 7")
    assert spec["weekday"] == {0}
    assert spec["day_restricted"] is False
    assert spec["weekday_restricted"] is True


def test_cron_is_in_valid_frequencies_whitelist():
    """cron 必须在 create_task 的频率白名单里，否则前端选了也被 400 拒掉。"""
    src = open("E:/Code/APIProxy/scheduler.py", encoding="utf-8").read()
    whitelist = src.split("valid_frequencies")[1].split("]")[0]
    assert "'cron'" in whitelist


# ---------- 任务管理参数校验 ----------

def test_execute_task_unknown_behavior():
    ok, msg = sched.TaskExecutor.execute_task({"behavior": "nope", "scope": "none", "params": "{}"})
    assert ok is False
    assert "未知行为类型" in msg


def test_create_task_invalid_behavior():
    with pytest.raises(ValueError):
        sched.create_task("t", "bad", "specific_user", {}, "2026-01-01 00:00", "daily")


def test_create_task_invalid_scope():
    with pytest.raises(ValueError):
        sched.create_task("t", "user_ban", "bad_scope", {}, "2026-01-01 00:00", "daily")
