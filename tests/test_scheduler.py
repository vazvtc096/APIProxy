"""定时任务调度器单元测试（纯逻辑，不涉及真实 DB）。"""
import datetime

from APIProxy import scheduler as sched


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
    # cron 当前为简化处理，返回 +1 分钟
    assert sched.calculate_next_run("cron", now, "0 0 * * *") == now + datetime.timedelta(minutes=1)


def test_execute_task_unknown_behavior():
    ok, msg = sched.TaskExecutor.execute_task({"behavior": "nope", "scope": "none", "params": "{}"})
    assert ok is False
    assert "未知行为类型" in msg


def test_create_task_invalid_behavior():
    with __import__("pytest").raises(ValueError):
        sched.create_task("t", "bad", "specific_user", {}, "2026-01-01 00:00", "daily")


def test_create_task_invalid_scope():
    with __import__("pytest").raises(ValueError):
        sched.create_task("t", "user_ban", "bad_scope", {}, "202 6-01-01 00:00", "daily")
