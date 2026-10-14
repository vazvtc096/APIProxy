"""套餐/订阅（花账户余额）集成测试：用临时 SQLite 隔离，验证扣费 + 订阅写入 + 余额不足回滚。

通过 monkeypatch APIProxy.db.get_conn / begin_write 指向临时库，不污染运行时 users.db。
"""
import sys
import os
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from APIProxy import db as db_mod
from APIProxy import subscription


@pytest.fixture
def tmpdb(tmp_path):
    path = tmp_path / "sub_test.db"
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE users (user_name TEXT PRIMARY KEY, user_password TEXT, balence REAL, "
                 "uid TEXT, email TEXT, allow_overdraft REAL DEFAULT 0, max_overdraft REAL DEFAULT 0)")
    conn.execute("""CREATE TABLE subscription_plans (
        id TEXT PRIMARY KEY, name TEXT, description TEXT, price REAL, period_days INTEGER,
        features TEXT, active INTEGER, created_at TEXT, updated_at TEXT)""")
    conn.execute("""CREATE TABLE user_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT, user_name TEXT, plan_id TEXT,
        started_at INTEGER, expires_at INTEGER, status TEXT, auto_renew INTEGER,
        created_at INTEGER, updated_at INTEGER)""")
    conn.commit()
    conn.close()

    orig_get = db_mod.get_conn
    orig_begin = db_mod.begin_write

    def fake_get_conn():
        c = sqlite3.connect(str(path))
        c.row_factory = sqlite3.Row
        return c

    db_mod.get_conn = fake_get_conn
    db_mod.begin_write = lambda c: None  # sqlite 默认每条语句自动提交，足以验证逻辑

    yield str(path)

    db_mod.get_conn = orig_get
    db_mod.begin_write = orig_begin


async def _seed_user(name, balence, uid='U1'):
    await subscription.async_db_query(
        "INSERT INTO users (user_name, user_password, balence, uid, email) VALUES (?, ?, ?, ?, ?)",
        (name, 'x', balence, uid, ''))


async def _seed_plan(pid, price, period=30, active=1, feats='["a","b"]'):
    await subscription.async_db_query(
        "INSERT INTO subscription_plans (id, name, description, price, period_days, features, active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (pid, pid, '', price, period, feats, active, '', ''))


async def test_subscribe_deducts_balance_and_creates_subscription(tmpdb):
    await _seed_user('alice', 100.0, 'UA')
    await _seed_plan('std', 30.0)
    ok, msg, sub = await subscription.subscribe('alice', 'std')
    assert ok is True
    assert sub['plan_id'] == 'std'
    assert sub['status'] == 'active'

    row = await subscription.async_db_query(
        "SELECT balence FROM users WHERE user_name=?", ('alice',), fetch_one=True)
    assert abs(row['balence'] - 70.0) < 1e-6

    active = await subscription.get_active_subscription('alice')
    assert active is not None
    assert active['plan_id'] == 'std'
    assert active['features'] == ['a', 'b']


async def test_subscribe_insufficient_balance_rolls_back(tmpdb):
    await _seed_user('bob', 10.0, 'UB')
    await _seed_plan('pro', 99.0, feats='["x"]')
    ok, msg, sub = await subscription.subscribe('bob', 'pro')
    assert ok is False
    assert sub is None

    row = await subscription.async_db_query(
        "SELECT balence FROM users WHERE user_name=?", ('bob',), fetch_one=True)
    assert abs(row['balence'] - 10.0) < 1e-6  # 余额未变（回滚）


async def test_subscribe_extends_existing_active(tmpdb):
    await _seed_user('carol', 200.0, 'UC')
    await _seed_plan('std', 30.0, period=30)
    await subscription.subscribe('carol', 'std')
    await subscription.subscribe('carol', 'std')  # 再次订阅应顺延，不新增行
    subs = await subscription.list_my_subscriptions('carol')
    active_rows = [s for s in subs if s['plan_id'] == 'std']
    assert len(active_rows) == 1
    # 余额扣了两次 30
    row = await subscription.async_db_query(
        "SELECT balence FROM users WHERE user_name=?", ('carol',), fetch_one=True)
    assert abs(row['balence'] - 140.0) < 1e-6
