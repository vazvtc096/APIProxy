# -*- coding: utf-8 -*-
"""本轮加固改动的最小回归测试（纯本地，无网络）。

覆盖：
  1. 单实例锁 instance_lock（同进程幂等 / 跨进程互斥 / ALLOW_MULTI 跳过）
  2. CSRF 豁免路径匹配（锚定正则，前缀碰撞不再放行）
  3. 二维码工具 utils.qr
  4. 动态注册 scope 钳制（oauth.register_client 剔除高危 scope）
  5. SQLite WAL/synchronous pragma 生效
  6. 幂等入账 _credit_request 并发只有一个生效（CAS）

从 E:/Code 运行：
    PYTHONPATH='E:/Code' python -m pytest APIProxy/tests/test_hardening.py -q --noconftest
"""
import asyncio
import os
import subprocess
import sys
import tempfile

import pytest

# 必须在导入应用模块之前设置好环境（configs 在 import 时读取）。
# 关键：这里**强制** sqlite（不是 setdefault）—— 本机 config.yaml 的 DB_TYPE=postgres
# 指向真实本地库，若测试连上去会污染线上数据（本项目真实踩过此坑）。
_TMP = tempfile.mkdtemp(prefix="apx_hard_")
os.environ["DB_TYPE"] = "sqlite"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = os.path.join(_TMP, "t.db")
os.environ["APIPROXY_OAUTH_JWT_SECRET"] = "x" * 64
os.environ["SESSION_SECRET"] = "y" * 64


# ---- 1. 单实例锁 -----------------------------------------------------------

def test_instance_lock_idempotent_and_release():
    from APIProxy import instance_lock
    p = os.path.join(_TMP, "lock_a.lock")
    h = instance_lock.acquire(p)
    assert h is not None
    assert instance_lock.acquire(p) is h          # 同进程重复获取幂等
    instance_lock.release()
    # 释放后可再次获取
    h2 = instance_lock.acquire(p)
    assert h2 is not None
    instance_lock.release()


def test_instance_lock_cross_process_blocked():
    from APIProxy import instance_lock
    p = os.path.join(_TMP, "lock_b.lock")
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys;sys.path.insert(0,r'E:/Code');"
         "from APIProxy.instance_lock import acquire;"
         f"acquire(r'{p}');import time;time.sleep(3)"],
    )
    try:
        import time
        time.sleep(1.5)
        with pytest.raises(instance_lock.InstanceLockError):
            instance_lock.acquire(p)
    finally:
        holder.terminate()
        holder.wait(timeout=10)


def test_instance_lock_allow_multi(monkeypatch):
    from APIProxy import instance_lock
    p = os.path.join(_TMP, "lock_c.lock")
    monkeypatch.setenv("APIPROXY_ALLOW_MULTI", "1")
    assert instance_lock.acquire(p) is None       # 显式跳过加锁
    instance_lock.release()


# ---- 2. CSRF 豁免路径 ------------------------------------------------------

def test_csrf_exempt_path_matcher():
    from APIProxy.core import is_csrf_exempt_path
    assert is_csrf_exempt_path("/api/recharge/callback/epay") is True
    assert is_csrf_exempt_path("/api/recharge/callback/wechatpay") is True
    assert is_csrf_exempt_path("/login") is True
    # 前缀碰撞（旧实现被放行）现在必须被拒绝
    assert is_csrf_exempt_path("/api/recharge/callback/") is False
    assert is_csrf_exempt_path("/api/recharge/callback/epay/../admin") is False
    assert is_csrf_exempt_path("/api/recharge/callback/a/b") is False
    assert is_csrf_exempt_path("/api/recharge/pay") is False


# ---- 3. 二维码 -------------------------------------------------------------

def test_qr_svg_generation():
    from APIProxy.utils.qr import qr_svg, qr_available
    if not qr_available():
        pytest.skip("qrcode 未安装")
    svg = qr_svg("weixin://wxpay/bizpayurl?pr=ABC123")
    assert svg and "<svg" in svg
    assert qr_svg("") is None


# ---- 4. 动态注册 scope 钳制 ------------------------------------------------

def test_dynamic_register_clamps_sensitive_scopes():
    from APIProxy import oauth

    captured = {}

    async def _db(sql, args=()):
        captured["sql"] = sql
        captured["args"] = args
        return []

    meta = {
        "client_name": "Evil App",
        "redirect_uris": ["https://evil.example/cb"],
        "token_endpoint_auth_method": "none",
        # 试图索取高危 scope
        "scopes": "api profile user:write transactions:write apikeys:write debug_console",
    }
    resp = asyncio.run(oauth.register_client(_db, meta))
    assert resp["client_id"].startswith("client_")
    assert "client_secret" not in resp                    # 公开客户端无 secret
    scopes = set(resp["scope"].split())
    for bad in oauth.SENSITIVE_SCOPES:
        assert bad not in scopes, bad
    assert "api" in scopes and "profile" in scopes
    # 落库的 scopes 参数同样不含高危项
    stored_scopes = captured["args"][-3]
    for bad in oauth.SENSITIVE_SCOPES:
        assert bad not in stored_scopes


def test_dynamic_register_confidential_issues_secret():
    from APIProxy import oauth

    async def _db(sql, args=()):
        return []

    resp = asyncio.run(oauth.register_client(_db, {
        "client_name": "Server App",
        "redirect_uris": ["https://app.example/cb"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scopes": "api",
    }))
    assert resp["client_secret"]
    assert resp["client_secret_expires_at"] == 0


# ---- 5. SQLite pragma ------------------------------------------------------

def test_sqlite_wal_enabled():
    from APIProxy import db, core_db
    if db.is_postgres():
        pytest.skip("PostgreSQL 后端")
    conn = core_db._get_conn()
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(mode).lower() == "wal"
    finally:
        conn.close()


# ---- 6. 幂等入账并发 -------------------------------------------------------

def _create_billing_schema():
    from APIProxy import core_db
    conn = core_db._get_conn()
    try:
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                " user_name TEXT PRIMARY KEY, uid TEXT, balence REAL DEFAULT 0)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS recharge_requests ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT UNIQUE,"
                " user_uid TEXT, user_name TEXT, amount REAL, status TEXT DEFAULT 'pending',"
                " pay_channel TEXT, pay_order_no TEXT, admin_remark TEXT,"
                " created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS balence_transactions ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT, transaction_id TEXT UNIQUE,"
                " user_uid TEXT, user_name TEXT, type TEXT, amount REAL,"
                " balence_after REAL, related_id TEXT, remark TEXT,"
                " created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    finally:
        conn.close()


def test_credit_request_concurrent_single_credit():
    from APIProxy.routes.recharge import _credit_request
    from APIProxy import core_db

    _create_billing_schema()
    conn = core_db._get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM users WHERE user_name='u1'")
            conn.execute("DELETE FROM recharge_requests WHERE request_id='reqC'")
            conn.execute("DELETE FROM balence_transactions WHERE user_name='u1'")
            conn.execute("INSERT INTO users (user_name, uid, balence) VALUES ('u1','uid1',0)")
            conn.execute(
                "INSERT INTO recharge_requests (request_id, user_uid, user_name, amount, status)"
                " VALUES ('reqC','uid1','u1',10.0,'pending')")
    finally:
        conn.close()

    async def _run():
        return await asyncio.gather(*[
            _credit_request("reqC", "ORD1", "epay", 10.0) for _ in range(5)
        ])

    results = asyncio.run(_run())
    assert all(ok for ok, _ in results), results
    # 恰有一次「入账成功」，其余为幂等命中
    assert sum(1 for _, msg in results if "入账成功" in msg) == 1

    conn = core_db._get_conn()
    try:
        bal = conn.execute("SELECT balence FROM users WHERE user_name='u1'").fetchone()[0]
        n = conn.execute(
            "SELECT COUNT(*) FROM balence_transactions WHERE user_name='u1'").fetchone()[0]
        st = conn.execute(
            "SELECT status FROM recharge_requests WHERE request_id='reqC'").fetchone()[0]
    finally:
        conn.close()
    assert abs(float(bal) - 10.0) < 1e-9      # 只加一次
    assert n == 1
    assert st == "approved"


def test_credit_request_amount_mismatch_rejected():
    from APIProxy.routes.recharge import _credit_request
    from APIProxy import core_db

    _create_billing_schema()
    conn = core_db._get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM recharge_requests WHERE request_id='reqM'")
            conn.execute(
                "INSERT INTO recharge_requests (request_id, user_uid, user_name, amount, status)"
                " VALUES ('reqM','uid1','u1',10.0,'pending')")
    finally:
        conn.close()

    ok, msg = asyncio.run(_credit_request("reqM", "ORD2", "epay", 99.0))
    assert ok is False
    assert "金额不匹配" in msg
