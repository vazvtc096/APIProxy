# -*- coding: utf-8 -*-
"""安全审计修复的回归测试（纯本地，无网络）。

覆盖审计报告中的发现：
  H1  内部端点用客户端可控 X-Forwarded-For 判回环 → 可伪造绕过（严重）
  H2  audit_export 格式名拼进文件名 → 任意路径写入
  M2  APIPROXY_* 环境变量在"无 config.yaml"时不生效（预检 fail-closed 拒启）
  L2  封禁时长 inf → 永久封禁且无法收敛
  L3  Worker 角色守卫用裸 except 静默失效
  （另含 .env 自动加载）

从 E:/Code 运行：
    PYTHONPATH='E:/Code' python -m pytest APIProxy/tests/test_security_fixes.py -q --noconftest
"""
import os
import subprocess
import sys
import tempfile
import textwrap

import pytest

# 强制隔离到 sqlite（本机 config.yaml 是 postgres 真库，绝不能连上去）。
_TMP = tempfile.mkdtemp(prefix="apx_secfix_")
os.environ["DB_TYPE"] = "sqlite"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = os.path.join(_TMP, "t.db")
os.environ["APIPROXY_OAUTH_JWT_SECRET"] = "x" * 64
os.environ["SESSION_SECRET"] = "y" * 64


class _FakeRequest:
    """最小 request 替身：只提供真实 IP 解析所需的两个属性。"""

    def __init__(self, remote, headers=None):
        self.remote_addr = remote
        self.headers = headers or {}


# ---- H1：真实对端解析不能采信客户端可控头 --------------------------------

def test_resolve_client_ip_ignores_forged_xff(monkeypatch):
    """公网直连带 `X-Forwarded-For: 127.0.0.1` 必须仍然解析成真实公网 IP。"""
    from APIProxy import cloudflare as cf

    monkeypatch.setattr(cf, "request", _FakeRequest(
        "203.0.113.9", {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}))
    assert cf._resolve_client_ip() == "203.0.113.9"
    assert cf.is_loopback_client() is False


def test_resolve_client_ip_loopback_without_headers(monkeypatch):
    """真正从回环连入（本机 curl）仍应被识别为回环。"""
    from APIProxy import cloudflare as cf

    monkeypatch.setattr(cf, "request", _FakeRequest("127.0.0.1", {}))
    assert cf.is_loopback_client() is True


def test_internal_secret_ok_prefers_constant_time_secret(monkeypatch):
    """配置了共享密钥时以密钥为准，回环身份不再具备豁免。"""
    from APIProxy import core_console

    monkeypatch.setattr(core_console, "_internal_secret", lambda: "s3cr3t-token")
    assert core_console.internal_secret_ok("s3cr3t-token") is True
    assert core_console.internal_secret_ok("wrong") is False
    assert core_console.internal_secret_ok("") is False


def test_internal_secret_ok_loopback_fallback(monkeypatch):
    """无共享密钥时回退到真实对端回环判定（伪装场景必须拒绝）。"""
    from APIProxy import core_console

    monkeypatch.setattr(core_console, "_internal_secret", lambda: "")
    monkeypatch.setattr("APIProxy.cloudflare.is_loopback_client", lambda: False)
    assert core_console.internal_secret_ok("") is False
    monkeypatch.setattr("APIProxy.cloudflare.is_loopback_client", lambda: True)
    assert core_console.internal_secret_ok("") is True


def test_no_vulnerable_loopback_heuristic_remains():
    """全仓防回归：不得再用「客户端可控头 + startswith('127.')」判定内部来源。

    这正是 H1 的缺陷形态。Quart 测试客户端不填充对端地址，无法在单测里端到端
    模拟公网来源，故这里用源码级扫描锁死该模式，防止日后被重新引入。
    """
    import glob

    root = "E:/Code/APIProxy"
    offenders = []
    for path in glob.glob(os.path.join(root, "**", "*.py"), recursive=True):
        norm = path.replace("\\", "/")
        if "/tests/" in norm or "node_modules" in norm:
            continue
        src = open(path, encoding="utf-8").read()
        if 'startswith("127.' in src or "startswith('127." in src:
            offenders.append(norm + " [startswith 127.]")
        if '"X-Forwarded-For", request.remote_addr' in src:
            offenders.append(norm + " [XFF->remote_addr]")
    assert offenders == [], offenders


def test_internal_endpoints_use_shared_gate():
    """4 个 /internal/* 端点必须统一走 internal_secret_ok（恒定时间 + 真实对端）。"""
    for rel in ("cache_store.py", "routes/audit_routes.py",
                "routes/auth_routes.py", "routes/console_routes.py"):
        src = open(os.path.join("E:/Code/APIProxy", rel), encoding="utf-8").read()
        assert "internal_secret_ok(" in src, rel


# ---- H2：审计导出格式白名单 ------------------------------------------------

def test_audit_export_rejects_path_traversal_format():
    from APIProxy import core_console

    evil = "../../evil_traversal"
    res = core_console._cmd_audit_export([evil])
    assert res["success"] is False
    assert "不支持" in res["output"]
    # 旧实现在 CWD（E:/Code）向上两级写出。确认没有产生该文件。
    target = os.path.abspath(os.path.join("E:/Code", evil))
    assert not os.path.exists(target)


def test_audit_export_writes_into_fixed_dir():
    from APIProxy import core_console, configs

    res = core_console._cmd_audit_export(["json"])
    assert res["success"] is True, res
    path = res["data"]["path"]
    export_dir = os.path.join(str(configs.BASE_DIR), "audit_exports")
    assert os.path.dirname(os.path.abspath(path)) == os.path.abspath(export_dir)
    assert os.path.basename(path).startswith("audit_export-")
    assert path.endswith(".json")
    try:
        os.remove(path)
    except OSError:
        pass


# ---- M2：纯环境变量部署（无 config.yaml）----------------------------------

def test_env_var_introduces_missing_config_key():
    """没有有效 config.yaml 时，APIPROXY_<KEY> 仍必须生效（否则预检拒启）。"""
    tmp = tempfile.mkdtemp(prefix="apx_env_")
    empty = os.path.join(tmp, "empty.yaml")
    open(empty, "w", encoding="utf-8").close()
    code = textwrap.dedent("""
        import sys
        sys.path.insert(0, r"E:/Code")
        from APIProxy import configs
        print("SECRET=" + repr(configs.OAUTH_JWT_SECRET))
        print("BASEURL=" + repr(configs._get("baseurl")))
        print("WAF=" + repr(configs._get_bool("WAF_ENABLED")))
    """)
    env = {k: v for k, v in os.environ.items() if not k.startswith("APIPROXY_")}
    env.update({
        "APIPROXY_CONFIG": empty,
        "APIPROXY_OAUTH_JWT_SECRET": "ENV-ONLY-SECRET",
        "APIPROXY_BASEURL": "https://env.example",
        "APIPROXY_WAF_ENABLED": "true",
    })
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       cwd="E:/Code/APIProxy", env=env)
    assert "SECRET='ENV-ONLY-SECRET'" in r.stdout, r.stdout + r.stderr
    assert "BASEURL='https://env.example'" in r.stdout, r.stdout + r.stderr
    assert "WAF=True" in r.stdout, r.stdout + r.stderr


def test_dotenv_is_loaded():
    """.env 里的键值必须被自动读取（引号与行内注释按规则处理）。"""
    tmp = tempfile.mkdtemp(prefix="apx_dotenv_")
    with open(os.path.join(tmp, "configs.py"), "w", encoding="utf-8") as f:
        f.write(open("E:/Code/APIProxy/configs.py", encoding="utf-8").read())
    with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as f:
        f.write("# comment\nAPIPROXY_OAUTH_JWT_SECRET=dotenv-secret\n")
        f.write('SOME_KEY="quoted value"\nOTHER=plain # inline\n')
    code = textwrap.dedent(f"""
        import importlib.util, os
        spec = importlib.util.spec_from_file_location("cfgdemo", r"{tmp}/configs.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        print("OAUTH=" + repr(m.OAUTH_JWT_SECRET))
        print("SOME=" + repr(os.environ.get("SOME_KEY")))
        print("OTHER=" + repr(os.environ.get("OTHER")))
    """)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("APIPROXY_") and k not in ("SOME_KEY", "OTHER")}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert "OAUTH='dotenv-secret'" in r.stdout, r.stdout + r.stderr
    assert "SOME='quoted value'" in r.stdout, r.stdout + r.stderr
    assert "OTHER='plain'" in r.stdout, r.stdout + r.stderr


# ---- L2：封禁时长非有限值 --------------------------------------------------

def test_eval_duration_rejects_non_finite():
    from APIProxy import security

    assert security.eval_duration("1e999", 1) == ("never", None)      # 溢出成 inf
    assert security.eval_duration("n ** 999", 100) == ("never", None)  # 幂运算溢出
    assert security.eval_duration("n * 10", 3) == ("minutes", 30.0)    # 正常仍工作


def test_ban_minutes_finite_guard():
    from APIProxy import security

    assert security._is_finite_minutes(30) is True
    assert security._is_finite_minutes(0) is True
    inf = float("inf")
    assert security._is_finite_minutes(inf) is False
    assert security._is_finite_minutes(float("-inf")) is False
    assert security._is_finite_minutes(float("nan")) is False
    assert security._is_finite_minutes(-5) is False
    assert security._is_finite_minutes("oops") is False


# ---- L3：Worker 角色守卫 ---------------------------------------------------

def test_is_worker_node_false_without_cluster():
    from APIProxy import cluster, configs

    if getattr(configs, "CLUSTER_ENABLED", False):
        pytest.skip("本环境已启用集群，跳过单机断言")
    assert cluster.is_worker_node() is False


def test_cache_internal_endpoint_guard_is_present():
    """确保 /internal/cache 的 Worker 守卫走统一判定，而不是裸 except 静默失效。"""
    src = open("E:/Code/APIProxy/cache_store.py", encoding="utf-8").read()
    assert "is_worker_node() is True" in src
    assert "workers do not serve cache" in src


# ---- L1：恒定时间比较（消除时序侧信道）------------------------------------

def test_apikey_password_verify_uses_constant_time(monkeypatch):
    """scrypt 派生密钥比较必须用 compare_digest，不能裸 ==。"""
    from APIProxy import apikey

    src = open("E:/Code/APIProxy/apikey.py", encoding="utf-8").read()
    assert "secrets.compare_digest(derived_key, stored_key)" in src
    assert "derived_key == stored_key" not in src

    # 行为不变：正确密码通过、错误密码拒绝
    hashed = apikey.hash_password("correct-horse")
    assert apikey.verify_password("correct-horse", hashed) is True
    assert apikey.verify_password("wrong-horse", hashed) is False


def test_cluster_token_compare_is_constant_time_and_fail_closed(monkeypatch):
    from APIProxy.routes import cluster_routes as cr

    real = cr.get_cluster_token()
    assert cr._token_ok(real) is True
    assert cr._token_ok("") is False
    assert cr._token_ok(real + "x") is False
    # fail-closed：令牌配置为空时一律拒绝（杜绝空令牌绕过）
    monkeypatch.setattr(cr, "get_cluster_token", lambda: "")
    assert cr._token_ok("") is False
    assert cr._token_ok("anything") is False


def test_cluster_login_is_rate_limited():
    """集群登录必须接入按 IP 限流，防止对启动令牌的暴力枚举。"""
    from APIProxy.core import RATE_LIMITS

    assert "cluster" in RATE_LIMITS
    # conftest 会把运行期上限放宽到极大值，故校验源码里的原始配置
    src_rl = open("E:/Code/APIProxy/core_rate_limit.py", encoding="utf-8").read()
    assert "'cluster': {'window': 60, 'max': 5}" in src_rl
    src = open("E:/Code/APIProxy/routes/cluster_routes.py", encoding="utf-8").read()
    assert '_check_rate_limit("cluster")' in src
    assert 'Retry-After' in src


def test_debug_console_login_is_rate_limited():
    """Debug Console 登录（最高权限入口）必须按 IP 限流防爆破。"""
    from APIProxy.core import RATE_LIMITS

    assert "console" in RATE_LIMITS
    src_rl = open("E:/Code/APIProxy/core_rate_limit.py", encoding="utf-8").read()
    assert "'console': {'window': 60, 'max': 5}" in src_rl
    src = open("E:/Code/APIProxy/routes/debug_console_routes.py", encoding="utf-8").read()
    assert "_check_rate_limit('console')" in src
    assert "Retry-After" in src


def test_internal_reject_logs_peer(monkeypatch):
    """内部端点拒绝时应记录真实对端 IP（观测面）。"""
    from APIProxy import core_console

    monkeypatch.setattr(core_console, "_internal_secret", lambda: "s3cr3t")
    captured = {}
    monkeypatch.setattr(core_console, "_log_internal_reject",
                        lambda reason: captured.setdefault("reason", reason))
    assert core_console.internal_secret_ok("nope") is False
    assert captured.get("reason")


# ---- 测试隔离：绝不触碰真实 Redis ------------------------------------------

def test_redis_disabled_under_pytest(monkeypatch):
    """pytest 运行期即使配置了 REDIS_URL 也绝不连接真实 Redis（安全网）。"""
    from APIProxy import redis_client

    monkeypatch.setattr(redis_client, "REDIS_URL", "redis://127.0.0.1:6379/0")
    assert redis_client.get_redis() is None


def test_conftest_disables_redis():
    src = open("E:/Code/APIProxy/tests/conftest.py", encoding="utf-8").read()
    assert 'os.environ["REDIS_URL"] = ""' in src


# ---- 公开模板不得泄漏真实凭据 ----------------------------------------------

def test_config_example_has_no_real_secrets():
    """config.yaml.example 是公开模板：所有密钥类字段必须为空或占位。

    回归背景：模板生成曾把真实 163 邮箱授权码（SMTP_PASS）与真实邮箱原样带出。
    本测试不内嵌任何真实凭据，只做结构性断言。
    """
    import re

    src = open("E:/Code/APIProxy/config.yaml.example", encoding="utf-8").read()

    def _val(key):
        m = re.search(rf"^[ \t]*{key}[ \t]*:[ \t]*(.*)$", src, re.M)
        assert m, f"模板缺少字段 {key}"
        return m.group(1).split("#")[0].strip().strip("\"'")

    # SMTP 凭据必须是空占位
    assert _val("SMTP_PASS") == ""
    assert _val("SMTP_USER") == ""

    placeholder = {"", "dummy"}
    offending = []
    for i, line in enumerate(src.splitlines(), 1):
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if not m:
            continue
        key = m.group(1)
        val = m.group(2).split("#")[0].strip().strip("\"'")
        if not re.search(r"(SECRET|PASSWORD|(?<![A-Z])PASS|API_?KEY|PRIVATE_KEY|^TOKEN$|_TOKEN$)", key, re.I):
            continue
        if val in placeholder or val.startswith("<") or "/" in val:
            continue
        if val.endswith((".key", ".pem", ".crt")):
            continue
        offending.append((i, key, val))
    assert offending == [], offending

