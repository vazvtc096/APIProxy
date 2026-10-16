"""pytest 全局配置与共享 fixture。

关键点：环境变量必须在 import APIProxy 之前设置，因为 configs.py 在
模块 import 时就会读取 DB_PATH / OAUTH_JWT_SECRET 并缓存。
"""

import os
import tempfile

# ---------------------------------------------------------------------------
# 1. 隔离测试数据库 —— 必须在 import APIProxy 之前设置
# ---------------------------------------------------------------------------
_TEST_DIR = tempfile.mkdtemp(prefix="apiproxy_test_")
_TEST_DB = os.path.join(_TEST_DIR, "test_users.db")
os.environ["DB_PATH"] = _TEST_DB

# 1.1 测试默认走隔离 sqlite，避免依赖 config.yaml 里 DB_TYPE=postgres 的
#     占位 DATABASE_URL（<PG_PASSWORD>）去连本机不存在/无密码的 PG 实例。
#     需要真实 PG 自测时，可在调用 pytest 前显式 export DB_TYPE=postgres。
os.environ.setdefault("DB_TYPE", "sqlite")
os.environ.setdefault("DATABASE_URL", "")

# 1.2 测试禁用真实 Redis —— config.yaml 里的 REDIS_URL 会让测试进程连上
#     本机/共享 Redis 实例（读写真实键、连接超时还会拖慢整套用例到数分钟）。
#     需要接入真实 Redis 自测时，在调用 pytest 前显式 export REDIS_URL。
os.environ["REDIS_URL"] = ""

# 2. 提供 JWT 密钥，避免 fail-closed 预检拒绝启动
os.environ["APIPROXY_OAUTH_JWT_SECRET"] = "test-oauth-jwt-secret-0123456789abcdef"

# 现在才 import 项目模块
import pytest
import pytest_asyncio

from APIProxy import core
from APIProxy.__main__ import create_app, init_database

# ---------------------------------------------------------------------------
# 测试数据常量
# ---------------------------------------------------------------------------
ADMIN_USER = "testadmin"
ADMIN_UID = "0123456789ab"  # 12 位十六进制，符合项目 UID 规范
ADMIN_PASS = "testpass123"
CSRF_TOKEN = "a" * 64


def _seed_admin_user() -> None:
    """在测试库插入管理员用户（幂等），供会话注入使用。"""
    import bcrypt
    conn = core._get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE user_name = ?", (ADMIN_USER,))
            if not cur.fetchone():
                hashed = bcrypt.hashpw(ADMIN_PASS.encode(), bcrypt.gensalt()).decode()
                cur.execute(
                    "INSERT INTO users (user_name, user_password, uid, is_admin) "
                    "VALUES (?, ?, ?, 1)",
                    (ADMIN_USER, hashed, ADMIN_UID),
                )
            conn.commit()
    finally:
        conn.close()


def _relax_rate_limits() -> None:
    """调大限流上限，避免全路由扫描时 429 掩盖真实错误。"""
    for cfg in core.RATE_LIMITS.values():
        cfg["max"] = 1_000_000


@pytest.fixture(scope="session", autouse=True)
def _bootstrap():
    """会话级：初始化测试库 schema + 种子数据 + 放宽限流。"""
    init_database()
    _seed_admin_user()
    _relax_rate_limits()
    yield


@pytest.fixture(scope="session")
def app():
    """装配好的 Quart 应用（只创建一次，避免蓝图重复注册）。"""
    return create_app()


@pytest_asyncio.fixture
async def client(app):
    """无会话的 test client。"""
    async with app.test_app() as test_app:
        yield test_app.test_client()


@pytest_asyncio.fixture
async def admin_client(app):
    """带管理员会话 + CSRF token 的 test client。

    会话通过 session_transaction 注入，绕过登录流程，直接进入受保护路由体。
    """
    async with app.test_app() as test_app:
        c = test_app.test_client()
        session_id = core._create_session_sync(
            ADMIN_USER, ADMIN_UID, "pytest/1.0", "127.0.0.1"
        )
        async with c.session_transaction() as sess:
            sess["user"] = ADMIN_USER
            sess["session_id"] = session_id
            sess["is_admin"] = True
            sess["uid"] = ADMIN_UID
            sess["csrf_token"] = CSRF_TOKEN
        yield c


@pytest_asyncio.fixture
async def fresh_admin_client(app):
    """返回工厂：每次调用都新建一个带完整会话的 client。

    某些路由（如清空会话）会登出当前会话，导致后续请求级联 401；
    用此工厂可在每个请求前拿到全新会话。
    """

    async def _make():
        ta = app.test_app()
        await ta.__aenter__()
        c = ta.test_client()
        session_id = core._create_session_sync(
            ADMIN_USER, ADMIN_UID, "pytest/1.0", "127.0.0.1"
        )
        async with c.session_transaction() as sess:
            sess["user"] = ADMIN_USER
            sess["session_id"] = session_id
            sess["is_admin"] = True
            sess["uid"] = ADMIN_UID
            sess["csrf_token"] = CSRF_TOKEN
        return c, ta

    yield _make
