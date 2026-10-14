"""应用启动与装配测试：确认重构后的模块化应用能正确挂载。"""

from APIProxy.app import app


def test_create_app_returns_app():
    from APIProxy.__main__ import create_app
    assert create_app() is app


def test_health_endpoint_registered():
    """/health 探针端点已注册（P0-01 新增）。"""
    rules = {str(r.rule) for r in app.url_map.iter_rules()}
    assert "/health" in rules


def test_core_endpoints_registered():
    """关键业务端点存在，证明蓝图全部挂载成功。"""
    rules = {str(r.rule) for r in app.url_map.iter_rules()}
    expected = {
        "/login",                      # 认证页
        "/api/chat/completions",       # 核心代理
        "/v1/chat/completions",        # OpenAI 兼容
        "/api/debug-console/stats",             # Debug Console
        "/api/admin/users",            # 管理
        "/api/posts",                  # 社交
        "/oauth/authorize",            # OAuth
        "/api/user/settings",          # 用户
    }
    missing = expected - rules
    assert not missing, f"缺失端点: {missing}"


def test_endpoint_alias_layer_registered():
    """端点别名兼容层已挂到 url_build_error_handlers。"""
    assert app.url_build_error_handlers, "别名兼容层未注册"


def test_blueprints_registered():
    """所有蓝图已注册（11 个域）。"""
    bp_names = {bp.name for bp in app.blueprints.values()}
    expected = {
        "auth", "user", "admin", "recharge", "chat_proxy", "social",
        "oauth", "debug_console", "pages", "email_captcha", "health",
    }
    missing = expected - bp_names
    assert not missing, f"缺失蓝图: {missing}"


async def test_health_returns_200(client):
    resp = await client.get("/health")
    assert resp.status_code == 200


async def test_login_page_redirects_guest(client):
    """未登录访问受保护页应 302 到登录页（而非 500）。"""
    resp = await client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (302, 303, 401, 403)
