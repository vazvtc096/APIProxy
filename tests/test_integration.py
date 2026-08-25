"""端到端集成测试：WAF 中间件请求级拦截 + OAuth 端点鉴权。

用 Quart test client 走「请求 → 中间件 → 路由 → 响应」完整链路，
验证 WAF 在路由匹配前拦截攻击载荷、OAuth 端点正确拒绝缺失/无效令牌。
"""
import pytest
import pytest_asyncio

from APIProxy import waf


@pytest_asyncio.fixture
async def waf_client(client, monkeypatch):
    """启用 WAF 且不限制 Host（聚焦规则检查，避免 Host 校验干扰）。"""
    monkeypatch.setattr(waf, "WAF_ENABLED", True)
    monkeypatch.setattr(waf, "WAF_ALLOWED_HOSTS", [])
    monkeypatch.setattr(waf, "WAF_DISABLE_IF_CLOUDFLARE", False)
    return client


# ---------- WAF 端到端拦截 ----------
@pytest.mark.asyncio
async def test_waf_blocks_scanner_path(waf_client):
    resp = await waf_client.get("/.env")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_waf_blocks_sqli_user_agent(waf_client):
    resp = await waf_client.get("/", headers={"User-Agent": "sqlmap/1.5"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_waf_blocks_xss_user_agent(waf_client):
    resp = await waf_client.get("/", headers={"User-Agent": "<script>alert(1)</script>"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_waf_allows_normal_request(waf_client):
    # /health 是正常端点，不应被 WAF 误拦（503 仅当测试库未就绪）
    resp = await waf_client.get("/health")
    assert resp.status_code in (200, 503)


# ---------- OAuth 端点鉴权 ----------
@pytest.mark.asyncio
async def test_oauth_userinfo_requires_bearer(client):
    resp = await client.get("/oauth/userinfo")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_oauth_userinfo_rejects_invalid_token(client):
    resp = await client.get("/oauth/userinfo",
                            headers={"Authorization": "Bearer not-a-valid-token"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_oauth_api_requires_bearer(client):
    resp = await client.get("/api/oauth")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_oauth_token_missing_params(client):
    # /oauth/token 缺少 grant_type 等参数，应返回 400
    resp = await client.post("/oauth/token", data={})
    assert resp.status_code == 400
