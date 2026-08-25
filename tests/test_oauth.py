"""OAuth 2.0 纯函数单元测试：scope 校验、PKCE、JWT 签发/验签。

覆盖 RFC 6749 / RFC 7636 核心纯逻辑，不依赖数据库。
"""
import base64
import hashlib

from APIProxy import oauth


# ---------- scope ----------
def test_normalize_scope_dedup_order():
    assert oauth.normalize_scope("a b a c") == "a b c"
    assert oauth.normalize_scope("") == ""
    assert oauth.normalize_scope("  a   b  ") == "a b"
    assert oauth.normalize_scope(None) == ""


def test_scope_subset():
    assert oauth.scope_subset("posts:read", "posts:read posts:write") is True
    assert oauth.scope_subset("posts:write", "posts:read") is False
    # 空请求 scope 是任意允许 scope 的子集
    assert oauth.scope_subset("", "posts:read") is True


def test_client_allows_redirect_uri():
    client = {"redirect_uris": "https://a.com/cb, https://b.com/cb"}
    assert oauth.client_allows_redirect_uri(client, "https://a.com/cb") is True
    assert oauth.client_allows_redirect_uri(client, "https://evil.com/cb") is False
    assert oauth.client_allows_redirect_uri({"redirect_uris": ""}, "https://a.com/cb") is False


# ---------- PKCE ----------
def test_pkce_plain():
    assert oauth.pkce_verify("abc123", "abc123", "plain") is True
    assert oauth.pkce_verify("abc123", "xyz", "plain") is False


def test_pkce_s256():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert oauth.pkce_verify(verifier, challenge, "S256") is True
    assert oauth.pkce_verify(verifier, challenge, "s256") is True  # 方法名大小写不敏感
    assert oauth.pkce_verify(verifier, "wrong-challenge", "S256") is False


def test_pkce_empty_rejected():
    assert oauth.pkce_verify("", "x", "S256") is False
    assert oauth.pkce_verify("x", "", "S256") is False


# ---------- JWT access token ----------
def test_sign_and_decode_access_token(monkeypatch):
    monkeypatch.setattr(oauth, "OAUTH_JWT_SECRET", "unit-test-secret-32bytes")
    token, jti, exp_ts = oauth.sign_access_token(
        "client_x", "uid_1", "alice", "api profile"
    )
    assert token
    assert jti
    assert exp_ts > 0

    payload = oauth.decode_access_token(token)
    assert payload is not None
    assert payload["client_id"] == "client_x"
    assert payload["scope"] == "api profile"
    assert payload["username"] == "alice"
    assert payload["token_type"] == "access"
    assert payload["sub"] == "uid_1"


def test_decode_invalid_token(monkeypatch):
    monkeypatch.setattr(oauth, "OAUTH_JWT_SECRET", "unit-test-secret-32bytes")
    assert oauth.decode_access_token("not-a-valid-token") is None
    # 用错误密钥签发的 token 验签必须失败
    import jwt as _jwt
    bad = _jwt.encode({"sub": "x"}, "wrong-secret", algorithm="HS256")
    assert oauth.decode_access_token(bad) is None
