"""OIDC 客户端模块纯单元测试（无网络 / 无 app 依赖）。

覆盖：PKCE 挑战正确性、授权 URL 构造、state/verifier 生成、用户名净化、secret 哈希、discovery 入参校验。
"""
import sys
import os
import base64
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from APIProxy import oidc


def test_pkce_challenge_is_s256_of_verifier():
    verifier = oidc.gen_code_verifier()
    chal, method = oidc.pkce_challenge(verifier)
    assert method == 'S256'
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    assert chal == expected


def test_state_and_verifier_long_enough():
    assert len(oidc.gen_state()) >= 32
    assert len(oidc.gen_code_verifier()) >= 32


def test_build_auth_url_includes_pkce_and_scope():
    provider = {
        'authorization_endpoint': 'https://idp.example.com/authorize',
        'client_id': 'abc',
    }
    url = oidc.build_auth_url(provider, 'stt', 'https://app/cb', 'chal',
                              scope='openid profile email')
    assert 'response_type=code' in url
    assert 'client_id=abc' in url
    assert 'redirect_uri=' in url
    assert 'scope=openid+profile+email' in url or 'scope=openid%20profile' in url
    assert 'state=stt' in url
    assert 'code_challenge=chal' in url
    assert 'code_challenge_method=S256' in url


def test_gen_username_sanitizes():
    assert oidc._gen_username('Alice Example') == 'aliceexample'
    assert oidc._gen_username('bad!@#name') == 'badname'
    assert len(oidc._gen_username('')) > 0  # 空串回落到随机名


def test_hash_secret_deterministic():
    h1 = oidc._hash_secret('secret123')
    h2 = oidc._hash_secret('secret123')
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex 摘要
    assert oidc._hash_secret('') != oidc._hash_secret('x')  # 空与非空结果不同


async def test_discover_rejects_empty_issuer():
    raised = False
    try:
        await oidc.discover('')
    except ValueError:
        raised = True
    assert raised
