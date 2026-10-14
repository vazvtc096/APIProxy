"""OAuth 权限收紧：敏感 scope 分类与默认安全基线。"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from APIProxy import oauth


def test_sensitive_scopes_defined():
    assert set(oauth.SENSITIVE_SCOPES) == {
        'user:write', 'transactions:write', 'apikeys:write', 'debug_console'
    }


def test_default_safe_scopes_exclude_sensitive():
    safe = set(oauth.DEFAULT_SAFE_SCOPES.split())
    assert safe.isdisjoint(set(oauth.SENSITIVE_SCOPES))
    # 安全基线应保留身份与只读类 scope
    assert {'api', 'openid', 'profile', 'email', 'user:read', 'transactions:read'} <= safe


def test_categorize_scopes_flags_sensitive():
    cats = oauth.categorize_scopes('api user:write debug_console profile')
    by_scope = {c['scope']: c for c in cats}
    assert by_scope['api']['sensitive'] is False
    assert by_scope['profile']['sensitive'] is False
    assert by_scope['user:write']['sensitive'] is True
    assert by_scope['debug_console']['sensitive'] is True


def test_categorize_dedup_and_order():
    cats = oauth.categorize_scopes('api api profile')
    scopes = [c['scope'] for c in cats]
    assert scopes == ['api', 'profile']  # 去重、保序
