"""纯函数模块（阶段 2 拆分产物）的单元测试。

覆盖内容安全、CIDR/OAuth、代理辅助三类下沉的纯函数，
同时验证 `from APIProxy import core` 的 facade 兼容性。
"""
from APIProxy import core


# ---------- 内容安全 ----------
def test_sanitize_removes_script_tag():
    assert core._sanitize_user_content("<script>alert(1)</script>") == "alert(1)"


def test_sanitize_removes_img_tag_and_handler():
    out = core._sanitize_user_content('<img src=x onerror="alert(1)">')
    assert "<img" not in out
    assert "onerror" not in out


def test_sanitize_removes_javascript_uri():
    assert "javascript:" not in core._sanitize_user_content('<a href="javascript:alert(1)">x</a>')


def test_sanitize_nested_tags():
    out = core._sanitize_user_content("<scr<script>ipt>alert(1)</script>")
    assert "<script" not in out.lower()


def test_sanitize_plain_text_unchanged():
    assert core._sanitize_user_content("hello world") == "hello world"


def test_sanitize_non_string_passthrough():
    assert core._sanitize_user_content(None) is None
    assert core._sanitize_user_content(123) == 123


def test_safe_username_valid():
    assert core._is_safe_username("alice_123") is True


def test_safe_username_invalid():
    assert core._is_safe_username("alice<3") is False
    assert core._is_safe_username("") is False
    assert core._is_safe_username("a b") is False


# ---------- 网络 / OAuth ----------
def test_ip_in_cidr_exact():
    assert core._ip_in_cidr("10.0.0.1", "10.0.0.1") is True


def test_ip_in_cidr_network():
    assert core._ip_in_cidr("10.0.0.50", "10.0.0.0/24") is True
    assert core._ip_in_cidr("10.0.1.50", "10.0.0.0/24") is False


def test_ip_in_cidr_invalid_entry():
    assert core._ip_in_cidr("10.0.0.1", "not-a-cidr") is False
    assert core._ip_in_cidr("10.0.0.1", "") is False


def test_is_absolute_http_uri():
    assert core._is_absolute_http_uri("https://example.com/cb") is True
    assert core._is_absolute_http_uri("http://localhost/cb") is True
    assert core._is_absolute_http_uri("/cb") is False
    assert core._is_absolute_http_uri("ftp://example.com") is False


def test_scope_satisfied():
    assert core._scope_satisfied(["posts:read"], {"posts:read"}) == []
    assert core._scope_satisfied(["posts:read"], {"posts:write"}) == ["posts:read"]
    # 'a|b' 表示满足其一即可
    assert core._scope_satisfied(["profile|openid"], {"openid"}) == []


# ---------- 代理辅助 ----------
def test_normalize_upstream_payload_ok():
    data = {"name": "up", "base_url": "https://x", "api_key": "k", "priority": 1}
    norm, err = core._normalize_upstream_payload(data)
    assert err is None
    assert norm["name"] == "up"
    assert norm["priority"] == 1
    assert norm["enabled"] is True


def test_normalize_upstream_payload_missing_field():
    _, err = core._normalize_upstream_payload({"name": "up"})
    assert err is not None


def test_normalize_upstream_payload_bad_priority():
    _, err = core._normalize_upstream_payload(
        {"name": "up", "base_url": "x", "api_key": "k", "priority": "abc"})
    assert err == "priority must be an integer"


def test_concat_text_parts():
    assert core._concat_text_parts("plain") == "plain"
    assert core._concat_text_parts([{"text": "a"}, {"text": "b"}]) == "ab"
    assert core._concat_text_parts([{"input": "x"}, "y"]) == "xy"


def test_responses_input_str():
    msgs = core._responses_input_to_messages({"input": "hello"})
    assert msgs == [{"role": "user", "content": "hello"}]


def test_responses_input_with_instructions():
    msgs = core._responses_input_to_messages({"instructions": "sys", "input": "hi"})
    assert msgs[0] == {"role": "system", "content": "sys"}
    assert msgs[1] == {"role": "user", "content": "hi"}


def test_chat_to_responses():
    r = core._chat_to_responses({
        "choices": [{"message": {"content": "hi"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        "created": 123,
        "model": "gpt-4",
    }, "gpt-4")
    assert r["object"] == "response"
    assert r["output"][0]["content"][0]["text"] == "hi"
    assert r["usage"]["total_tokens"] == 3


def test_sse_response_event():
    ev = core._sse_response_event("message", {"x": 1})
    assert ev.startswith("event: message\n")
    assert "data:" in ev


def test_neg_time_key_reverse_order():
    assert core._neg_time_key("") == "~"
    # 越新的时间键越小（倒序排列），'9' 比 '0' 键更小
    assert core._neg_time_key("9") < core._neg_time_key("0")
