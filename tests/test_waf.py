"""WAF 规则与辅助函数单元测试：URL 解码、Cloudflare 判定、攻击特征正则。

攻击特征正则（SQLi/XSS/路径遍历/扫描器/恶意 UA）是安全关键，测试用于
锁定检测能力，防止后续改动无意中削弱 WAF。
"""
from APIProxy import waf


# ---------- _decode：多次 URL 解码 ----------
def test_decode_single():
    assert waf._decode("hello%20world") == "hello world"


def test_decode_double_encoding():
    # 二次编码的 ../（%252e%252e%252f）会被逐层解码还原
    assert waf._decode("%252e%252e%252f") == "../"


def test_decode_plain_unchanged():
    assert waf._decode("plain text") == "plain text"


# ---------- is_behind_cloudflare ----------
class _FakeReq:
    def __init__(self, headers):
        self.headers = headers


def test_is_behind_cloudflare_true(monkeypatch):
    monkeypatch.setattr(waf, "CLOUDFLARE_TRUSTED", "true")
    req = _FakeReq({"CF-Connecting-IP": "1.2.3.4"})
    assert waf.is_behind_cloudflare(req) is True


def test_is_behind_cloudflare_no_header(monkeypatch):
    monkeypatch.setattr(waf, "CLOUDFLARE_TRUSTED", "true")
    assert waf.is_behind_cloudflare(_FakeReq({})) is False


def test_is_behind_cloudflare_disabled(monkeypatch):
    monkeypatch.setattr(waf, "CLOUDFLARE_TRUSTED", "false")
    assert waf.is_behind_cloudflare(_FakeReq({"CF-Connecting-IP": "1.2.3.4"})) is False


# ---------- 攻击特征正则（WAF 检测能力锁定） ----------
def test_sqli_detects_union_select():
    assert waf._SQLI.search("1' UNION SELECT * FROM users--") is not None


def test_sqli_detects_drop_table():
    assert waf._SQLI.search("; DROP TABLE users") is not None


def test_sqli_ignores_plain_text():
    # 正常文本含 select 不应误报（规则要求结构化成对关键字）
    assert waf._SQLI.search("please select a value") is None


def test_xss_detects_script_tag():
    assert waf._XSS.search("<script>alert(1)</script>") is not None


def test_xss_detects_event_handler():
    assert waf._XSS.search('<img onerror=alert(1)>') is not None


def test_traversal_detects_dotdot():
    assert waf._TRAVERSAL.search("../../etc/passwd") is not None


def test_scanner_detects_env_and_git():
    assert waf._SCANNER.search("/.env") is not None
    assert waf._SCANNER.search("/.git/config") is not None


def test_bad_ua_detects_sqlmap():
    assert waf._BAD_UA.search("sqlmap/1.5") is not None
