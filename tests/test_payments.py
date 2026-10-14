# -*- coding: utf-8 -*-
"""payments 多支付框架单元测试（纯本地，无网络）。

覆盖：注册表/工厂、启用判定、可用方式列表、状态归一、各渠道签名
往返（含篡改拒绝）、微信 XML 收发、Stripe Webhook 验签、回调解析。

从 E:/Code 运行：
    python -m pytest APIProxy/tests/test_payments.py -q --noconftest
"""
import asyncio
import hashlib
import hmac
import json

from APIProxy import payments
from APIProxy.payments import registry
from APIProxy.payments.alipay import AlipayProvider
from APIProxy.payments.epay import EpayProvider
from APIProxy.payments.stripe import StripeProvider
from APIProxy.payments.wechatpay import WechatPayProvider


def _rsa_pair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


# ---- 注册表 / 工厂 ---------------------------------------------------------

def test_builtin_types_registered():
    types = payments.provider_types()
    for t in ("epay", "wechatpay", "alipay", "stripe", "paypal"):
        assert t in types, t
    assert payments.PROVIDER_LABELS["epay"] == "易支付"
    assert payments.PROVIDER_LABELS["alipay"] == "支付宝"


def test_enabled_requires_config():
    cfg = {"enabled": True, "callback_base": "https://x", "methods": {
        "epay": {"enabled": True},                                  # 缺 api_url/pid/key
        "stripe": {"enabled": True, "secret_key": "sk_test_x"},
    }}
    provs = registry.enabled_providers(cfg)
    assert "stripe" in provs
    assert "epay" not in provs          # 未配置齐备 → 视为不可用
    assert registry.enabled(cfg) is True


def test_enabled_false_when_master_off():
    cfg = {"enabled": False, "methods": {"stripe": {"enabled": True, "secret_key": "sk"}}}
    assert registry.enabled(cfg) is False


def test_available_methods_shape():
    cfg = {"enabled": True, "callback_base": "https://x",
           "methods": {"stripe": {"enabled": True, "secret_key": "sk_test_x"}}}
    methods = payments.available_methods(cfg)
    assert len(methods) == 1
    m = methods[0]
    assert m["type"] == "stripe" and m["label"] == "Stripe" and m["enabled"] is True


def test_notify_and_return_urls():
    p = EpayProvider(config={"api_url": "https://pay.x", "pid": "1", "key": "k",
                             "callback_base": "https://api.x/"})
    assert p.notify_url() == "https://api.x/api/recharge/callback/epay"
    assert p.return_url("req7").endswith("/dashboard/recharge?rid=req7")


def test_normalize_status():
    norm = payments.PaymentProvider.normalize_status
    assert norm("TRADE_SUCCESS") == "PAID"
    assert norm("trade_finished") == "PAID"
    assert norm("TRADE_CLOSED") == "CLOSED"
    assert norm("PAYERROR") == "FAILED"
    assert norm("USERPAYING") == "PENDING"


# ---- 易支付 ---------------------------------------------------------------

def test_epay_sign_roundtrip_and_tamper():
    p = EpayProvider(config={"api_url": "https://pay.x", "pid": "1001", "key": "secret"})
    params = {"pid": "1001", "out_trade_no": "req1", "money": "10.00",
              "trade_status": "TRADE_SUCCESS"}
    params["sign"] = p._sign(params)
    assert asyncio.run(p.verify_callback(dict(params))) is True
    params["money"] = "999.00"          # 篡改金额
    assert asyncio.run(p.verify_callback(dict(params))) is False


def test_epay_parse_callback_paid():
    p = EpayProvider(config={"api_url": "https://pay.x", "pid": "1", "key": "k"})
    d = {"pid": "1", "out_trade_no": "req6", "trade_no": "TN1",
         "money": "12.00", "trade_status": "TRADE_SUCCESS"}
    d["sign"] = p._sign(d)
    res = asyncio.run(p.parse_callback(d))
    assert res["ok"] is True
    assert res["status"] == "PAID"
    assert res["order_no"] == "TN1"
    assert res["request_id"] == "req6"


# ---- 微信支付 -------------------------------------------------------------

def test_wechat_xml_roundtrip_and_sign():
    p = WechatPayProvider(config={"appid": "wx1", "mch_id": "m1", "api_key": "k" * 32})
    params = {"appid": "wx1", "mch_id": "m1", "nonce_str": "abc", "out_trade_no": "req3"}
    parsed = p._parse_xml(p._to_xml(params))
    assert parsed["appid"] == "wx1" and parsed["out_trade_no"] == "req3"
    assert p._sign(params) == p._sign(dict(params))
    assert len(p._sign(params)) == 32


def test_wechat_verify_and_parse_from_raw_xml():
    p = WechatPayProvider(config={"appid": "wx1", "mch_id": "m1", "api_key": "k" * 32})
    fields = {"appid": "wx1", "mch_id": "m1", "out_trade_no": "req4",
              "result_code": "SUCCESS", "total_fee": "250"}
    fields["sign"] = p._sign(fields)
    raw = p._to_xml(fields)
    res = asyncio.run(p.parse_callback({}, raw=raw))
    assert res["ok"] is True
    assert res["request_id"] == "req4"
    assert res["status"] == "PAID"
    assert abs(res["amount"] - 2.5) < 1e-9
    # 篡改后验签失败
    bad = dict(fields, total_fee="999")
    assert asyncio.run(p.verify_callback(bad)) is False


# ---- 支付宝 ---------------------------------------------------------------

def test_alipay_sign_verify_roundtrip():
    priv, pub = _rsa_pair()
    p = AlipayProvider(config={"app_id": "2021", "private_key": priv, "alipay_public_key": pub})
    params = {"app_id": "2021", "out_trade_no": "req2",
              "total_amount": "5.00", "trade_status": "TRADE_SUCCESS"}
    params["sign"] = p._sign(params)
    params["sign_type"] = "RSA2"
    assert asyncio.run(p.verify_callback(dict(params))) is True
    params["total_amount"] = "6.00"     # 篡改
    assert asyncio.run(p.verify_callback(dict(params))) is False


def test_alipay_bare_base64_private_key():
    priv, pub = _rsa_pair()
    bare = "".join(priv.strip().splitlines()[1:-1])
    p = AlipayProvider(config={"app_id": "2021", "private_key": bare, "alipay_public_key": pub})
    params = {"app_id": "2021", "out_trade_no": "req8", "total_amount": "1.00"}
    params["sign"] = p._sign(params)     # 裸 base64 也能签名
    assert params["sign"]


# ---- Stripe ---------------------------------------------------------------

def test_stripe_webhook_signature_and_parse():
    secret = "whsec_test"
    p = StripeProvider(config={"secret_key": "sk_test_x", "webhook_secret": secret})
    payload = json.dumps({
        "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_1", "client_reference_id": "req5",
                            "payment_status": "paid", "amount_total": 300}},
    })
    raw = payload.encode()
    t = "1234567890"
    sig = hmac.new(secret.encode(), ("%s.%s" % (t, payload)).encode(),
                   hashlib.sha256).hexdigest()
    headers = {"Stripe-Signature": "t=%s,v1=%s" % (t, sig)}
    assert asyncio.run(p.verify_callback(json.loads(payload), headers=headers, raw=raw)) is True
    res = asyncio.run(p.parse_callback(json.loads(payload), headers=headers, raw=raw))
    assert res["ok"] is True and res["status"] == "PAID"
    assert res["request_id"] == "req5"
    assert abs(res["amount"] - 3.0) < 1e-9
    # 篡改签名 → 拒绝
    bad = {"Stripe-Signature": "t=%s,v1=%s" % (t, "0" * 64)}
    assert asyncio.run(p.verify_callback(json.loads(payload), headers=bad, raw=raw)) is False
