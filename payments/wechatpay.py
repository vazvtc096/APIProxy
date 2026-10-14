# -*- coding: utf-8 -*-
"""微信支付（v2 统一下单，XML + MD5 签名）适配器。

走 v2 接口的原因：无需上传 APIv3 证书，纯 appid/mch_id/APIv2 密钥即可用，
自托管部署门槛最低。如需退款/更高安全等级，可后续补 v3。

配置：
    enabled     bool
    appid       公众号/商户 appid
    mch_id      商户号
    api_key     APIv2 密钥（32 位）
    trade_type  NATIVE（扫码，返回 code_url，默认）| MWEB（H5，返回 mweb_url）
    client_ip   下单 IP（默认 127.0.0.1）
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets

from . import _http
from .base import PaymentProvider

_LEAF = re.compile(r"<(\w+)>(?:<!\[CDATA\[(.*?)\]\]>|([^<]*))</\1>", re.S)


class WechatPayProvider(PaymentProvider):
    type = "wechatpay"
    label = "微信支付"
    API = "https://api.mch.weixin.qq.com"

    def is_configured(self) -> bool:
        return bool(self.cfg.get("appid") and self.cfg.get("mch_id") and self.cfg.get("api_key"))

    # ---- 签名 / XML ----------------------------------------------------
    def _sign(self, params: dict) -> str:
        items = sorted(
            (k, str(v)) for k, v in params.items()
            if k != "sign" and v not in (None, "")
        )
        raw = "&".join(f"{k}={v}" for k, v in items) + "&key=" + str(self.cfg.get("api_key"))
        return hashlib.md5(raw.encode("utf-8")).hexdigest().upper()

    @staticmethod
    def _to_xml(params: dict) -> bytes:
        parts = ["<xml>"]
        for k, v in params.items():
            parts.append(f"<{k}><![CDATA[{v}]]></{k}>")
        parts.append("</xml>")
        return "".join(parts).encode("utf-8")

    @staticmethod
    def _parse_xml(text) -> dict:
        if isinstance(text, (bytes, bytearray)):
            text = text.decode("utf-8", "ignore")
        out = {}
        for m in _LEAF.finditer(str(text or "")):
            out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
        return out

    async def _xml_call(self, path, params):
        params = dict(params)
        params["sign"] = self._sign(params)
        code, data = await _http.post_raw(
            self.API + path, self._to_xml(params),
            headers={"Content-Type": "application/xml"})
        if not isinstance(data, dict):
            data = self._parse_xml(data)
        return code, data

    # ---- 下单 ----------------------------------------------------------
    async def create_order(self, request_id, amount, subject):
        trade_type = str(self.cfg.get("trade_type") or "NATIVE").upper()
        params = {
            "appid": str(self.cfg.get("appid")),
            "mch_id": str(self.cfg.get("mch_id")),
            "nonce_str": secrets.token_hex(16),
            "body": str(subject or "余额充值")[:127],
            "out_trade_no": str(request_id)[:32],
            "total_fee": self.to_cents(amount),
            "spbill_create_ip": str(self.cfg.get("client_ip") or "127.0.0.1"),
            "notify_url": self.notify_url(),
            "trade_type": trade_type,
        }
        if trade_type == "MWEB":
            params["scene_info"] = json.dumps({
                "h5_info": {"type": "Wap",
                            "wap_url": self._base_url(),
                            "wap_name": "APIProxy"}
            }, ensure_ascii=False)
        code, data = await self._xml_call("/pay/unifiedorder", params)
        if not isinstance(data, dict):
            return {"error": f"微信统一下单失败（HTTP {code}）"}
        if str(data.get("return_code")) != "SUCCESS":
            return {"error": str(data.get("return_msg") or "微信统一下单失败")}
        if str(data.get("result_code")) != "SUCCESS":
            return {"error": str(data.get("err_code_des") or data.get("err_code") or "微信统一下单失败")}
        return {
            "order_no": str(request_id),
            "pay_url": data.get("mweb_url") or "",
            "qr_code": data.get("code_url") or "",
            "prepay_id": str(data.get("prepay_id") or ""),
            "status": "PENDING",
            "raw": data,
        }

    # ---- 回调 ----------------------------------------------------------
    async def verify_callback(self, data, headers=None, raw=None):
        if not isinstance(data, dict) or not data:
            data = self._parse_xml(raw)
        if not isinstance(data, dict):
            return False
        sign = str(data.get("sign") or "")
        if not sign:
            return False
        return hmac.compare_digest(self._sign(data), sign.upper())

    async def parse_callback(self, data, headers=None, raw=None):
        if not isinstance(data, dict) or not data:
            data = self._parse_xml(raw)
        d = data if isinstance(data, dict) else {}
        ok = await self.verify_callback(data, headers, raw)
        trade_state = str(d.get("trade_state") or "")
        # 异步通知没有 trade_state，成功即代表已支付
        paid = ok and (str(d.get("result_code")) == "SUCCESS" or trade_state.upper() == "SUCCESS")
        return {
            "ok": ok,
            "request_id": str(d.get("out_trade_no") or ""),
            "order_no": str(d.get("transaction_id") or ""),
            "amount": (float(d.get("total_fee")) / 100.0) if str(d.get("total_fee") or "").isdigit() else None,
            "status": "PAID" if paid else self.normalize_status(trade_state),
            "event": "TRADE_SUCCESS" if paid else trade_state,
        }

    def callback_ack(self, ok: bool = True):
        rc = "SUCCESS" if ok else "FAIL"
        msg = "OK" if ok else "FAIL"
        body = ("<xml><return_code><![CDATA[%s]]></return_code>"
                "<return_msg><![CDATA[%s]]></return_msg></xml>" % (rc, msg))
        return body, "application/xml"

    # ---- 查单 ----------------------------------------------------------
    async def query_order(self, request_id, order_no=None):
        code, data = await self._xml_call("/pay/orderquery", {
            "appid": str(self.cfg.get("appid")),
            "mch_id": str(self.cfg.get("mch_id")),
            "out_trade_no": str(request_id)[:32],
            "nonce_str": secrets.token_hex(16),
        })
        if isinstance(data, dict):
            return {"status": self.normalize_status(data.get("trade_state")), "raw": data}
        return {"error": f"微信查单失败（HTTP {code}）"}
