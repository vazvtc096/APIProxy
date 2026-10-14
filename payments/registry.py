# -*- coding: utf-8 -*-
"""支付渠道注册表 + 配置工厂。

设计要点：
  * 内置渠道懒加载，任一渠道 import 失败（缺可选依赖等）不影响其它渠道，
    也不影响主应用启动。
  * 配置形状（来自 configs.PAYMENT）：

        {
          "enabled": True,                 # 全局总开关
          "callback_base": "https://...",  # 拼 notify_url / return_url 用
          "methods": {
             "epay":      {"enabled": True, "api_url": ..., "pid": ..., "key": ...},
             "alipay":    {"enabled": True, ...},
             ...
          }
        }

  * `enabled_providers(cfg)` 只返回「启用且配置齐备」的实例。
"""
from __future__ import annotations

import importlib
import logging

logger = logging.getLogger(__name__)

#: type -> 默认展示名（Provider 类内另有 label，此处用于列表兜底）
PROVIDER_LABELS = {
    "epay": "易支付",
    "wechatpay": "微信支付",
    "alipay": "支付宝",
    "stripe": "Stripe",
    "paypal": "PayPal",
}

#: type -> (模块名, 类名)，模块相对本包
_BUILTINS = {
    "epay": ("epay", "EpayProvider"),
    "wechatpay": ("wechatpay", "WechatPayProvider"),
    "alipay": ("alipay", "AlipayProvider"),
    "stripe": ("stripe", "StripeProvider"),
    "paypal": ("paypal", "PayPalProvider"),
}

_CLASSES = {}
_LOADED = False


def _ensure_loaded():
    global _LOADED
    if _LOADED:
        return
    for ptype, (modname, clsname) in _BUILTINS.items():
        try:
            mod = importlib.import_module("." + modname, __package__)
            _CLASSES[ptype] = getattr(mod, clsname)
        except Exception as e:  # noqa: BLE001 - 单渠道失败不影响整体
            logger.warning("payment provider '%s' unavailable: %s", ptype, e)
    _LOADED = True


def reload():
    """测试用：重置懒加载状态。"""
    global _LOADED
    _CLASSES.clear()
    _LOADED = False


def provider_types():
    _ensure_loaded()
    return list(_CLASSES.keys())


def _callback_base(payment_cfg):
    return str((payment_cfg or {}).get("callback_base") or "").rstrip("/")


def build_all(payment_cfg) -> dict:
    """构造全部已注册渠道实例（不论启用与否）。返回 {type: provider}。"""
    _ensure_loaded()
    methods = (payment_cfg or {}).get("methods") or {}
    base = _callback_base(payment_cfg)
    out = {}
    for ptype, cls in _CLASSES.items():
        cfg = dict(methods.get(ptype) or {})
        if base:
            cfg.setdefault("callback_base", base)
        try:
            out[ptype] = cls(name=ptype, config=cfg)
        except Exception as e:  # noqa: BLE001
            logger.warning("build provider '%s' failed: %s", ptype, e)
    return out


def enabled_providers(payment_cfg) -> dict:
    """只返回「启用且配置齐备」的渠道。"""
    return {t: p for t, p in build_all(payment_cfg).items() if p.enabled}


def get_provider(payment_cfg, ptype):
    return build_all(payment_cfg).get(str(ptype or ""))


def available_methods(payment_cfg) -> list:
    """给前端的可选支付方式列表（仅启用且配置齐备的）。"""
    return [p.describe() for p in enabled_providers(payment_cfg).values()]


def all_methods(payment_cfg) -> list:
    """全部渠道状态（含未启用/未配置），供管理端展示。"""
    return [p.describe() for p in build_all(payment_cfg).values()]


def enabled(payment_cfg) -> bool:
    """在线支付总开关：全局 enabled 且至少一个渠道可用。"""
    return bool((payment_cfg or {}).get("enabled")) and bool(enabled_providers(payment_cfg))
