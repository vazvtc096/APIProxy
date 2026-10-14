# -*- coding: utf-8 -*-
"""可配置多支付方式框架。

统一入口见 `registry`：
    enabled(cfg)              —— 在线支付是否可用（总开关 + 至少一个渠道就绪）
    available_methods(cfg)    —— 前端可选支付方式列表
    all_methods(cfg)          —— 全部渠道状态（管理端）
    get_provider(cfg, type)   —— 取指定渠道实例
    enabled_providers(cfg)    —— 全部可用渠道实例
    PROVIDER_LABELS           —— type -> 展示名

内置渠道：epay（易支付）/ wechatpay（微信支付）/ alipay（支付宝）/
stripe / paypal。每个渠道的配置块由 `configs.PAYMENT['methods'][type]` 提供。
"""
from __future__ import annotations

from .base import PaymentProvider
from .registry import (
    PROVIDER_LABELS,
    all_methods,
    available_methods,
    build_all,
    enabled,
    enabled_providers,
    get_provider,
    provider_types,
    reload,
)

__all__ = [
    "PaymentProvider",
    "PROVIDER_LABELS",
    "all_methods",
    "available_methods",
    "build_all",
    "enabled",
    "enabled_providers",
    "get_provider",
    "provider_types",
    "reload",
]
