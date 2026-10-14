"""二维码生成工具（服务端渲染，无 Pillow 依赖）。

用途：微信支付 NATIVE 模式下单返回的是 code_url（一串 weixin:// 支付链接），
浏览器无法直接扫码，需要渲染成二维码图片。这里用 qrcode 的 SVG 工厂输出
矢量二维码，前端可直接内联/以 <img src> 引用。

设计：
  - 纯 SVG 路径输出，不依赖 Pillow；
  - qrcode 缺失时返回 None，调用方降级为回显原始链接字符串（不致命）。
"""
from __future__ import annotations

import io
import logging

logger = logging.getLogger(__name__)

try:
    import qrcode  # type: ignore
    import qrcode.image.svg  # type: ignore
    _QR_OK = True
except Exception:  # pragma: no cover - 环境缺库时降级
    _QR_OK = False


def qr_svg(data: str, box_size: int = 10, border: int = 2) -> str | None:
    """把字符串编码为 SVG 二维码；失败或未安装 qrcode 时返回 None。"""
    if not data or not _QR_OK:
        return None
    try:
        img = qrcode.make(
            data,
            image_factory=qrcode.image.svg.SvgPathImage,
            box_size=box_size,
            border=border,
        )
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception as e:  # pragma: no cover - 数据异常时降级
        logger.warning("二维码生成失败: %s", e)
        return None


def qr_available() -> bool:
    """当前环境是否具备二维码生成能力。"""
    return _QR_OK
