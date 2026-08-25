"""内容安全纯函数：危险 HTML 净化、用户名校验。

从 core.py 拆分而来（阶段 2：God module 拆分），保持
`from APIProxy import core; core._sanitize_user_content` 等调用兼容。
"""
import re

_DANGEROUS_TAGS = re.compile(
    r'</?(script|iframe|object|embed|link|meta|style|form|input|button|'
    r'textarea|select|option|frame|frameset|svg|math|base|applet|img)[^>]*>',
    re.IGNORECASE
)
_DANGEROUS_ATTRS = re.compile(r'\s(on\w+)\s*=', re.IGNORECASE)
_JAVASCRIPT_URI = re.compile(r'javascript:', re.IGNORECASE)


def _sanitize_user_content(text: str) -> str:
    """净化用户生成内容，移除危险 HTML 标签、事件处理器和 javascript: 协议
    用于帖子、聊天消息、备注等存储型 XSS 防护（配合 Content-Security-Policy 头）
    多次迭代以处理嵌套/混淆标签（如 <scr<script>ipt>）
    """
    if not text or not isinstance(text, str):
        return text
    for _ in range(5):
        new = _DANGEROUS_TAGS.sub('', text)
        new = _DANGEROUS_ATTRS.sub(' ', new)
        new = _JAVASCRIPT_URI.sub('', new)
        if new == text:
            break
        text = new
    return text


_USERNAME_ALLOWED = re.compile(r'^[A-Za-z0-9_]+$')


def _is_safe_username(username: str) -> bool:
    """用户名只允许字母、数字、下划线（防止 XSS / 注入通过用户名载体）"""
    return bool(username) and _USERNAME_ALLOWED.match(username) is not None


# ---------- 安全常量 ----------
MIN_PASSWORD_LENGTH = 6
MAX_USERNAME_LENGTH = 32
