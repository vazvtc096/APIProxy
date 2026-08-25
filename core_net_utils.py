"""网络/OAuth 纯函数：CIDR 匹配、URI 校验、scope 匹配。

从 core.py 拆分而来（阶段 2：God module 拆分），保持
`from APIProxy import core; core._ip_in_cidr` 等调用兼容。
"""
import ipaddress
from urllib.parse import urlparse


def _ip_in_cidr(client_ip: str, entry: str) -> bool:
    """判断 client_ip 是否匹配白名单条目（支持精确 IP 与 CIDR 网段）。"""
    entry = (entry or '').strip()
    if not entry:
        return False
    if '/' in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return ipaddress.ip_address(client_ip) in net
        except ValueError:
            return False
    return client_ip == entry


def _is_absolute_http_uri(uri: str) -> bool:
    """redirect_uri 必须是 http(s) 绝对地址（允许外部/第三方回调，不强制同源）。"""
    try:
        p = urlparse(uri)
        return p.scheme in ('http', 'https') and bool(p.netloc)
    except Exception:
        return False


def _scope_satisfied(required, granted: set) -> list:
    """返回未满足的 scope 需求列表（'a|b' 表示满足其一即可）。"""
    return [r for r in required if not any(o in granted for o in r.split('|'))]
