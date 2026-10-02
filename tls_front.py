# -*- coding: utf-8 -*-
"""tls_front.py —— 自建 TLS 前置代理：终结 TLS + 真实 JA3 指纹注入。

背景：
  本项目原先部署在 Cloudflare 边缘之后，浏览器侧 TLS 由 CF 终结，
  真实 JA3 依赖 CF Enterprise 的 "Add bot protection headers" 透传
  （cf-ja3-hash / cf-ja4）。CF 暂时不可用时，由本模块自建边缘：

      浏览器 --TLS--> tls_front(:5443) --HTTP/1.1--> Hypercorn(127.0.0.1:5000)

工作原理：
  1. accept 后用 MSG_PEEK 抓取 TLS ClientHello（不消费内核缓冲区），
     手工解析出五元组（版本/密码套件/扩展/椭圆曲线/点格式），
     按标准 JA3 算法生成 ja3_str 与 MD5（与 ja3.parse_ja3_string 同构，可互相校验）。
  2. ssl_context.wrap_socket() 终结 TLS（peek 不消费数据，握手不受影响）；
     ALPN 仅提供 http/1.1，避免 h2 升级带来的转发复杂度。
  3. 每个 HTTP 请求：剥离客户端伪造的指纹类头（x-ja3* / cf-ja3* / cf-bot-score 等），
     注入 X-JA3-String / X-JA3-Hash / X-Forwarded-For / X-Real-IP，加 Connection: close
     转发给后端；响应按字节透传（天然支持 SSE / chunked 流式）。
  4. 客户端侧保持 HTTP/1.1 keep-alive（同一 TLS 连接可承载多个请求），
     后端侧每请求一条连接，响应读至 EOF 即为该响应结束。

接线（零改动）：
  ja3.py 的指纹优先级链第 2 层「自定义反代透传」已原生支持 x-ja3（原始元组，
  自带 parse_ja3_string 校验），本模块注入即生效，source=header、synthetic=False。

安全语义：
  - 指纹头由本代理强制覆盖，外部无法伪造（剥离在注入之前无条件执行）；
  - 后端应绑定 127.0.0.1（config.yaml BIND_HOST），绕过本代理直连 :5000 者只能拿合成指纹；
  - 若将来 Cloudflare 回归且指向本代理，cf-* 头来自 CF 本体（不可伪造），优先级更高；
    但注意 CF->源站 TLS 的 ClientHello 是 CF 自己的栈，X-JA3-String 将描述 CF 而非访客，
    此时以 cf-ja3-hash 为准（ja3.py 优先级已保证）。

已知限制（第一版）：
  - 仅 JA3（JA4 规范化复杂，后续需要再补）；
  - 不支持 WebSocket 升级（检测到 Upgrade 头直接 501，明确报错优于静默卡死）；
  - 请求体按 Content-Length / chunked 流式转发，不落盘不整体缓冲。

运行：
    python tls_front.py            # 前台运行
配置（env > config.yaml > 默认值）：
    TLS_FRONT_BIND_HOST    默认 ::（双栈：同时接受 IPv4 与 IPv6；0.0.0.0 = 仅 IPv4）
    TLS_FRONT_PORT         默认 5443
    TLS_FRONT_BACKEND_HOST 默认 127.0.0.1
    TLS_FRONT_BACKEND_PORT 默认 5000
    TLS_FRONT_CERT         默认 certs/server.crt
    TLS_FRONT_KEY          默认 certs/server.key
    TLS_FRONT_PLAIN_REDIRECT  纯 HTTP 打到 TLS 端口时 301 跳转（默认 true）
"""
import hashlib
import os
import socket
import ssl
import sys
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# ---------------------------------------------------------------------------
# 配置（env > config.yaml > 默认值；复用 configs 的解析但不触发任何 DB/应用初始化）
# ---------------------------------------------------------------------------
try:
    import configs as _configs  # 同目录 configs.py，导入安全
except Exception:
    _configs = None


def _cfg(key, default):
    v = os.getenv(key)
    if v is not None:
        return v
    if _configs is not None:
        try:
            raw = getattr(_configs, "_RAW", None) or {}
            val = raw.get(key)
            if val is not None:
                return val
        except Exception:
            pass
    return default


BIND_HOST = str(_cfg("TLS_FRONT_BIND_HOST", "0.0.0.0"))
PORT = int(_cfg("TLS_FRONT_PORT", 5443))
BACKEND_HOST = str(_cfg("TLS_FRONT_BACKEND_HOST", "127.0.0.1"))
BACKEND_PORT = int(_cfg("TLS_FRONT_BACKEND_PORT", 5000))
CERT_FILE = str(_cfg("TLS_FRONT_CERT", os.path.join(BASE_DIR, "certs", "server.crt")))
KEY_FILE = str(_cfg("TLS_FRONT_KEY", os.path.join(BASE_DIR, "certs", "server.key")))
PLAIN_REDIRECT = str(_cfg("TLS_FRONT_PLAIN_REDIRECT", "true")).strip().lower() in ("1", "true", "yes", "on")
IDLE_TIMEOUT = float(_cfg("TLS_FRONT_IDLE_TIMEOUT", 75))      # keep-alive 空闲
HANDSHAKE_TIMEOUT = float(_cfg("TLS_FRONT_HANDSHAKE_TIMEOUT", 15))
BACKEND_TIMEOUT = float(_cfg("TLS_FRONT_BACKEND_TIMEOUT", 15))
MAX_HEAD_BYTES = 65536

# 无条件剥离的客户端请求头（防伪造：真实指纹只在注入处产生）
STRIP_PREFIXES = (
    b"x-ja3", b"x-ja4", b"x-ssl-ja3", b"x-tls-ja3", b"ja4:",
    b"cf-ja3", b"cf-ja4", b"cf-bot-score", b"cf-verified-bot", b"cf-ipcountry",
    b"cf-connecting-ip",
    b"x-forwarded-for", b"x-real-ip", b"proxy-connection", b"keep-alive",
)

_stats_lock = threading.Lock()
_stats = {"conns": 0, "requests": 0, "errors": 0, "started": time.time()}


def _bump(key, n=1):
    with _stats_lock:
        _stats[key] += n


def _normalize_ip(peer_ip: str) -> str:
    """IPv4-mapped IPv6 地址（::ffff:a.b.c.d）归一化回 IPv4。

    双栈监听下 IPv4 客户端在套接字层表现为 ::ffff:x.y.z.w，若不归一化，
    XFF/JA3 限流/WAF/封禁都会把它当成另一个（畸形的）IP 处理。
    """
    if peer_ip and peer_ip.startswith("::ffff:") and "." in peer_ip:
        return peer_ip[7:]
    return peer_ip


# ===========================================================================
# ClientHello 解析（标准 JA3）
# ===========================================================================
def _hello_span(buf: bytes):
    """从 TLS record 流中提取完整的 ClientHello 握手消息。

    返回 (status, hs)：status = 'tls'（hs 为完整握手消息）| 'more'（需继续等）| 'plain'（非 TLS）
    """
    pos = 0
    hs = b""
    while True:
        if len(buf) - pos < 5:
            return ("more", None)
        rec_type = buf[pos]
        rec_len = int.from_bytes(buf[pos + 3:pos + 5], "big")
        if len(buf) - pos - 5 < rec_len:
            return ("more", None)
        payload = buf[pos + 5:pos + 5 + rec_len]
        pos += 5 + rec_len
        if rec_type != 22:
            # 第一个 record 不是 handshake：纯 HTTP 或垃圾流量
            return ("plain", None)
        hs += payload
        if len(hs) >= 4:
            hs_len = int.from_bytes(hs[1:4], "big")
            if len(hs) >= 4 + hs_len:
                return ("tls", hs[:4 + hs_len])


def parse_client_hello(hs: bytes):
    """解析完整 ClientHello 握手消息 → (ja3_str, ja3_hash, sni)。

    算法与 ja3.parse_ja3_string 严格同构：Version,Ciphers,Extensions,Curves,PointFormats。
    GREASE 值按原版 JA3 规范保留原值。
    """
    if not hs or hs[0] != 0x01:
        return None
    try:
        p = 4
        version = int.from_bytes(hs[p:p + 2], "big")
        p += 2 + 32                                   # version + random
        sid_len = hs[p]
        p += 1 + sid_len                              # session id
        cs_len = int.from_bytes(hs[p:p + 2], "big")
        p += 2
        ciphers = [int.from_bytes(hs[p + i * 2:p + i * 2 + 2], "big")
                   for i in range(cs_len // 2)]
        p += cs_len
        comp_len = hs[p]
        p += 1 + comp_len                             # compression
        ext_total = int.from_bytes(hs[p:p + 2], "big") if p + 2 <= len(hs) else 0
        p += 2
        exts, curves, fmts, sni = [], [], [], ""
        end = min(p + ext_total, len(hs))
        while p + 4 <= end:
            etype = int.from_bytes(hs[p:p + 2], "big")
            elen = int.from_bytes(hs[p + 2:p + 4], "big")
            edata = hs[p + 4:p + 4 + elen]
            exts.append(etype)
            if etype == 0x000A and elen >= 2:         # supported_groups
                gl = int.from_bytes(edata[0:2], "big")
                curves = [int.from_bytes(edata[2 + i * 2:4 + i * 2], "big")
                          for i in range(min(gl, elen - 2) // 2)]
            elif etype == 0x000B and elen >= 1:       # ec_point_formats
                fmts = list(edata[1:1 + edata[0]])
            elif etype == 0x0000 and elen >= 5:       # server_name（仅记录用）
                try:
                    slen = edata[4]
                    sni = edata[5:5 + slen].decode("ascii", "ignore")
                except Exception:
                    pass
            p += 4 + elen
        ja3_str = ",".join([
            str(version),
            "-".join(map(str, ciphers)),
            "-".join(map(str, exts)),
            "-".join(map(str, curves)),
            "-".join(map(str, fmts)),
        ])
        return ja3_str, hashlib.md5(ja3_str.encode("utf-8")).hexdigest(), sni
    except (IndexError, ValueError, struct_error := Exception):
        return None


def collect_hello(sock) -> tuple:
    """MSG_PEEK 循环收集完整 ClientHello（不消费数据）。返回 ('tls', hs) / ('plain', first_data) / (None, None)。"""
    sock.settimeout(HANDSHAKE_TIMEOUT)
    while True:
        try:
            data = sock.recv(65535, socket.MSG_PEEK)
        except socket.timeout:
            return (None, None)
        except OSError:
            return (None, None)
        if not data:
            return (None, None)
        if data[0] != 0x16:
            # TLS ClientHello 的 record 首字节恒为 0x16，否则是纯 HTTP/垃圾流量
            return ("plain", data)
        status, hs = _hello_span(data)
        if status == "tls":
            return ("tls", hs)
        if status == "plain":
            return ("plain", data)
        # 'more'：继续等（阻塞 recv 会等到下一包或超时）


# ===========================================================================
# 带缓冲的连接读取器
# ===========================================================================
class ConnBuf:
    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def _fill(self):
        data = self.s.recv(65536)
        if not data:
            raise ConnectionError("peer closed")
        self.buf += data

    def read_until(self, delim: bytes, cap: int) -> bytes:
        while delim not in self.buf:
            if len(self.buf) > cap:
                raise ValueError("head too large")
            self._fill()
        head, self.buf = self.buf.split(delim, 1)
        return head

    def read_exact(self, n: int, sink) -> None:
        """把恰好 n 字节推给 sink（流式，不整体缓冲）。"""
        while n > 0:
            if self.buf:
                take = min(n, len(self.buf))
                sink(self.buf[:take])
                self.buf = self.buf[take:]
                n -= take
                continue
            data = self.s.recv(min(65536, n))
            if not data:
                raise ConnectionError("body truncated")
            sink(data)
            n -= len(data)

    def discard(self, n: int) -> None:
        while n > 0:
            if self.buf:
                take = min(n, len(self.buf))
                self.buf = self.buf[take:]
                n -= take
                continue
            data = self.s.recv(min(65536, n))
            if not data:
                raise ConnectionError("truncated")
            n -= len(data)


# ===========================================================================
# HTTP 转发
# ===========================================================================
def _send_simple(sock, status, reason, extra=b""):
    body = f"{status} {reason}".encode()
    head = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n{extra.decode() if extra else ''}\r\n")
    try:
        sock.sendall(head.encode() + body)
    except OSError:
        pass


def _rewrite_request_head(head: bytes, ja3_str: str, ja3_hash: str, peer_ip: str) -> bytes:
    """剥离伪造头 + 注入真实指纹头。"""
    lines = head.split(b"\r\n")
    kept = [lines[0]]
    for ln in lines[1:]:
        if not ln:
            continue
        low = ln.split(b":", 1)[0].strip().lower()
        if low.startswith(STRIP_PREFIXES) or low in (b"connection",):
            continue
        kept.append(ln)
    kept.append(b"Connection: close")
    kept.append(b"X-JA3-String: " + ja3_str.encode("ascii", "replace"))
    kept.append(b"X-JA3-Hash: " + ja3_hash.encode())
    kept.append(b"X-Forwarded-For: " + peer_ip.encode())
    kept.append(b"X-Real-IP: " + peer_ip.encode())
    kept.append(b"X-TLS-Front: 1")
    return b"\r\n".join(kept) + b"\r\n\r\n"


def _forward_request_body(buf: ConnBuf, head: bytes, backend_sock) -> None:
    low = head.lower()
    if b"\r\ntransfer-encoding:" in low and b"chunked" in low:
        # 流式透传 chunked：逐块转发（尺寸行 + 数据 + CRLF），直到 0 块与结尾 CRLF
        while True:
            size_line = buf.read_until(b"\r\n", 8192)
            backend_sock.sendall(size_line + b"\r\n")
            size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
            if size == 0:
                # trailers：读到空行
                while True:
                    line = buf.read_until(b"\r\n", 8192)
                    backend_sock.sendall(line + b"\r\n")
                    if line == b"":
                        break
                break
            buf.read_exact(size, lambda d: backend_sock.sendall(d))
            crlf = buf.read_until(b"\r\n", 8)
            backend_sock.sendall(crlf + b"\r\n")
        return
    # Content-Length（默认 0 = 无请求体）
    clen = 0
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(b"content-length:"):
            try:
                clen = int(ln.split(b":", 1)[1].strip())
            except ValueError:
                clen = 0
            break
    if clen > 0:
        buf.read_exact(clen, lambda d: backend_sock.sendall(d))


def _proxy_request(csock, cbuf: ConnBuf, head: bytes, ja3_str: str, ja3_hash: str, peer_ip: str):
    """转发单个请求并透传响应（读至后端 EOF）。"""
    new_head = _rewrite_request_head(head, ja3_str, ja3_hash, peer_ip)
    bsock = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=BACKEND_TIMEOUT)
    try:
        bsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        bsock.settimeout(IDLE_TIMEOUT)
        bsock.sendall(new_head)
        _forward_request_body(cbuf, new_head, bsock)

        # 响应：读头部（记日志用）→ 发头部与残留 → 透传到 EOF
        bbuf = ConnBuf(bsock)
        rhead = bbuf.read_until(b"\r\n\r\n", MAX_HEAD_BYTES)
        status_line = rhead.split(b"\r\n", 1)[0]
        csock.sendall(rhead + b"\r\n\r\n")
        leftover = bbuf.buf
        if leftover:
            csock.sendall(leftover)
            bbuf.buf = b""
        while True:
            data = bsock.recv(65536)
            if not data:
                break
            csock.sendall(data)
        return status_line
    finally:
        try:
            bsock.close()
        except OSError:
            pass


def _handle_plain_http(sock, first_data: bytes):
    """纯 HTTP 打到 TLS 端口：301 跳转到 https（或直接 400）。"""
    if not PLAIN_REDIRECT:
        _send_simple(sock, 400, "TLS required")
        return
    try:
        raw = first_data
        sock.settimeout(5)
        while b"\r\n\r\n" not in raw and len(raw) < MAX_HEAD_BYTES:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
        head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        req_line = head.split("\r\n", 1)[0]
        parts = req_line.split()
        path = parts[1] if len(parts) >= 2 else "/"
        host = ""
        for ln in head.split("\r\n")[1:]:
            if ln.lower().startswith("host:"):
                host = ln.split(":", 1)[1].strip()
                break
        if not host:
            _send_simple(sock, 400, "Bad Request")
            return
        loc = f"https://{host}{path}"
        _send_simple(sock, 301, "Moved Permanently", f"Location: {loc}\r\n".encode())
    except Exception:
        pass


def handle_conn(sock: socket.socket, addr):
    _bump("conns")
    peer_ip = _normalize_ip(addr[0] if isinstance(addr, tuple) else str(addr))
    ja3_str, ja3_hash, sni = "", "", ""
    tls_sock = None
    try:
        status, payload = collect_hello(sock)
        if status != "tls":
            if status == "plain":
                _handle_plain_http(sock, payload)
            return
        parsed = parse_client_hello(payload)
        if not parsed:
            return
        ja3_str, ja3_hash, sni = parsed

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        sock.settimeout(IDLE_TIMEOUT)
        tls_sock = ctx.wrap_socket(sock, server_side=True)
        cbuf = ConnBuf(tls_sock)

        while True:
            try:
                head = cbuf.read_until(b"\r\n\r\n", MAX_HEAD_BYTES)
            except socket.timeout:
                return                                   # keep-alive 空闲
            except (ConnectionError, ssl.SSLError, OSError):
                return
            if not head:
                return
            _bump("requests")
            req_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            # WebSocket 升级不支持：明确拒绝
            if b"upgrade:" in head.lower():
                _send_simple(tls_sock, 501, "WebSocket upgrade not supported by tls_front")
                return
            try:
                status_line = _proxy_request(tls_sock, cbuf, head, ja3_str, ja3_hash, peer_ip)
                print(f"[tls_front] {peer_ip} {req_line} -> {status_line.decode('latin-1', 'replace')[:60]}"
                      f"  ja3={ja3_hash[:12]}{' sni=' + sni if sni else ''}", flush=True)
            except (ConnectionError, socket.timeout) as e:
                _bump("errors")
                try:
                    _send_simple(tls_sock, 502, "Bad Gateway")
                except OSError:
                    pass
                print(f"[tls_front] {peer_ip} {req_line[:60]} backend error: {e}", flush=True)
                return
            except (ValueError, ssl.SSLError, OSError) as e:
                _bump("errors")
                print(f"[tls_front] {peer_ip} {req_line[:60]} error: {e}", flush=True)
                return
    except (ssl.SSLError, OSError) as e:
        _bump("errors")
        print(f"[tls_front] {peer_ip} conn error: {e}", flush=True)
    finally:
        for s in (tls_sock, sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


# ===========================================================================
# 服务入口
# ===========================================================================
def serve():
    ctx_info = f"{CERT_FILE} + {KEY_FILE}"
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print(f"[tls_front] 证书不存在: {ctx_info}", flush=True)
        sys.exit(2)

    # 双栈支持：BIND_HOST 含冒号视为 IPv6 地址。绑 "::"（默认）时关闭
    # IPV6_V6ONLY，同一端口同时接受 IPv4（内核自动映射）与 IPv6 连接；
    # 绑 "::1" 则仅 IPv6 回环。Windows/Windows Server 上 IPv6 套接字默认
    # V6ONLY=1，必须显式关掉才有双栈效果。
    if ":" in BIND_HOST:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if BIND_HOST == "::":
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        srv.bind((BIND_HOST, PORT))
    else:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((BIND_HOST, PORT))
    srv.listen(128)
    mode = "dual-stack (IPv4+IPv6)" if (":" in BIND_HOST and BIND_HOST == "::") else (
        "IPv6 only" if ":" in BIND_HOST else "IPv4 only")
    print(f"[tls_front] listening on {BIND_HOST}:{PORT} [{mode}]  ->  http://{BACKEND_HOST}:{BACKEND_PORT}", flush=True)
    print(f"[tls_front] cert: {ctx_info}", flush=True)
    print(f"[tls_front] JA3 injection: X-JA3-String / X-JA3-Hash (spoof-proof)", flush=True)

    while True:
        try:
            sock, addr = srv.accept()
        except OSError:
            break
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handle_conn, args=(sock, addr), daemon=True).start()


def status() -> dict:
    with _stats_lock:
        s = dict(_stats)
    s["uptime_sec"] = int(time.time() - s.pop("started", time.time()))
    return s


if __name__ == "__main__":
    serve()
