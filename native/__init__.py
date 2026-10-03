"""APIProxy native accelerator bridge (C/C++ pillar of the multi-language architecture).

Loads the compiled shared library produced by ``build_native.py`` and exposes
``fnv1a_64``, ``constant_time_compare``, ``md5_hex``, ``sha256_hex``,
``sliding_window_allow`` and ``parse_client_hello``. If the native library is
missing or fails to load (or its self-test fails), pure-Python fallbacks are
used so the application keeps working on machines without a C toolchain.

Importing this package is cheap and side-effect free beyond a tiny self-test.
"""
import ctypes
import hashlib
import os
import time as _time
from ctypes import c_ubyte, c_uint64, c_int, c_char_p, c_longlong, POINTER

_HERE = os.path.dirname(os.path.abspath(__file__))
_DLL_CANDIDATES = (
    os.path.join(_HERE, "_apx_native.dll"),      # Windows (MinGW / MSVC build)
    os.path.join(_HERE, "libapx_native.so"),     # Linux
    os.path.join(_HERE, "libapx_native.dylib"), # macOS
)

_lib = None
native_available = False

for _p in _DLL_CANDIDATES:
    if os.path.exists(_p):
        try:
            _lib = ctypes.CDLL(_p)
            _lib.apx_fnv1a_64.restype = c_uint64
            _lib.apx_fnv1a_64.argtypes = [POINTER(c_ubyte), c_int]
            _lib.apx_constant_time_compare.restype = c_int
            _lib.apx_constant_time_compare.argtypes = [POINTER(c_ubyte), c_int, POINTER(c_ubyte), c_int]
            _lib.apx_md5_hex.restype = None
            _lib.apx_md5_hex.argtypes = [c_char_p, c_int, c_char_p]
            _lib.apx_sha256_hex.restype = None
            _lib.apx_sha256_hex.argtypes = [c_char_p, c_int, c_char_p]
            _lib.apx_sliding_window_allow.restype = c_int
            _lib.apx_sliding_window_allow.argtypes = [c_char_p, c_longlong, c_int]
            _lib.apx_parse_client_hello.restype = c_int
            _lib.apx_parse_client_hello.argtypes = [POINTER(c_ubyte), c_int,
                                                    c_char_p, c_int,
                                                    c_char_p, c_int,
                                                    c_char_p, c_int]
            native_available = True
            break
        except Exception:
            _lib = None

_FNV_OFFSET = 14695981039346656037


# ===========================================================================
# Pure-Python fallbacks (used when the native library is unavailable)
# ===========================================================================
def _fnv1a_64_pure(data: bytes) -> int:
    h = _FNV_OFFSET
    for byte in data:
        h ^= byte
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def _constant_time_compare_pure(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def _md5_hex_pure(data) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    return hashlib.md5(bytes(data)).hexdigest()


def _sha256_hex_pure(data) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    return hashlib.sha256(bytes(data)).hexdigest()


_SW_PURE: dict = {}


def _sliding_window_allow_pure(key: str, window_ms: int, max_n: int) -> bool:
    if max_n <= 0:
        return False
    now = _time.time() * 1000.0
    lst = _SW_PURE.setdefault(key, [])
    cut = now - window_ms
    while lst and lst[0] < cut:
        lst.pop(0)
    if len(lst) >= max_n:
        return False
    lst.append(now)
    return True


def _parse_client_hello_pure(hs: bytes):
    """Pure-Python ClientHello -> JA3 parser (mirrors tls_front.parse_client_hello).

    Returns (ja3_str, ja3_hash, sni) or None on malformed input. Used when the
    native library is unavailable so JA3 keeps working everywhere.
    """
    if not hs or hs[0] != 0x01:
        return None
    try:
        p = 4
        version = int.from_bytes(hs[p:p + 2], "big")
        p += 2 + 32
        sid_len = hs[p]
        p += 1 + sid_len
        cs_len = int.from_bytes(hs[p:p + 2], "big")
        p += 2
        ciphers = [int.from_bytes(hs[p + i * 2:p + i * 2 + 2], "big")
                   for i in range(cs_len // 2)]
        p += cs_len
        comp_len = hs[p]
        p += 1 + comp_len
        ext_total = int.from_bytes(hs[p:p + 2], "big") if p + 2 <= len(hs) else 0
        p += 2
        exts, curves, fmts, sni = [], [], [], ""
        end = min(p + ext_total, len(hs))
        while p + 4 <= end:
            etype = int.from_bytes(hs[p:p + 2], "big")
            elen = int.from_bytes(hs[p + 2:p + 4], "big")
            edata = hs[p + 4:p + 4 + elen]
            exts.append(etype)
            if etype == 0x000A and elen >= 2:
                gl = int.from_bytes(edata[0:2], "big")
                avail = (elen - 2) // 2
                curves = [int.from_bytes(edata[2 + i * 2:4 + i * 2], "big")
                          for i in range(min(gl, avail))]
            elif etype == 0x000B and elen >= 1:
                fmts = list(edata[1:1 + edata[0]])
            elif etype == 0x0000 and elen >= 5:
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
        return (ja3_str, hashlib.md5(ja3_str.encode("utf-8")).hexdigest(), sni)
    except Exception:
        return None


# ===========================================================================
# Public API
# ===========================================================================
def fnv1a_64(data) -> int:
    """FNV-1a 64-bit hash of *data* (bytes/str). Stable, fast key hash."""
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    data = bytes(data)
    n = len(data)
    if n == 0:
        return _FNV_OFFSET
    if _lib is None:
        return _fnv1a_64_pure(data)
    buf = (c_ubyte * n).from_buffer_copy(data)
    return _lib.apx_fnv1a_64(buf, n)


def constant_time_compare(a, b) -> bool:
    """Constant-time equality test for tokens/secrets. Accepts bytes or str."""
    if not isinstance(a, (bytes, bytearray)):
        a = str(a).encode("utf-8")
    if not isinstance(b, (bytes, bytearray)):
        b = str(b).encode("utf-8")
    a, b = bytes(a), bytes(b)
    if _lib is None:
        return _constant_time_compare_pure(a, b)
    la, lb = len(a), len(b)
    buf_a = (c_ubyte * la).from_buffer_copy(a) if la else None
    buf_b = (c_ubyte * lb).from_buffer_copy(b) if lb else None
    return bool(_lib.apx_constant_time_compare(buf_a, la, buf_b, lb))


def md5_hex(data) -> str:
    """MD5 hex digest (32 lowercase chars). Native when available, hashlib fallback."""
    if _lib is None:
        return _md5_hex_pure(data)
    b = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    out = ctypes.create_string_buffer(33)
    _lib.apx_md5_hex(b, len(b), out)
    return out.value.decode()


def sha256_hex(data) -> str:
    """SHA-256 hex digest (64 lowercase chars). Native when available, hashlib fallback."""
    if _lib is None:
        return _sha256_hex_pure(data)
    b = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    out = ctypes.create_string_buffer(65)
    _lib.apx_sha256_hex(b, len(b), out)
    return out.value.decode()


def sliding_window_allow(key: str, window: float, max_n: int) -> bool:
    """In-process sliding-window rate check. Native when available, pure fallback.

    *key*      — stable bucket key (e.g. ``"login:user:42"``)
    *window*   — window length in **seconds**
    *max_n*    — max allowed events within the window
    Returns True to allow, False to deny.
    """
    if _lib is None:
        return _sliding_window_allow_pure(key, int(window * 1000), max_n)
    return bool(_lib.apx_sliding_window_allow(key.encode("utf-8"), int(window * 1000), int(max_n)))


def parse_client_hello(hs) -> "tuple | None":
    """Parse a full TLS ClientHello handshake message into the standard JA3 tuple.

    *hs* must be the complete handshake message (first byte 0x01), as produced by
    ``tls_front.collect_hello``. Returns ``(ja3_str, ja3_hash, sni)`` or ``None``
    on malformed input. Uses the native C parser when available, else the
    pure-Python fallback — both are byte-identical.
    """
    if not isinstance(hs, (bytes, bytearray)):
        hs = bytes(hs)
    hs = bytes(hs)
    if _lib is None:
        return _parse_client_hello_pure(hs)
    n = len(hs)
    buf = (c_ubyte * n).from_buffer_copy(hs) if n else None
    sstr = ctypes.create_string_buffer(1024)
    shash = ctypes.create_string_buffer(33)
    ssni = ctypes.create_string_buffer(256)
    rc = _lib.apx_parse_client_hello(buf, n, sstr, 1024, shash, 33, ssni, 256)
    if not rc:
        return None
    return (sstr.value.decode("ascii", "replace"),
            shash.value.decode("ascii"),
            ssni.value.decode("ascii", "replace"))


# Cheap self-test: catches ABI/toolchain mismatch early. On failure we disable
# the native path and fall back to pure Python instead of crashing the import.
def _selftest():
    # FNV-1a + constant-time compare
    assert fnv1a_64(b"") == _FNV_OFFSET
    assert fnv1a_64(b"hello") == _fnv1a_64_pure(b"hello")
    assert fnv1a_64("APIProxy") == _fnv1a_64_pure(b"APIProxy")
    assert constant_time_compare(b"abc", b"abc") is True
    assert constant_time_compare(b"abc", b"abd") is False
    assert constant_time_compare(b"abc", b"abcd") is False
    assert constant_time_compare("tok", "tok") is True
    # MD5 + SHA-256 must match hashlib exactly
    for s in (b"", b"abc", b"APIProxy", "中文信号".encode("utf-8"),
              b"The quick brown fox jumps over the lazy dog"):
        assert md5_hex(s) == hashlib.md5(s if isinstance(s, bytes) else s).hexdigest()
        assert sha256_hex(s) == hashlib.sha256(s if isinstance(s, bytes) else s).hexdigest()
    # sliding-window semantics
    k = "selftest:" + str(id(object()))
    assert sliding_window_allow(k, 1.0, 2) is True
    assert sliding_window_allow(k, 1.0, 2) is True
    assert sliding_window_allow(k, 1.0, 2) is False
    # JA3 ClientHello parse: build a small valid ClientHello and verify the
    # native path matches the pure path AND the MD5 matches hashlib.
    def _sample_hello():
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
        cs = b"\x13\x01\x13\x02"
        body += len(cs).to_bytes(2, "big") + cs
        body += b"\x01\x00"
        sg = b"\x00\x02\x00\x1d\x00\x17"
        exts = b"\x00\x0a" + len(sg).to_bytes(2, "big") + sg
        ep = b"\x01\x00"
        exts += b"\x00\x0b" + len(ep).to_bytes(2, "big") + ep
        sn = b"\x00\x0a\x00" + b"\x00\x07" + b"example"
        exts += b"\x00\x00" + len(sn).to_bytes(2, "big") + sn
        body += len(exts).to_bytes(2, "big") + exts
        return b"\x01" + len(body).to_bytes(3, "big") + body
    hello = _sample_hello()
    res = parse_client_hello(hello)
    assert res is not None, "parse_client_hello returned None"
    js, jh, sni = res
    assert sni == "example", f"unexpected SNI: {sni!r}"
    assert jh == hashlib.md5(js.encode("utf-8")).hexdigest(), "JA3 hash mismatch"
    assert res == _parse_client_hello_pure(hello), "native/pure ClientHello mismatch"
    assert js == "771,4865-4866,10-11-0,29-23,0", f"unexpected ja3_str: {js!r}"


try:
    _selftest()
except Exception:
    _lib = None
    native_available = False
