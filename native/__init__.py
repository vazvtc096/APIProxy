"""APIProxy native accelerator bridge (C/C++ pillar of the multi-language architecture).

Loads the compiled shared library produced by ``build_native.py`` and exposes
``fnv1a_64``, ``constant_time_compare``, ``md5_hex``, ``sha256_hex`` and
``sliding_window_allow``. If the native library is missing or fails to load (or
its self-test fails), pure-Python fallbacks are used so the application keeps
working on machines without a C toolchain.

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


try:
    _selftest()
except Exception:
    _lib = None
    native_available = False
