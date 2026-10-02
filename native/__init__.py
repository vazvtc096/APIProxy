"""APIProxy native accelerator bridge (C/C++ pillar of the multi-language architecture).

Loads the compiled shared library produced by ``build_native.py`` and exposes
``fnv1a_64`` and ``constant_time_compare``. If the native library is missing or
fails to load (or its self-test fails), pure-Python fallbacks are used so the
application keeps working on machines without a C toolchain.

Importing this package is cheap and side-effect free beyond a tiny self-test.
"""
import ctypes
import os
from ctypes import c_ubyte, c_uint64, c_int, POINTER

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
            native_available = True
            break
        except Exception:
            _lib = None

_FNV_OFFSET = 14695981039346656037


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


# Cheap self-test: catches ABI/toolchain mismatch early. On failure we disable
# the native path and fall back to pure Python instead of crashing the import.
def _selftest():
    assert fnv1a_64(b"") == _FNV_OFFSET
    assert fnv1a_64(b"hello") == _fnv1a_64_pure(b"hello")
    assert fnv1a_64("APIProxy") == _fnv1a_64_pure(b"APIProxy")
    assert constant_time_compare(b"abc", b"abc") is True
    assert constant_time_compare(b"abc", b"abd") is False
    assert constant_time_compare(b"abc", b"abcd") is False
    assert constant_time_compare("tok", "tok") is True


try:
    _selftest()
except Exception:
    _lib = None
    native_available = False
