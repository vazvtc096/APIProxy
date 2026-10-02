/* APIProxy native accelerator — C/C++ pillar of the multi-language architecture.
 *
 * Built by native/build_native.py and loaded from Python via ctypes
 * (see native/__init__.py). A pure-Python fallback exists so the app keeps
 * working on machines without a C toolchain.
 *
 * Exposed functions:
 *   uint64_t apx_fnv1a_64(const unsigned char* data, int len)
 *   int      apx_constant_time_compare(const unsigned char* a, int la,
 *                                      const unsigned char* b, int lb)
 */
#include <stdint.h>

#define APX_FNV_OFFSET 14695981039346656037ULL
#define APX_FNV_PRIME  1099511628211ULL

/* FNV-1a 64-bit. Handles arbitrary bytes (including NUL). Empty input yields
 * the FNV offset basis, matching the pure-Python fallback in __init__.py. */
__declspec(dllexport) uint64_t apx_fnv1a_64(const unsigned char* data, int len) {
    uint64_t h = APX_FNV_OFFSET;
    int i;
    for (i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= APX_FNV_PRIME;
    }
    return h;
}

/* Constant-time compare. Returns 1 if equal length & content, else 0.
 * Content comparison does not short-circuit; length mismatch returns 0 early,
 * identical to Python's secrets.compare_digest semantics. */
__declspec(dllexport) int apx_constant_time_compare(const unsigned char* a, int la,
                                                    const unsigned char* b, int lb) {
    int i;
    unsigned char diff = 0;
    if (la != lb) return 0;
    for (i = 0; i < la; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return (diff == 0) ? 1 : 0;
}
