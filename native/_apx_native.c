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
 *   void     apx_md5_hex(const char* in, int len, char* out32)   // 32-char lowercase hex
 *   void     apx_sha256_hex(const char* in, int len, char* out64) // 64-char lowercase hex
 *   int      apx_sliding_window_allow(const char* key, long long window_ms, int max)
 *           // thread-safe in-process sliding-window rate limiter; 1 = allow, 0 = deny
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#ifdef _WIN32
#include <windows.h>
static long long now_ms(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned long long t = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (long long)(t / 10000 - 11644473600000LL);
}
#else
#include <time.h>
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

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

/* ===========================================================================
 * MD5 (RFC 1321) — used by JA3 fingerprint hashing.
 * =========================================================================== */
static const uint32_t MD5_T[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
    0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
    0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
    0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
    0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
    0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const int MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static uint32_t md5_F(int n, uint32_t x, uint32_t y, uint32_t z) {
    if (n < 16) return (x & y) | (~x & z);
    if (n < 32) return (x & z) | (y & ~z);
    if (n < 48) return x ^ y ^ z;
    return y ^ (x | ~z);
}
static uint32_t md5_rotl(uint32_t x, int s) { return (x << s) | (x >> (32 - s)); }

static void md5_to_bytes(const unsigned char* msg, uint64_t len, unsigned char out[16]) {
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    uint64_t newlen = ((len + 8) / 64 + 1) * 64;
    unsigned char* m = (unsigned char*)calloc(newlen, 1);
    if (!m) return;
    memcpy(m, msg, len);
    m[len] = 0x80;
    uint64_t bitlen = len * 8;
    memcpy(m + newlen - 8, &bitlen, 8); /* little-endian bit length */
    for (uint64_t off = 0; off < newlen; off += 64) {
        uint32_t M[16];
        int i;
        for (i = 0; i < 16; i++) {
            M[i] = (uint32_t)m[off + 4*i]     | ((uint32_t)m[off + 4*i + 1] << 8) |
                  ((uint32_t)m[off + 4*i + 2] << 16) | ((uint32_t)m[off + 4*i + 3] << 24);
        }
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (i = 0; i < 64; i++) {
            uint32_t Fg = md5_F(i, B, C, D);
            uint32_t g = (i < 16) ? i : (i < 32) ? (5*i + 1) % 16
                                  : (i < 48) ? (3*i + 5) % 16 : (7*i) % 16;
            Fg = Fg + A + MD5_T[i] + M[g];
            A = D; D = C; C = B;
            B = B + md5_rotl(Fg, MD5_S[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    memcpy(out, &a0, 4); memcpy(out + 4, &b0, 4);
    memcpy(out + 8, &c0, 4); memcpy(out + 12, &d0, 4);
    free(m);
}

/* ===========================================================================
 * SHA-256 (FIPS 180-4) — used by synthetic JA3 fingerprint hashing.
 * =========================================================================== */
static const uint32_t SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t sha_rotr(uint32_t x, int s) { return (x >> s) | (x << (32 - s)); }

static void sha256_to_bytes(const unsigned char* msg, uint64_t len, unsigned char out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint64_t newlen = ((len + 8) / 64 + 1) * 64;
    unsigned char* m = (unsigned char*)calloc(newlen, 1);
    if (!m) return;
    memcpy(m, msg, len);
    m[len] = 0x80;
    uint64_t bitlen = len * 8;
    for (int i = 0; i < 8; i++) {
        m[newlen - 1 - i] = (unsigned char)((bitlen >> (8 * i)) & 0xff); /* big-endian */
    }
    for (uint64_t off = 0; off < newlen; off += 64) {
        uint32_t w[64];
        int i;
        for (i = 0; i < 16; i++) {
            w[i] = ((uint32_t)m[off + 4*i] << 24) | ((uint32_t)m[off + 4*i + 1] << 16) |
                   ((uint32_t)m[off + 4*i + 2] << 8) | ((uint32_t)m[off + 4*i + 3]);
        }
        for (i = 16; i < 64; i++) {
            uint32_t s0 = sha_rotr(w[i-15], 7) ^ sha_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = sha_rotr(w[i-2], 17) ^ sha_rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (i = 0; i < 64; i++) {
            uint32_t S1 = sha_rotr(e, 6) ^ sha_rotr(e, 11) ^ sha_rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + SHA_K[i] + w[i];
            uint32_t S0 = sha_rotr(a, 2) ^ sha_rotr(a, 13) ^ sha_rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (h[i] >> 24) & 0xff;
        out[4*i+1] = (h[i] >> 16) & 0xff;
        out[4*i+2] = (h[i] >> 8) & 0xff;
        out[4*i+3] = h[i] & 0xff;
    }
    free(m);
}

static const char HEX[] = "0123456789abcdef";
static void bytes_to_hex(const unsigned char* in, int n, char* out) {
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[(in[i] >> 4) & 0xf];
        out[2*i+1] = HEX[in[i] & 0xf];
    }
    out[2*n] = '\0';
}

__declspec(dllexport) void apx_md5_hex(const char* in, int len, char* out32) {
    unsigned char d[16];
    md5_to_bytes((const unsigned char*)in, (uint64_t)(len < 0 ? 0 : len), d);
    bytes_to_hex(d, 16, out32);
}

__declspec(dllexport) void apx_sha256_hex(const char* in, int len, char* out64) {
    unsigned char d[32];
    sha256_to_bytes((const unsigned char*)in, (uint64_t)(len < 0 ? 0 : len), d);
    bytes_to_hex(d, 32, out64);
}

/* ===========================================================================
 * In-process thread-safe sliding-window rate limiter.
 *
 * Backs the SQLite fallback in core_rate_limit.py for single-instance /
 * Redis-unavailable deployments: faster than a DB round-trip and semantically
 * equivalent (same "max events per window" rule). State is in-memory and resets
 * on process restart — acceptable for best-effort rate limiting.
 * =========================================================================== */
typedef struct SWNode {
    char* key;
    long long* ts;
    int cnt;
    int cap;
    struct SWNode* next;
} SWNode;

#define SW_BUCKETS 4096
static SWNode* sw_table[SW_BUCKETS];
static pthread_mutex_t sw_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long long sw_hash(const char* s) {
    unsigned long long h = 14695981039346656037ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h;
}

__declspec(dllexport) int apx_sliding_window_allow(const char* key, long long window_ms, int max) {
    if (max <= 0) return 0;
    long long now = now_ms();
    pthread_mutex_lock(&sw_lock);
    unsigned int b = (unsigned int)(sw_hash(key) & (SW_BUCKETS - 1));
    SWNode* n = sw_table[b];
    while (n) {
        if (strcmp(n->key, key) == 0) break;
        n = n->next;
    }
    if (!n) {
        n = (SWNode*)calloc(1, sizeof(SWNode));
        n->key = strdup(key);
        n->cap = 8;
        n->ts = (long long*)malloc(sizeof(long long) * n->cap);
        n->cnt = 0;
        n->next = sw_table[b];
        sw_table[b] = n;
    }
    /* prune timestamps outside the window */
    int w = 0;
    for (int i = 0; i < n->cnt; i++) {
        if (n->ts[i] > now - window_ms) n->ts[w++] = n->ts[i];
    }
    n->cnt = w;
    if (n->cnt >= max) {
        pthread_mutex_unlock(&sw_lock);
        return 0;
    }
    if (n->cnt >= n->cap) {
        n->cap *= 2;
        n->ts = (long long*)realloc(n->ts, sizeof(long long) * n->cap);
    }
    n->ts[n->cnt++] = now;
    pthread_mutex_unlock(&sw_lock);
    return 1;
}
