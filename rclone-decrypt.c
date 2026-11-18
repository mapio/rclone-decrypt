/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Massimo Santini */

/*
 * rclone-decrypt - decrypt an rclone crypt directory, without rclone.
 *
 * Build:  cc -O2 -o rclone-decrypt rclone-decrypt.c
 * Run:    rclone-decrypt --help
 *
 * Written in C99 with POSIX.1-2008 for directories, the terminal and file
 * times; it needs libc and nothing else. Every primitive is implemented
 * here from its specification, one section each, named at its head. The
 * format is rclone's (https://rclone.org/crypt/); where that page is silent,
 * the behaviour follows rclone's source as of v1.75.2, and the comment says
 * which file: backend/crypt/cipher.go, fs/config/obscure/obscure.go,
 * backend/crypt/pkcs7/pkcs7.go, and the libraries cipher.go imports,
 * github.com/rfjakob/eme and github.com/Max-Sum/base32768.
 *
 * The format, in short:
 *
 *   keys     scrypt(password, salt, N=16384, r=8, p=1) gives 80 bytes: the
 *            data key (32), the name key (32), the name tweak (16). The salt
 *            is the crypt's password2, or rclone's fixed default salt.
 *   contents "RCLONE\0\0", a 24-byte nonce, then chunks of 64 KiB of
 *            plaintext, the last one shorter, each sealed as a NaCl
 *            secretbox (XSalsa20 and a Poly1305 tag of 16 bytes in front)
 *            under the data key; the nonce, a little-endian counter, is
 *            incremented by one after each chunk.
 *   names    each path segment PKCS#7-padded to 16 bytes, enciphered with
 *            EME over AES-256 under the name key and tweak, then written in
 *            base32 (RFC 4648's hex alphabet, lower case, no padding),
 *            base64 (URL alphabet, no padding) or base32768.
 *
 * Sections:
 *    1. Utilities
 *    2. SHA-256 and HMAC-SHA-256
 *    3. PBKDF2-HMAC-SHA-256
 *    4. Salsa20 core and scrypt
 *    5. XSalsa20, Poly1305 and the NaCl secretbox
 *    6. AES-256 and AES-CTR
 *    7. EME and PKCS#7
 *    8. UTF-8, base32, base64 and base32768
 *    9. rclone crypt: keys, obscured values, names, file contents
 *   10. Self-test
 *   11. The tree and the command line
 */

#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

/* ===================================================================== */
/* 1. Utilities                                                          */
/* ===================================================================== */

static const char *progname = "rclone-decrypt";

/* Exit statuses: 0 all done, 1 some path failed, 2 nothing could be done. */
#define EXIT_SOME_FAILED 1
#define EXIT_FATAL 2

static void die(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "%s: ", progname);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FATAL);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        die("out of memory");
    return p;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xmalloc(n), s, n);
}

/* "a/b", or b alone when a is empty. */
static char *join(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    char *p = xmalloc(la + lb + 2);
    if (la == 0) {
        memcpy(p, b, lb + 1);
        return p;
    }
    memcpy(p, a, la);
    p[la] = '/';
    memcpy(p + la + 1, b, lb + 1);
    return p;
}

/* Overwrite secrets before freeing them. */
static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--)
        *v++ = 0;
}

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t load32_be(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           (uint32_t)p[3];
}

static void store32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

/* Read n bytes, or fewer only at end of file; -1 on error. */
static ssize_t read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (uint8_t *)buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int write_full(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, (const uint8_t *)buf + done, n - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)w;
    }
    return 0;
}

/* ===================================================================== */
/* 2. SHA-256 (FIPS 180-4, section 6.2) and HMAC-SHA-256 (RFC 2104)      */
/* ===================================================================== */

typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    size_t buflen;
    uint64_t total; /* bytes hashed so far */
} sha256_ctx;

/* FIPS 180-4, 4.2.2: the first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes. */
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void sha256_init(sha256_ctx *c)
{
    /* FIPS 180-4, 5.3.3 */
    static const uint32_t h0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                   0xa54ff53a, 0x510e527f, 0x9b05688c,
                                   0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, h0, sizeof h0);
    c->buflen = 0;
    c->total = 0;
}

/* FIPS 180-4, 6.2.2: process one 64-byte block. */
static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
    int t;
    for (t = 0; t < 16; t++)
        w[t] = load32_be(p + 4 * t);
    for (t = 16; t < 64; t++) {
        uint32_t s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^
                      (w[t - 15] >> 3);
        uint32_t s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^
                      (w[t - 2] >> 10);
        w[t] = s1 + w[t - 7] + s0 + w[t - 16];
    }
    a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (t = 0; t < 64; t++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t1 = h + S1 + ch + sha256_k[t] + w[t];
        t2 = S0 + maj;
        h = g, g = f, f = e, e = d + t1;
        d = cc, cc = b, b = a, a = t1 + t2;
    }
    c->h[0] += a, c->h[1] += b, c->h[2] += cc, c->h[3] += d;
    c->h[4] += e, c->h[5] += f, c->h[6] += g, c->h[7] += h;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    c->total += n;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n)
            take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take, p += take, n -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

/* FIPS 180-4, 5.1.1: pad with 1, zeros, and the length in bits. */
static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->total * 8;
    uint8_t one = 0x80, zero = 0, len[8];
    int i;
    sha256_update(c, &one, 1);
    while (c->buflen != 56)
        sha256_update(c, &zero, 1);
    for (i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, len, 8);
    for (i = 0; i < 8; i++)
        store32_be(out + 4 * i, c->h[i]);
}

/* HMAC (RFC 2104): H((K ^ opad) || H((K ^ ipad) || message)). The context
 * holds both hashes already keyed, so that it can be copied and reused. */
typedef struct {
    sha256_ctx inner, outer;
} hmac_ctx;

static void hmac_init(hmac_ctx *c, const uint8_t *key, size_t keylen)
{
    uint8_t k[64], pad[64];
    int i;
    memset(k, 0, sizeof k);
    if (keylen > 64) {
        sha256_ctx t;
        sha256_init(&t);
        sha256_update(&t, key, keylen);
        sha256_final(&t, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x36;
    sha256_init(&c->inner);
    sha256_update(&c->inner, pad, 64);
    for (i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x5c;
    sha256_init(&c->outer);
    sha256_update(&c->outer, pad, 64);
    wipe(k, sizeof k);
    wipe(pad, sizeof pad);
}

static void hmac_update(hmac_ctx *c, const void *data, size_t n)
{
    sha256_update(&c->inner, data, n);
}

static void hmac_final(hmac_ctx *c, uint8_t out[32])
{
    uint8_t ih[32];
    sha256_final(&c->inner, ih);
    sha256_update(&c->outer, ih, 32);
    sha256_final(&c->outer, out);
}

/* ===================================================================== */
/* 3. PBKDF2-HMAC-SHA-256 (RFC 8018, section 5.2)                        */
/* ===================================================================== */

static void pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt,
                          size_t saltlen, uint32_t iterations, uint8_t *out,
                          size_t outlen)
{
    hmac_ctx keyed, c;
    uint32_t block, j;
    hmac_init(&keyed, pw, pwlen);
    for (block = 1; outlen > 0; block++) {
        uint8_t u[32], t[32], be[4];
        size_t k, n = outlen < 32 ? outlen : 32;
        /* U_1 = PRF(P, S || INT(i)) */
        c = keyed;
        hmac_update(&c, salt, saltlen);
        store32_be(be, block);
        hmac_update(&c, be, 4);
        hmac_final(&c, u);
        memcpy(t, u, 32);
        /* U_j = PRF(P, U_{j-1}); T_i = U_1 ^ U_2 ^ ... ^ U_c */
        for (j = 1; j < iterations; j++) {
            c = keyed;
            hmac_update(&c, u, 32);
            hmac_final(&c, u);
            for (k = 0; k < 32; k++)
                t[k] ^= u[k];
        }
        memcpy(out, t, n);
        out += n, outlen -= n;
    }
    wipe(&keyed, sizeof keyed);
    wipe(&c, sizeof c);
}

/* ===================================================================== */
/* 4. Salsa20 core (Bernstein, "Salsa20 specification", 2005, and RFC    */
/*    7914 section 3) and scrypt (RFC 7914, sections 4 to 6)             */
/* ===================================================================== */

/* The quarterround on words a, b, c, d of the state, each word written
 * through the macro W, and the doubleround, a column round then a row
 * round, as the specification defines them. */
#define QUARTERROUND(W, a, b, c, d)                                            \
    W(b) ^= rotl32(W(a) + W(d), 7);                                            \
    W(c) ^= rotl32(W(b) + W(a), 9);                                            \
    W(d) ^= rotl32(W(c) + W(b), 13);                                           \
    W(a) ^= rotl32(W(d) + W(c), 18);
#define DOUBLEROUND(Q)                                                         \
    Q(0, 4, 8, 12) Q(5, 9, 13, 1) Q(10, 14, 2, 6) Q(15, 3, 7, 11)              \
    Q(0, 1, 2, 3) Q(5, 6, 7, 4) Q(10, 11, 8, 9) Q(15, 12, 13, 14)

/* The Salsa20 core over 16 little-endian words: `rounds` rounds (8 for
 * scrypt's Salsa20/8, 20 for Salsa20 itself), then, if feedforward, the
 * input added word by word. HSalsa20 is the 20-round core without it. */
static void salsa20_core(uint32_t out[16], const uint32_t in[16], int rounds,
                         int feedforward)
{
#define WORD(i) x[i]
#define QR1(a, b, c, d) QUARTERROUND(WORD, a, b, c, d)
    uint32_t x[16];
    int i;
    memcpy(x, in, sizeof x);
    for (i = 0; i < rounds; i += 2) {
        DOUBLEROUND(QR1)
    }
    for (i = 0; i < 16; i++)
        out[i] = feedforward ? x[i] + in[i] : x[i];
#undef WORD
#undef QR1
}

/* Four Salsa20/20 blocks at once, for speed alone: the state `in` with the
 * block counters counter to counter + 3 in words 8 and 9, each block in a
 * lane, out[word][lane], so that compilers can keep the four in vector
 * registers. */
static void salsa20_x4(uint32_t out[16][4], const uint32_t in[16],
                       uint64_t counter)
{
#define LANE(i) x[i][j]
#define QR4(a, b, c, d)                                                        \
    for (j = 0; j < 4; j++) {                                                  \
        QUARTERROUND(LANE, a, b, c, d)                                         \
    }
    uint32_t s[16][4], x[16][4];
    int i, j, k;
    for (k = 0; k < 16; k++)
        for (j = 0; j < 4; j++)
            s[k][j] = in[k];
    for (j = 0; j < 4; j++) {
        s[8][j] = (uint32_t)(counter + (uint64_t)j);
        s[9][j] = (uint32_t)((counter + (uint64_t)j) >> 32);
    }
    memcpy(x, s, sizeof x);
    for (i = 0; i < 20; i += 2) {
        DOUBLEROUND(QR4)
    }
    for (k = 0; k < 16; k++)
        for (j = 0; j < 4; j++)
            out[k][j] = x[k][j] + s[k][j];
#undef LANE
#undef QR4
}

/* scryptBlockMix (RFC 7914, section 4) on 2r blocks of 16 words; y is
 * scratch space of the same size. */
static void scrypt_blockmix(uint32_t *b, uint32_t *y, size_t r)
{
    uint32_t x[16];
    size_t i, k;
    memcpy(x, &b[(2 * r - 1) * 16], 64);
    for (i = 0; i < 2 * r; i++) {
        for (k = 0; k < 16; k++)
            x[k] ^= b[i * 16 + k];
        salsa20_core(x, x, 8, 1);
        memcpy(&y[i * 16], x, 64);
    }
    /* B' = (Y_0, Y_2, ..., Y_{2r-2}, Y_1, Y_3, ..., Y_{2r-1}) */
    for (i = 0; i < r; i++) {
        memcpy(&b[i * 16], &y[2 * i * 16], 64);
        memcpy(&b[(r + i) * 16], &y[(2 * i + 1) * 16], 64);
    }
}

/* scrypt (RFC 7914, sections 5 and 6), N a power of two. */
static void scrypt(const uint8_t *pw, size_t pwlen, const uint8_t *salt,
                   size_t saltlen, uint32_t n, size_t r, size_t p,
                   uint8_t *out, size_t outlen)
{
    size_t words = 32 * r; /* one block of 128r bytes, in 32-bit words */
    uint8_t *b = xmalloc(p * 128 * r);
    uint32_t *x = xmalloc(words * 4), *y = xmalloc(words * 4);
    uint32_t *v = xmalloc((size_t)n * words * 4);
    size_t i, k;
    uint32_t j;

    pbkdf2_sha256(pw, pwlen, salt, saltlen, 1, b, p * 128 * r);
    for (i = 0; i < p; i++) {
        uint8_t *bi = b + i * 128 * r;
        /* scryptROMix (section 5) */
        for (k = 0; k < words; k++)
            x[k] = load32_le(bi + 4 * k);
        for (j = 0; j < n; j++) {
            memcpy(&v[(size_t)j * words], x, words * 4);
            scrypt_blockmix(x, y, r);
        }
        for (j = 0; j < n; j++) {
            /* Integerify: the last 64-byte block's first word, mod N */
            uint32_t idx = x[(2 * r - 1) * 16] & (n - 1);
            for (k = 0; k < words; k++)
                x[k] ^= v[(size_t)idx * words + k];
            scrypt_blockmix(x, y, r);
        }
        for (k = 0; k < words; k++)
            store32_le(bi + 4 * k, x[k]);
    }
    pbkdf2_sha256(pw, pwlen, b, p * 128 * r, 1, out, outlen);

    wipe(b, p * 128 * r);
    wipe(v, (size_t)n * words * 4);
    wipe(x, words * 4);
    wipe(y, words * 4);
    free(b), free(x), free(y), free(v);
}

/* ===================================================================== */
/* 5. XSalsa20 (Bernstein, "Extending the Salsa20 nonce", 2011),         */
/*    Poly1305 (RFC 8439, section 2.5) and NaCl's crypto_secretbox       */
/*    (Bernstein, "Cryptography in NaCl", 2009, sections 7 to 9)         */
/* ===================================================================== */

/* The Salsa20 input matrix: the constants "expand 32-byte k" on the
 * diagonal, the key in words 1-4 and 11-14, `in` (nonce and counter, or
 * HSalsa20's 16-byte input) in words 6-9. */
static void salsa20_setup(uint32_t x[16], const uint8_t key[32],
                          const uint8_t in[16])
{
    int i;
    x[0] = 0x61707865, x[5] = 0x3320646e, x[10] = 0x79622d32,
    x[15] = 0x6b206574;
    for (i = 0; i < 4; i++) {
        x[1 + i] = load32_le(key + 4 * i);
        x[11 + i] = load32_le(key + 16 + 4 * i);
        x[6 + i] = load32_le(in + 4 * i);
    }
}

/* HSalsa20: the 20-round core without feedforward; words 0, 5, 10, 15, 6,
 * 7, 8, 9 of the result are the subkey. */
static void hsalsa20(uint8_t out[32], const uint8_t key[32],
                     const uint8_t in[16])
{
    static const int pick[8] = {0, 5, 10, 15, 6, 7, 8, 9};
    uint32_t x[16], z[16];
    int i;
    salsa20_setup(x, key, in);
    salsa20_core(z, x, 20, 0);
    for (i = 0; i < 8; i++)
        store32_le(out + 4 * i, z[pick[i]]);
    wipe(x, sizeof x);
    wipe(z, sizeof z);
}

/* Poly1305 one-time authenticator, in radix 2^26 (the arithmetic of
 * Andrew Moon's public-domain poly1305-donna-32). */
static void poly1305(uint8_t tag[16], const uint8_t *m, size_t n,
                     const uint8_t key[32])
{
    /* r, clamped: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff */
    const uint32_t r0 = load32_le(key + 0) & 0x3ffffff;
    const uint32_t r1 = (load32_le(key + 3) >> 2) & 0x3ffff03;
    const uint32_t r2 = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    const uint32_t r3 = (load32_le(key + 9) >> 6) & 0x3f03fff;
    const uint32_t r4 = (load32_le(key + 12) >> 8) & 0x00fffff;
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, c, mask;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t d0, d1, d2, d3, d4, f;
    uint8_t last[16];

    while (n > 0) {
        /* Each 16-byte block, as a number with a 1 bit above it; a final
         * short block gets its 1 as a byte right after the message. */
        const uint8_t *blk = m;
        uint32_t hibit = 1u << 24;
        if (n < 16) {
            memset(last, 0, sizeof last);
            memcpy(last, m, n);
            last[n] = 1;
            blk = last;
            hibit = 0;
            n = 0;
        } else {
            m += 16, n -= 16;
        }
        /* h += block */
        h0 += load32_le(blk + 0) & 0x3ffffff;
        h1 += (load32_le(blk + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(blk + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(blk + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(blk + 12) >> 8) | hibit;
        /* h *= r, mod 2^130 - 5 */
        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
             (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
             (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
             (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
             (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
             (uint64_t)h3 * r1 + (uint64_t)h4 * r0;
        c = (uint32_t)(d0 >> 26), h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c, c = (uint32_t)(d1 >> 26), h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c, c = (uint32_t)(d2 >> 26), h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c, c = (uint32_t)(d3 >> 26), h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c, c = (uint32_t)(d4 >> 26), h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5, c = h0 >> 26, h0 &= 0x3ffffff;
        h1 += c;
    }

    /* carry fully */
    c = h1 >> 26, h1 &= 0x3ffffff;
    h2 += c, c = h2 >> 26, h2 &= 0x3ffffff;
    h3 += c, c = h3 >> 26, h3 &= 0x3ffffff;
    h4 += c, c = h4 >> 26, h4 &= 0x3ffffff;
    h0 += c * 5, c = h0 >> 26, h0 &= 0x3ffffff;
    h1 += c;
    /* g = h - (2^130 - 5); take g if it did not go negative */
    g0 = h0 + 5, c = g0 >> 26, g0 &= 0x3ffffff;
    g1 = h1 + c, c = g1 >> 26, g1 &= 0x3ffffff;
    g2 = h2 + c, c = g2 >> 26, g2 &= 0x3ffffff;
    g3 = h3 + c, c = g3 >> 26, g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);
    mask = (g4 >> 31) - 1; /* all ones when h >= 2^130 - 5 */
    g0 &= mask, g1 &= mask, g2 &= mask, g3 &= mask, g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0, h1 = (h1 & mask) | g1, h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3, h4 = (h4 & mask) | g4;
    /* h mod 2^128, as four 32-bit words */
    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);
    /* tag = (h + s) mod 2^128, s the key's second half */
    f = (uint64_t)h0 + load32_le(key + 16), h0 = (uint32_t)f;
    f = (uint64_t)h1 + load32_le(key + 20) + (f >> 32), h1 = (uint32_t)f;
    f = (uint64_t)h2 + load32_le(key + 24) + (f >> 32), h2 = (uint32_t)f;
    f = (uint64_t)h3 + load32_le(key + 28) + (f >> 32), h3 = (uint32_t)f;
    store32_le(tag + 0, h0);
    store32_le(tag + 4, h1);
    store32_le(tag + 8, h2);
    store32_le(tag + 12, h3);
}

/* crypto_secretbox_open as NaCl defines it, on the box as rclone and Go's
 * golang.org/x/crypto/nacl/secretbox store it: the 16-byte tag, then the
 * ciphertext. The XSalsa20 keystream's first 32 bytes are the Poly1305 key;
 * the rest encrypts the message. Returns 0 and writes boxlen - 16 bytes of
 * plaintext, or -1, writing nothing, if the tag does not verify. */
static int secretbox_open(uint8_t *out, const uint8_t *box, size_t boxlen,
                          const uint8_t nonce[24], const uint8_t key[32])
{
    uint8_t subkey[32], in[16], block[64], tag[16], ks[256];
    uint32_t x[16], z[16], z4[16][4];
    const uint8_t *ct = box + 16;
    size_t ctlen = boxlen - 16, pos, k, n, j;
    unsigned diff = 0;
    uint64_t counter = 0;

    if (boxlen < 16)
        return -1;
    /* XSalsa20: subkey from the nonce's first 16 bytes, then Salsa20 with
     * its last 8 as nonce and a 64-bit block counter from 0. */
    hsalsa20(subkey, key, nonce);
    memcpy(in, nonce + 16, 8);
    memset(in + 8, 0, 8);
    salsa20_setup(x, subkey, in);
    salsa20_core(z, x, 20, 1);
    for (k = 0; k < 16; k++)
        store32_le(block + 4 * k, z[k]);

    poly1305(tag, ct, ctlen, block);
    for (k = 0; k < 16; k++)
        diff |= tag[k] ^ box[k];
    if (diff != 0) {
        wipe(subkey, sizeof subkey);
        return -1;
    }

    /* Plaintext byte i is ciphertext byte i ^ keystream byte 32 + i. */
    n = ctlen < 32 ? ctlen : 32;
    for (k = 0; k < n; k++)
        out[k] = ct[k] ^ block[32 + k];
    /* Then blocks 1, 2, ..., four at a time. */
    for (pos = 32; pos < ctlen; pos += 256, counter += 4) {
        salsa20_x4(z4, x, counter + 1);
        n = ctlen - pos < 256 ? ctlen - pos : 256;
        if (n == 256) { /* four whole blocks, a word at a time */
            for (j = 0; j < 4; j++)
                for (k = 0; k < 16; k++) {
                    size_t at = pos + 64 * j + 4 * k;
                    store32_le(out + at, load32_le(ct + at) ^ z4[k][j]);
                }
            continue;
        }
        for (j = 0; j < 4; j++)
            for (k = 0; k < 16; k++)
                store32_le(ks + 64 * j + 4 * k, z4[k][j]);
        for (k = 0; k < n; k++)
            out[pos + k] = ct[pos + k] ^ ks[k];
    }
    wipe(subkey, sizeof subkey);
    wipe(x, sizeof x);
    wipe(block, sizeof block);
    wipe(ks, sizeof ks);
    wipe(z4, sizeof z4);
    return 0;
}

/* ===================================================================== */
/* 6. AES-256 (FIPS-197) and AES-CTR (NIST SP 800-38A, section 6.5)      */
/* ===================================================================== */

/* Byte-oriented and table-free but for the S-box, which is computed from
 * its definition: AES here only handles names and passwords, never file
 * contents, so speed and timing do not matter. */

static uint8_t aes_sbox[256], aes_inv_sbox[256];

/* Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (FIPS-197, 4.2) */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    while (b) {
        if (b & 1)
            p ^= a;
        a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
        b >>= 1;
    }
    return p;
}

/* FIPS-197, 5.1.1: the multiplicative inverse, then the affine map. */
static void aes_init_tables(void)
{
    int x, i;
    for (x = 0; x < 256; x++) {
        uint8_t inv = 0, s;
        if (x) { /* x^254 = x^-1 */
            inv = 1;
            for (i = 0; i < 254; i++)
                inv = gf_mul(inv, (uint8_t)x);
        }
        s = inv;
        for (i = 1; i <= 4; i++)
            s ^= (uint8_t)((inv << i) | (inv >> (8 - i)));
        s ^= 0x63;
        aes_sbox[x] = s;
        aes_inv_sbox[s] = (uint8_t)x;
    }
}

typedef struct {
    uint8_t rk[240]; /* 15 round keys of 16 bytes */
} aes256;

/* FIPS-197, 5.2: key expansion, Nk = 8, Nr = 14. */
static void aes256_init(aes256 *a, const uint8_t key[32])
{
    uint8_t rcon = 1, t[4], u;
    int i, k;
    if (aes_sbox[0] != 0x63)
        aes_init_tables();
    memcpy(a->rk, key, 32);
    for (i = 8; i < 60; i++) {
        memcpy(t, a->rk + 4 * (i - 1), 4);
        if (i % 8 == 0) { /* SubWord(RotWord(t)) ^ Rcon */
            u = t[0], t[0] = t[1], t[1] = t[2], t[2] = t[3], t[3] = u;
            for (k = 0; k < 4; k++)
                t[k] = aes_sbox[t[k]];
            t[0] ^= rcon;
            rcon = gf_mul(rcon, 2);
        } else if (i % 8 == 4) { /* SubWord(t) */
            for (k = 0; k < 4; k++)
                t[k] = aes_sbox[t[k]];
        }
        for (k = 0; k < 4; k++)
            a->rk[4 * i + k] = a->rk[4 * (i - 8) + k] ^ t[k];
    }
}

/* The state is the 16 bytes in input order: s[4 * column + row]. */

static void aes_add_round_key(uint8_t s[16], const uint8_t *rk)
{
    int i;
    for (i = 0; i < 16; i++)
        s[i] ^= rk[i];
}

/* FIPS-197, 5.1.2 and 5.3.1: row r rotates left, or right, by r. */
static void aes_shift_rows(uint8_t s[16], int inverse)
{
    uint8_t t[16];
    int r, c;
    for (r = 0; r < 4; r++)
        for (c = 0; c < 4; c++) {
            if (inverse)
                t[4 * ((c + r) % 4) + r] = s[4 * c + r];
            else
                t[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    memcpy(s, t, 16);
}

/* FIPS-197, 5.1.3 and 5.3.3: each column times a fixed polynomial,
 * {03}x^3 + {01}x^2 + {01}x + {02}, or its inverse
 * {0b}x^3 + {0d}x^2 + {09}x + {0e}. */
static void aes_mix_columns(uint8_t s[16], int inverse)
{
    static const uint8_t fwd[4] = {2, 3, 1, 1}, inv[4] = {14, 11, 13, 9};
    const uint8_t *m = inverse ? inv : fwd;
    int c, r, k;
    for (c = 0; c < 4; c++) {
        uint8_t a[4], b;
        memcpy(a, s + 4 * c, 4);
        for (r = 0; r < 4; r++) {
            b = 0;
            for (k = 0; k < 4; k++)
                b ^= gf_mul(m[(k - r + 4) % 4], a[k]);
            s[4 * c + r] = b;
        }
    }
}

/* FIPS-197, 5.1: Cipher */
static void aes256_encrypt(const aes256 *a, uint8_t out[16],
                           const uint8_t in[16])
{
    uint8_t s[16];
    int round, i;
    memcpy(s, in, 16);
    aes_add_round_key(s, a->rk);
    for (round = 1; round <= 14; round++) {
        for (i = 0; i < 16; i++)
            s[i] = aes_sbox[s[i]];
        aes_shift_rows(s, 0);
        if (round != 14)
            aes_mix_columns(s, 0);
        aes_add_round_key(s, a->rk + 16 * round);
    }
    memcpy(out, s, 16);
}

/* FIPS-197, 5.3: InvCipher */
static void aes256_decrypt(const aes256 *a, uint8_t out[16],
                           const uint8_t in[16])
{
    uint8_t s[16];
    int round, i;
    memcpy(s, in, 16);
    aes_add_round_key(s, a->rk + 16 * 14);
    for (round = 13; round >= 0; round--) {
        aes_shift_rows(s, 1);
        for (i = 0; i < 16; i++)
            s[i] = aes_inv_sbox[s[i]];
        aes_add_round_key(s, a->rk + 16 * round);
        if (round != 0)
            aes_mix_columns(s, 1);
    }
    memcpy(out, s, 16);
}

/* CTR mode: the IV is a 128-bit big-endian counter, as in Go's
 * crypto/cipher.NewCTR, which rclone's obscure.go uses. */
static void aes256_ctr(const aes256 *a, uint8_t *buf, size_t n,
                       const uint8_t iv[16])
{
    uint8_t ctr[16], ks[16];
    size_t i;
    int k;
    memcpy(ctr, iv, 16);
    for (i = 0; i < n; i++) {
        if (i % 16 == 0) {
            aes256_encrypt(a, ks, ctr);
            for (k = 15; k >= 0 && ++ctr[k] == 0; k--)
                ;
        }
        buf[i] ^= ks[i % 16];
    }
}

/* ===================================================================== */
/* 7. EME (Halevi and Rogaway, "A Parallelizable Enciphering Mode",      */
/*    2003) and PKCS#7 padding (RFC 5652, section 6.3)                   */
/* ===================================================================== */

/* Doubling in GF(2^128), in the byte order of rfjakob/eme's multByTwo:
 * byte 0 is the least significant, and the carry out of byte 15 folds
 * back as 135 (x^7 + x^2 + x + 1). */
static void eme_double(uint8_t b[16])
{
    uint8_t carry = b[15] >> 7;
    int j;
    for (j = 15; j > 0; j--)
        b[j] = (uint8_t)((b[j] << 1) | (b[j - 1] >> 7));
    b[0] = (uint8_t)((b[0] << 1) ^ (carry ? 135 : 0));
}

static void xor16(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    int i;
    for (i = 0; i < 16; i++)
        out[i] = a[i] ^ b[i];
}

/* EME decryption, step for step as rfjakob/eme's Transform (eme.go, which
 * rclone's cipher.go calls) with direction decrypt: len a multiple of 16,
 * 1 to 128 blocks; out may be in. Note that L comes from AES encryption
 * of zero in either direction. */
static void eme_decrypt(const aes256 *a, const uint8_t tweak[16],
                        uint8_t *out, const uint8_t *in, size_t len)
{
    static uint8_t l[128][16];
    uint8_t li[16], mp[16], mc[16], m[16], ccc1[16];
    size_t nblocks = len / 16, j;

    /* L_j = 2^(j+1) * AES-enc(K, 0) */
    memset(li, 0, 16);
    aes256_encrypt(a, li, li);
    for (j = 0; j < nblocks; j++) {
        eme_double(li);
        memcpy(l[j], li, 16);
    }
    /* PPP_j = AES(P_j ^ L_j) */
    for (j = 0; j < nblocks; j++) {
        xor16(out + 16 * j, in + 16 * j, l[j]);
        aes256_decrypt(a, out + 16 * j, out + 16 * j);
    }
    /* MP = (xor of PPP_j) ^ T; MC = AES(MP); M = MP ^ MC */
    xor16(mp, out, tweak);
    for (j = 1; j < nblocks; j++)
        xor16(mp, mp, out + 16 * j);
    aes256_decrypt(a, mc, mp);
    xor16(m, mp, mc);
    /* CCC_j = 2^(j-1) * M ^ PPP_j, for j >= 1 (counting from 0) */
    for (j = 1; j < nblocks; j++) {
        eme_double(m);
        xor16(out + 16 * j, out + 16 * j, m);
    }
    /* CCC_0 = (xor of CCC_j, j >= 1) ^ T ^ MC */
    xor16(ccc1, mc, tweak);
    for (j = 1; j < nblocks; j++)
        xor16(ccc1, ccc1, out + 16 * j);
    memcpy(out, ccc1, 16);
    /* C_j = AES(CCC_j) ^ L_j */
    for (j = 0; j < nblocks; j++) {
        aes256_decrypt(a, out + 16 * j, out + 16 * j);
        xor16(out + 16 * j, out + 16 * j, l[j]);
    }
}

/* PKCS#7 unpadding to 16-byte blocks, with the checks of rclone's
 * pkcs7.Unpad: the unpadded length, or -1. */
static long pkcs7_unpad(const uint8_t *buf, size_t len)
{
    size_t pad, i;
    if (len == 0 || len % 16 != 0)
        return -1;
    pad = buf[len - 1];
    if (pad == 0 || pad > 16)
        return -1;
    for (i = 0; i < pad; i++)
        if (buf[len - 1 - i] != pad)
            return -1;
    return (long)(len - pad);
}

/* ===================================================================== */
/* 8. UTF-8 (RFC 3629), base32 and base64 (RFC 4648) and base32768       */
/* ===================================================================== */

/* Decode one UTF-8 sequence from s (n bytes available): its length, with
 * the code point in *cp, or 0 if it is malformed, overlong, a surrogate or
 * beyond U+10FFFF. */
static size_t utf8_decode(const uint8_t *s, size_t n, uint32_t *cp)
{
    size_t len, i;
    uint32_t c, min;
    if (n == 0)
        return 0;
    if (s[0] < 0x80) {
        *cp = s[0];
        return 1;
    } else if ((s[0] & 0xe0) == 0xc0) {
        len = 2, c = s[0] & 0x1f, min = 0x80;
    } else if ((s[0] & 0xf0) == 0xe0) {
        len = 3, c = s[0] & 0x0f, min = 0x800;
    } else if ((s[0] & 0xf8) == 0xf0) {
        len = 4, c = s[0] & 0x07, min = 0x10000;
    } else {
        return 0;
    }
    if (n < len)
        return 0;
    for (i = 1; i < len; i++) {
        if ((s[i] & 0xc0) != 0x80)
            return 0;
        c = (c << 6) | (s[i] & 0x3f);
    }
    if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
        return 0;
    *cp = c;
    return len;
}

static size_t utf8_encode(uint32_t c, uint8_t *out)
{
    if (c < 0x80) {
        out[0] = (uint8_t)c;
        return 1;
    } else if (c < 0x800) {
        out[0] = (uint8_t)(0xc0 | (c >> 6));
        out[1] = (uint8_t)(0x80 | (c & 0x3f));
        return 2;
    } else if (c < 0x10000) {
        out[0] = (uint8_t)(0xe0 | (c >> 12));
        out[1] = (uint8_t)(0x80 | ((c >> 6) & 0x3f));
        out[2] = (uint8_t)(0x80 | (c & 0x3f));
        return 3;
    }
    out[0] = (uint8_t)(0xf0 | (c >> 18));
    out[1] = (uint8_t)(0x80 | ((c >> 12) & 0x3f));
    out[2] = (uint8_t)(0x80 | ((c >> 6) & 0x3f));
    out[3] = (uint8_t)(0x80 | (c & 0x3f));
    return 4;
}

/* base32 with RFC 4648's "base32hex" alphabet (section 7), 0-9 then A-V.
 * rclone (cipher.go, caseInsensitiveBase32Encoding) writes it in lower
 * case without the '=' padding, and reads either case. Returns the decoded
 * length, or -1. */
static long base32hex_decode(const char *s, size_t n, uint8_t *out)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t i, o = 0;
    if (n % 8 == 1 || n % 8 == 3 || n % 8 == 6)
        return -1; /* no whole byte can end there */
    for (i = 0; i < n; i++) {
        int c = (unsigned char)s[i], v;
        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'a' && c <= 'v')
            v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'V')
            v = c - 'A' + 10;
        else
            return -1;
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
        acc &= (1u << bits) - 1;
    }
    return (long)o;
}

/* base64 with RFC 4648's URL-safe alphabet (section 5), unpadded, as Go's
 * base64.RawURLEncoding that rclone uses. */
static long base64url_decode(const char *s, size_t n, uint8_t *out)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t i, o = 0;
    if (n % 4 == 1)
        return -1;
    for (i = 0; i < n; i++) {
        int c = (unsigned char)s[i], v;
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= 'a' && c <= 'z')
            v = c - 'a' + 26;
        else if (c >= '0' && c <= '9')
            v = c - '0' + 52;
        else if (c == '-')
            v = 62;
        else if (c == '_')
            v = 63;
        else
            return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
        acc &= (1u << bits) - 1;
    }
    return (long)o;
}

/* base32768 (qntm, https://github.com/qntm/base32768), as Max-Sum/base32768
 * implements it for rclone (SafeEncoding). Each character of the Basic
 * Multilingual Plane carries 15 bits, most significant first; a last
 * group of 7 bits or fewer is one character of a second repertoire, and
 * leftover bits are padding (ones). A repertoire is a list of blocks of 32
 * consecutive code points: the block's position in the list gives the
 * high bits of the value, the code point's offset in its block the low 5.
 * These are the blocks of qntm's repertoires, in increasing order, as
 * ranges of whole blocks: */
static const uint16_t b32768_rep15[][2] = {
    {0x04A0, 0x04BF}, {0x0500, 0x051F}, {0x0680, 0x06BF}, {0x0760, 0x079F},
    {0x07C0, 0x07DF}, {0x1000, 0x101F}, {0x10A0, 0x10BF}, {0x1100, 0x115F},
    {0x1180, 0x119F}, {0x11E0, 0x123F}, {0x1260, 0x127F}, {0x12E0, 0x12FF},
    {0x1320, 0x133F}, {0x13A0, 0x13DF}, {0x1420, 0x165F}, {0x16A0, 0x16DF},
    {0x1780, 0x179F}, {0x1820, 0x185F}, {0x18C0, 0x18DF}, {0x1980, 0x199F},
    {0x19E0, 0x19FF}, {0x1A20, 0x1A3F}, {0x1BC0, 0x1BDF}, {0x1C00, 0x1C1F},
    {0x1D00, 0x1D1F}, {0x21E0, 0x21FF}, {0x22C0, 0x22DF}, {0x2340, 0x23DF},
    {0x2400, 0x241F}, {0x2500, 0x275F}, {0x2780, 0x27BF}, {0x2800, 0x297F},
    {0x29A0, 0x29BF}, {0x2A20, 0x2A5F}, {0x2A80, 0x2ABF}, {0x2AE0, 0x2B5F},
    {0x2C00, 0x2C1F}, {0x2C80, 0x2CDF}, {0x2D00, 0x2D1F}, {0x2D40, 0x2D5F},
    {0x2EA0, 0x2EDF}, {0x31C0, 0x31DF}, {0x3400, 0x4D9F}, {0x4DC0, 0x9FBF},
    {0xA000, 0xA47F}, {0xA4A0, 0xA4BF}, {0xA500, 0xA5FF}, {0xA640, 0xA65F},
    {0xA6A0, 0xA6DF}, {0xA700, 0xA75F}, {0xA780, 0xA79F}, {0xA840, 0xA85F}};
static const uint16_t b32768_rep7[][2] = {{0x0180, 0x019F}, {0x0240, 0x029F}};

/* For each block of the BMP (code point >> 5): 0 if not in a repertoire,
 * 1 + its position in the 15-bit list, or -1 - its position in the 7-bit
 * list. */
static int16_t b32768_map[2048];

static void b32768_init(void)
{
    size_t i;
    int pos = 0;
    uint32_t b;
    for (i = 0; i < sizeof b32768_rep15 / sizeof b32768_rep15[0]; i++)
        for (b = b32768_rep15[i][0]; b <= b32768_rep15[i][1]; b += 32)
            b32768_map[b >> 5] = (int16_t)(1 + pos++);
    if (pos != 1024)
        die("internal error: base32768 table has %d blocks", pos);
    pos = 0;
    for (i = 0; i < sizeof b32768_rep7 / sizeof b32768_rep7[0]; i++)
        for (b = b32768_rep7[i][0]; b <= b32768_rep7[i][1]; b += 32)
            b32768_map[b >> 5] = (int16_t)(-1 - pos++);
    if (pos != 4)
        die("internal error: base32768 table has %d short blocks", pos);
}

/* rclone gives its backends names in its "Standard" encoding (lib/encoder),
 * where the control characters 0x01-0x1F are the symbols U+2401-U+241F
 * and DEL is U+2421, and each backend turns them into its own: the local
 * backend on Linux and macOS writes them back as control characters, sftp
 * keeps the symbols. So a name read from disk holds either form, and the
 * crypt name is the one with the symbols. */
static uint32_t local_to_standard(uint32_t cp)
{
    if (cp >= 0x01 && cp <= 0x1f)
        return cp + 0x2400;
    return cp == 0x7f ? 0x2421 : cp;
}

static int is_symbol(uint32_t r)
{
    return (r >= 0x2401 && r <= 0x241f) || r == 0x2421;
}

/* The other way: a decrypted name, in the Standard encoding, as rclone's
 * local backend writes it on Linux (FromStandardName): a symbol becomes its
 * control character, and U+201B, which quotes a literal symbol, is dropped.
 * In place, since the result is never longer. */
static void standard_to_local(char *s)
{
    uint8_t *p = (uint8_t *)s, *out = p;
    size_t n = strlen(s), i = 0, l, l2;
    uint32_t r, r2;
    while (i < n) {
        l = utf8_decode(p + i, n - i, &r);
        if (l == 0) { /* not UTF-8: kept as it is */
            *out++ = p[i++];
            continue;
        }
        if (r == 0x201b && (l2 = utf8_decode(p + i + l, n - i - l, &r2)) &&
            is_symbol(r2)) {
            memmove(out, p + i + l, l2); /* a quoted symbol, literally */
            out += l2, i += l + l2;
            continue;
        }
        if (is_symbol(r)) {
            *out++ = r == 0x2421 ? 0x7f : (uint8_t)(r - 0x2400);
            i += l;
            continue;
        }
        memmove(out, p + i, l);
        out += l, i += l;
    }
    *out = '\0';
}

/* Decode base32768 from UTF-8, control characters read as the symbols they
 * stand for (local_to_standard). Like rclone's decoder it does not check
 * the padding bits; unlike it, it refuses characters after a 7-bit one,
 * which rclone ignores and never writes. */
static long base32768_decode(const char *s, size_t n, uint8_t *out)
{
    uint32_t acc = 0, cp, v;
    int bits = 0, ended = 0, nb, m;
    size_t i = 0, o = 0, l;
    if (b32768_map[0x4A0 >> 5] == 0)
        b32768_init();
    while (i < n) {
        l = utf8_decode((const uint8_t *)s + i, n - i, &cp);
        if (l == 0)
            return -1;
        i += l;
        cp = local_to_standard(cp);
        if (ended || cp > 0xffff)
            return -1;
        m = b32768_map[cp >> 5];
        if (m == 0)
            return -1;
        if (m > 0) {
            v = ((uint32_t)(m - 1) << 5) | (cp & 31);
            nb = 15;
        } else {
            v = ((uint32_t)(-m - 1) << 5) | (cp & 31);
            nb = 7;
            ended = 1;
        }
        acc = (acc << nb) | v;
        bits += nb;
        while (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
        acc &= (1u << bits) - 1;
    }
    return (long)o;
}

/* ===================================================================== */
/* 9. rclone crypt                                                       */
/* ===================================================================== */

enum name_mode { NAMES_STANDARD, NAMES_OBFUSCATE, NAMES_OFF };
enum name_encoding { ENC_BASE32, ENC_BASE64, ENC_BASE32768 };

struct crypt {
    uint8_t data_key[32], name_key[32], name_tweak[16];
    aes256 name_aes;
    enum name_mode mode;
    enum name_encoding encoding;
    int dir_names;      /* directory_name_encryption */
    const char *suffix; /* for mode off: ".bin", or "" for suffix = none */
};

/* cipher.go: defaultSalt, used when password2 is empty */
static const uint8_t rclone_default_salt[16] = {
    0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
    0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1};

/* cipher.go, Key: scrypt(N=16384, r=8, p=1) to 80 bytes; an empty
 * password gives all-zero keys (which rclone's own tests use). */
static void crypt_set_keys(struct crypt *c, const uint8_t *pw, size_t pwlen,
                           const uint8_t *salt, size_t saltlen)
{
    uint8_t key[80];
    if (saltlen == 0)
        salt = rclone_default_salt, saltlen = sizeof rclone_default_salt;
    if (pwlen == 0)
        memset(key, 0, sizeof key);
    else
        scrypt(pw, pwlen, salt, saltlen, 16384, 8, 1, key, sizeof key);
    memcpy(c->data_key, key, 32);
    memcpy(c->name_key, key + 32, 32);
    memcpy(c->name_tweak, key + 64, 16);
    aes256_init(&c->name_aes, c->name_key);
    wipe(key, sizeof key);
}

/* obscure.go, Reveal: the value in rclone.conf is base64url (unpadded) of
 * a 16-byte IV followed by the secret under AES-256-CTR with this fixed
 * key. It hides a password from a glance, nothing more. Returns the
 * secret's length, written over buf, or -1. */
static long rclone_reveal(char *buf)
{
    static const uint8_t obscure_key[32] = {
        0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c,
        0x63, 0xc8, 0x86, 0xa9, 0x2b, 0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12,
        0x8a, 0xfb, 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38};
    size_t n = strlen(buf);
    uint8_t *raw = xmalloc(n);
    aes256 a;
    long len = base64url_decode(buf, n, raw);
    if (len < 16) {
        free(raw);
        return -1;
    }
    aes256_init(&a, obscure_key);
    aes256_ctr(&a, raw + 16, (size_t)len - 16, raw);
    memcpy(buf, raw + 16, (size_t)len - 16);
    buf[len - 16] = '\0';
    wipe(raw, (size_t)len);
    free(raw);
    return len - 16;
}

/* cipher.go, decryptSegment: decode, EME-decrypt, unpad. */
static char *decrypt_segment(const struct crypt *c, const char *seg,
                             const char **why)
{
    size_t n = strlen(seg);
    uint8_t *raw = xmalloc(n + 1);
    long len, plen;
    switch (c->encoding) {
    case ENC_BASE32:
        len = base32hex_decode(seg, n, raw);
        break;
    case ENC_BASE64:
        len = base64url_decode(seg, n, raw);
        break;
    default:
        len = base32768_decode(seg, n, raw);
        break;
    }
    if (len < 0)
        *why = "not in the name encoding given";
    else if (len == 0 || len % 16 != 0)
        *why = "not a whole number of cipher blocks";
    else if (len > 2048)
        *why = "too long";
    if (len <= 0 || len % 16 != 0 || len > 2048) {
        free(raw);
        return NULL;
    }
    eme_decrypt(&c->name_aes, c->name_tweak, raw, raw, (size_t)len);
    plen = pkcs7_unpad(raw, (size_t)len);
    if (plen < 0) {
        *why = "bad padding: wrong password or salt, or not this crypt";
        free(raw);
        return NULL;
    }
    raw[plen] = '\0';
    return (char *)raw;
}

/* cipher.go, deobfuscateSegment: "N.rotated", N the sum of the original's
 * code points mod 256; each character rotates back within its class by an
 * amount from N plus the bytes of the name key; '!' quotes the next
 * character; "!.name" was not rotated. */
static char *deobfuscate_segment(const struct crypt *c, const char *seg,
                                 const char **why)
{
    const char *dot = strchr(seg, '.'), *p;
    size_t n = strlen(seg), o = 0, l;
    char *out;
    long dir = 0;
    int i, in_quote = 0;
    uint32_t r, nr;

    if (!dot || dot == seg || dot - seg > 6) {
        *why = "not an obfuscated name (no number before a '.')";
        return NULL;
    }
    if (dot - seg == 1 && seg[0] == '!')
        return xstrdup(dot + 1);
    for (p = seg; p < dot; p++) {
        if (*p < '0' || *p > '9') {
            *why = "not an obfuscated name (no number before a '.')";
            return NULL;
        }
        dir = dir * 10 + (*p - '0');
    }
    for (i = 0; i < 32; i++)
        dir += c->name_key[i];

    out = xmalloc(4 * n + 1);
    for (p = dot + 1; *p; p += l) {
        l = utf8_decode((const uint8_t *)p, strlen(p), &r);
        if (l == 0) {
            *why = "not valid UTF-8";
            free(out);
            return NULL;
        }
        r = local_to_standard(r);
        nr = r;
        if (in_quote) {
            in_quote = 0;
        } else if (r == '!') {
            in_quote = 1;
            continue;
        } else if (r >= '0' && r <= '9') {
            long t = dir % 9 + 1;
            nr = (uint32_t)('0' + ((long)r - '0' - t + 10) % 10);
        } else if ((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
            long t = dir % 25 + 1, pos = (long)r - 'A';
            if (pos >= 26)
                pos -= 6; /* a-z follow A-Z at 26-51 */
            pos -= t;
            if (pos < 0)
                pos += 52;
            if (pos >= 26)
                pos += 6;
            nr = (uint32_t)('A' + pos);
        } else if (r >= 0xA0 && r <= 0xFF) {
            long t = dir % 95 + 1;
            nr = (uint32_t)(0xA0 + ((long)r - 0xA0 - t + 96) % 96);
        } else if (r >= 0x100) {
            long t = dir % 127 + 1, base = (long)(r - r % 256);
            long v = (long)r - t;
            if (v < base)
                v += 256;
            nr = (uint32_t)v;
            if (nr >= 0xd800 && nr <= 0xdfff)
                nr = 0xfffd; /* as Go's WriteRune of an invalid rune */
        }
        o += utf8_encode(nr, (uint8_t *)out + o);
    }
    out[o] = '\0';
    return out;
}

/* A decrypted segment must be usable as a single name. */
static int name_is_safe(const char *s)
{
    return s[0] != '\0' && strcmp(s, ".") != 0 && strcmp(s, "..") != 0 &&
           strchr(s, '/') == NULL;
}

/* The plaintext name of one directory entry, or NULL with *why set.
 * cipher.go: DecryptFileName, DecryptDirName. */
static char *decrypt_name(const struct crypt *c, const char *name, int is_dir,
                          const char **why)
{
    char *out;
    if (c->mode == NAMES_OFF || (is_dir && !c->dir_names)) {
        if (c->mode == NAMES_OFF && !is_dir) {
            size_t n = strlen(name), sl = strlen(c->suffix);
            if (n <= sl || strcmp(name + n - sl, c->suffix) != 0) {
                *why = "does not end with the crypt's suffix";
                return NULL;
            }
            out = xstrdup(name);
            out[n - sl] = '\0';
        } else {
            out = xstrdup(name);
        }
    } else {
        out = c->mode == NAMES_STANDARD ? decrypt_segment(c, name, why)
                                        : deobfuscate_segment(c, name, why);
        if (out)
            standard_to_local(out);
    }
    if (out && !name_is_safe(out)) {
        *why = "decrypts to a name that is not usable as a file name";
        free(out);
        return NULL;
    }
    return out;
}

/* File contents (cipher.go, constants and decrypter): a 32-byte header,
 * then chunks of up to 64 KiB of plaintext, each a secretbox of 16 bytes
 * more. */
#define FILE_MAGIC "RCLONE\0\0"
#define HEADER_SIZE 32
#define CHUNK_DATA 65536
#define CHUNK_BOX (CHUNK_DATA + 16)

/* Decrypt the stream on fd `in` to fd `out`; on error print it, naming
 * `path`, and return -1. */
static int decrypt_contents(const struct crypt *c, int in, int out,
                            const char *path)
{
    static uint8_t box[CHUNK_BOX], plain[CHUNK_DATA];
    uint8_t header[HEADER_SIZE], nonce[24];
    unsigned long long chunk;
    ssize_t n;
    int i;

    n = read_full(in, header, HEADER_SIZE);
    if (n < 0) {
        fprintf(stderr, "%s: %s: read: %s\n", progname, path, strerror(errno));
        return -1;
    }
    if (n < HEADER_SIZE) {
        fprintf(stderr,
                "%s: %s: too short for an rclone crypt file (%ld bytes)\n",
                progname, path, (long)n);
        return -1;
    }
    if (memcmp(header, FILE_MAGIC, 8) != 0) {
        fprintf(stderr, "%s: %s: not an rclone crypt file (bad magic)\n",
                progname, path);
        return -1;
    }
    memcpy(nonce, header + 8, 24);
    for (chunk = 0;; chunk++) {
        n = read_full(in, box, CHUNK_BOX);
        if (n < 0) {
            fprintf(stderr, "%s: %s: read: %s\n", progname, path,
                    strerror(errno));
            return -1;
        }
        if (n == 0)
            break;
        if (n <= 16) {
            fprintf(stderr, "%s: %s: chunk %llu is truncated (%ld bytes)\n",
                    progname, path, chunk, (long)n);
            return -1;
        }
        if (secretbox_open(plain, box, (size_t)n, nonce, c->data_key) != 0) {
            fprintf(stderr,
                    "%s: %s: chunk %llu (plaintext from byte %llu) fails "
                    "authentication: wrong password or salt, or corrupted\n",
                    progname, path, chunk, chunk * CHUNK_DATA);
            return -1;
        }
        if (write_full(out, plain, (size_t)n - 16) != 0) {
            fprintf(stderr, "%s: %s: write: %s\n", progname, path,
                    strerror(errno));
            return -1;
        }
        /* cipher.go, nonce.increment: little-endian, carrying upward */
        for (i = 0; i < 24 && ++nonce[i] == 0; i++)
            ;
        if (n < CHUNK_BOX)
            break; /* a short read is the end of the file */
    }
    return 0;
}

/* ===================================================================== */
/* 10. Self-test: known answers from the specifications and from         */
/*     rclone's own tests (cipher_test.go, obscure_test.go)              */
/* ===================================================================== */

static int hex_matches(const uint8_t *got, size_t n, const char *hex)
{
    size_t i;
    char buf[3];
    if (strlen(hex) != 2 * n)
        return 0;
    for (i = 0; i < n; i++) {
        buf[0] = hex[2 * i], buf[1] = hex[2 * i + 1], buf[2] = '\0';
        if ((uint8_t)strtoul(buf, NULL, 16) != got[i])
            return 0;
    }
    return 1;
}

static void hex_parse(const char *hex, uint8_t *out)
{
    size_t i;
    char buf[3];
    for (i = 0; hex[2 * i]; i++) {
        buf[0] = hex[2 * i], buf[1] = hex[2 * i + 1], buf[2] = '\0';
        out[i] = (uint8_t)strtoul(buf, NULL, 16);
    }
}

static int st_failures;

static void st_check(const char *what, int ok)
{
    if (!ok) {
        fprintf(stderr, "%s: self-test failed: %s\n", progname, what);
        st_failures++;
    }
}

/* A rclone name decryption with all-zero keys, from cipher_test.go. */
static void st_name(enum name_mode mode, enum name_encoding enc,
                    const char *in, const char *want)
{
    struct crypt c;
    const char *why = NULL;
    char *got;
    memset(&c, 0, sizeof c);
    crypt_set_keys(&c, NULL, 0, NULL, 0);
    c.mode = mode, c.encoding = enc, c.dir_names = 1, c.suffix = ".bin";
    got = decrypt_name(&c, in, 0, &why);
    st_check(in, got && strcmp(got, want) == 0);
    free(got);
}

/* Returns 1 if every known answer matches. The full test adds the slow
 * scrypt vectors, at rclone's own parameters. */
static int self_test(int full)
{
    uint8_t out[80], key[32], box[64], nonce[24];
    sha256_ctx s;
    hmac_ctx h;
    aes256 a;
    struct crypt c;
    char obscured[64];
    uint32_t w[16];
    int i;

    st_failures = 0;
    /* FIPS 180-4 example (also in FIPS 180-2, appendix B.1) */
    sha256_init(&s);
    sha256_update(&s, "abc", 3);
    sha256_final(&s, out);
    st_check("SHA-256", hex_matches(out, 32, "ba7816bf8f01cfea414140de5dae2223"
                                             "b00361a396177a9cb410ff61f20015ad"));
    /* RFC 4231, test case 2 */
    hmac_init(&h, (const uint8_t *)"Jefe", 4);
    hmac_update(&h, "what do ya want for nothing?", 28);
    hmac_final(&h, out);
    st_check("HMAC-SHA-256",
             hex_matches(out, 32, "5bdcc146bf60754e6a042426089575c7"
                                  "5a003f089d2739839dec58b964ec3843"));
    /* RFC 7914, section 11 */
    pbkdf2_sha256((const uint8_t *)"passwd", 6, (const uint8_t *)"salt", 4, 1,
                  out, 64);
    st_check("PBKDF2-HMAC-SHA-256",
             hex_matches(out, 64,
                         "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b"
                         "9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845"
                         "b1e30bd509112041d3a19783"));
    /* RFC 7914, section 8 */
    hex_parse("7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d"
              "ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e",
              box);
    for (i = 0; i < 16; i++)
        w[i] = load32_le(box + 4 * i);
    salsa20_core(w, w, 8, 1);
    for (i = 0; i < 16; i++)
        store32_le(box + 4 * i, w[i]);
    st_check("Salsa20/8 core",
             hex_matches(box, 64,
                         "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b"
                         "1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc10"
                         "2c91745c24ad673dc7618f81"));
    /* RFC 7914, section 12, first vector */
    scrypt((const uint8_t *)"", 0, (const uint8_t *)"", 0, 16, 1, 1, out, 64);
    st_check("scrypt N=16",
             hex_matches(out, 64,
                         "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdf"
                         "fa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb"
                         "2e0d3628cf35e20c38d18906"));
    /* RFC 8439, section 2.5.2 */
    hex_parse("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
              key);
    poly1305(out, (const uint8_t *)"Cryptographic Forum Research Group", 34,
             key);
    st_check("Poly1305",
             hex_matches(out, 16, "a8061dc1305136c6c22b8baf0c0127a9"));
    /* FIPS-197, appendix C.3 */
    hex_parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
              key);
    aes256_init(&a, key);
    hex_parse("00112233445566778899aabbccddeeff", out);
    aes256_encrypt(&a, out, out);
    st_check("AES-256 encryption",
             hex_matches(out, 16, "8ea2b7ca516745bfeafc49904b496089"));
    aes256_decrypt(&a, out, out);
    st_check("AES-256 decryption",
             hex_matches(out, 16, "00112233445566778899aabbccddeeff"));
    /* obscure_test.go, TestReveal */
    strcpy(obscured, "YmJiYmJiYmJiYmJiYmJiYp3gcEWbAw");
    st_check("rclone reveal", rclone_reveal(obscured) == 6 &&
                                  strcmp(obscured, "potato") == 0);
    /* cipher_test.go, file1 and file16: all-zero key, nonce 01 02 ... 18 */
    memset(key, 0, 32);
    for (i = 0; i < 24; i++)
        nonce[i] = (uint8_t)(i + 1);
    hex_parse("095b446cd6237bbcb08d09fb524ce565aa", box);
    st_check("secretbox (1 byte)",
             secretbox_open(out, box, 17, nonce, key) == 0 && out[0] == 1);
    hex_parse("b9c4552a2710062918960a3e608c29b9aa8a5e1e165b6d075de4e9bb367fd6d4",
              box);
    {
        int ok = secretbox_open(out, box, 32, nonce, key) == 0;
        for (i = 0; i < 16; i++)
            ok = ok && out[i] == i + 1;
        st_check("secretbox (16 bytes)", ok);
        box[20] ^= 1;
        st_check("secretbox rejects a changed byte",
                 secretbox_open(out, box, 32, nonce, key) != 0);
    }
    /* cipher_test.go: names with all-zero keys */
    st_name(NAMES_STANDARD, ENC_BASE32, "p0e52nreeaj0a5ea7s64m4j72s", "1");
    st_name(NAMES_STANDARD, ENC_BASE32, "QGM4AVR35M5LOI1TH53ATO71V0", "123");
    st_name(NAMES_STANDARD, ENC_BASE32,
            "mijbj0frqf6ms7frcr6bd9h0env53jv96pjaaoirk7forcgpt70g",
            "1234567890123456");
    st_name(NAMES_STANDARD, ENC_BASE64, "1CxFf2Mti1xIPYlGruDh-A", "123");
    st_name(NAMES_STANDARD, ENC_BASE64,
            "tKa5gfvTzW4d-2bMtqYgdf5Rz-k2ZqViW6HfjbIZ6cE", "1234567890123456");
    st_name(NAMES_STANDARD, ENC_BASE32768,
            "\xe8\xa9\xae\xe3\xaa\x97\xe9\x90\xae\xe5\x83\x80\xe4\xbc\x8e"
            "\xe4\xbd\x9c\xe3\xbb\x96\xe3\xa2\xa7\xe2\xaa\x9f",
            "1"); /* 詮㪗鐮僀伎作㻖㢧⪟ */
    st_name(NAMES_STANDARD, ENC_BASE32768,
            "\xe8\x82\xb3\xe5\x93\x80\xe6\x97\x9a\xe6\x8c\xb6\xe9\x9d\x8f"
            "\xe9\x8f\xbb\xe3\xbe\xad\xe4\xb1\xa0\xe6\x85\x9f\xe3\xaa\xb3"
            "\xea\x8f\x86\xe8\xb3\x8a\xe5\x85\xb2\xe9\x93\xa7\xe6\x95\xbb"
            "\xe5\xa1\xb9\xe9\xad\x80\xca\x9f",
            "1234567890123456"); /* 肳哀旚挶靏鏻㾭䱠慟㪳ꏆ賊兲铧敻塹魀ʟ */
    st_name(NAMES_OBFUSCATE, ENC_BASE32, "!.hello", "hello");
    st_name(NAMES_OBFUSCATE, ENC_BASE32, "161.\xc3\xa4", "\xc2\xa1");
    st_name(NAMES_OBFUSCATE, ENC_BASE32, "160.\xcf\x82", "\xce\xa0");
    st_name(NAMES_OBFUSCATE, ENC_BASE32, "53.!!lipps", "!hello");
    st_name(NAMES_OFF, ENC_BASE32, "123.bin", "123");
    {
        char name[] = "a\xe2\x90\x8d \xe2\x80\x9b\xe2\x90\x8d \xe2\x80\x9bz";
        standard_to_local(name); /* a␍ ‛␍ ‛z */
        st_check("rclone's Standard encoding",
                 strcmp(name, "a\r \xe2\x90\x8d \xe2\x80\x9bz") == 0);
    }

    if (full) {
        /* RFC 7914, section 12, second and third vectors */
        scrypt((const uint8_t *)"password", 8, (const uint8_t *)"NaCl", 4,
               1024, 8, 16, out, 64);
        st_check("scrypt N=1024 r=8 p=16",
                 hex_matches(out, 64,
                             "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830"
                             "e77376634b3731622eaf30d92e22a3886ff109279d9830da"
                             "c727afb94a83ee6d8360cbdfa2cc0640"));
        scrypt((const uint8_t *)"pleaseletmein", 13,
               (const uint8_t *)"SodiumChloride", 14, 16384, 8, 1, out, 64);
        st_check("scrypt N=16384 r=8 p=1",
                 hex_matches(out, 64,
                             "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3e"
                             "a9b543f6545da1f2d5432955613f0fcf62d49705242a9af9"
                             "e61e85dc0d651e40dfcf017b45575887"));
        /* cipher_test.go, TestKey */
        crypt_set_keys(&c, (const uint8_t *)"potato", 6, NULL, 0);
        st_check("rclone key, default salt",
                 hex_matches(c.data_key, 32,
                             "7455c71ab17c865b8471f47b79acb07e"
                             "b31d5678b80c7e2eaf4fc8066a9ee468") &&
                     hex_matches(c.name_key, 32,
                                 "765da27ab15d77f95796711f7b93ad63"
                                 "bbb484072e7180a8d17a9bbec14270d0") &&
                     hex_matches(c.name_tweak, 16,
                                 "c18d5932f55b2828c5e1e87215520310"));
        crypt_set_keys(&c, (const uint8_t *)"potato", 6,
                       (const uint8_t *)"sausage", 7);
        st_check("rclone key, salt",
                 hex_matches(c.data_key, 32,
                             "8e9b6b99f8690467a071f9cb92d0aa78"
                             "7f8ff178bec96f999fd5206e644a1b50") &&
                     hex_matches(c.name_key, 32,
                                 "3ea95ef681782dc9d9955d225bfd442c"
                                 "6f5d6897b029015c6f462e2a9dae2ce3") &&
                     hex_matches(c.name_tweak, 16,
                                 "f17fd7141d65274f363fc2a04dd2148a"));
    }
    return st_failures == 0;
}

/* ===================================================================== */
/* 11. The tree and the command line                                     */
/* ===================================================================== */

static const char usage[] =
    "usage: rclone-decrypt [options] SRC DST   decrypt the tree SRC into DST\n"
    "       rclone-decrypt --names [options] SRC\n"
    "                                          print each encrypted path, a tab,\n"
    "                                          and its decrypted path\n"
    "       rclone-decrypt --file [options] IN OUT\n"
    "                                          decrypt one file's contents\n"
    "       rclone-decrypt --self-test         check every primitive\n"
    "\n"
    "Decrypts an rclone crypt directory (https://rclone.org/crypt/) as it lies\n"
    "on disk, with no rclone. The options mirror the crypt's settings in\n"
    "rclone.conf; each default is rclone's:\n"
    "\n"
    "  --encoding base32|base64|base32768   filename_encoding (base32)\n"
    "  --names-off            filename_encryption = off: names in clear, files\n"
    "                         with the suffix (--suffix, default .bin)\n"
    "  --names-obfuscate      filename_encryption = obfuscate\n"
    "  --no-dir-names         directory_name_encryption = false\n"
    "  --suffix S             suffix = S, for --names-off (\"none\" for none)\n"
    "  --password-file F      password from the file F (its last newline\n"
    "                         dropped); else asked on the terminal\n"
    "  --salt-file F          password2, the salt, likewise; an empty one\n"
    "                         means rclone's default salt (--salt-file\n"
    "                         /dev/null when the crypt has no password2)\n"
    "  --obscured             the password and salt given are rclone.conf's\n"
    "                         obscured values, to be revealed first\n"
    "\n"
    "Format: scrypt (N=16384, r=8, p=1) turns the password and salt into a\n"
    "data key, a name key and a tweak. Each file is \"RCLONE\\0\\0\", a 24-byte\n"
    "nonce, then chunks of 64 KiB, each an XSalsa20-Poly1305 secretbox, the\n"
    "nonce incremented per chunk; each tag is verified, and a file that fails\n"
    "is reported with its chunk and not written. Each name is PKCS#7-padded,\n"
    "enciphered with EME over AES-256, then encoded.\n"
    "\n"
    "Output is written to a temporary file in the same directory and renamed\n"
    "only when complete. Existing files in DST are never overwritten: each is\n"
    "reported as an error. Modification times are kept. A path that fails is\n"
    "reported, naming it, and the rest goes on; the exit status is then 1\n"
    "(2 when nothing could be done).\n";

struct options {
    struct crypt crypt;
    int names_only;
    long errors;
};

/* The temporary output file, removed if a signal interrupts the run. */
static char *volatile tmp_path;

static void on_signal(int sig)
{
    char *p = tmp_path;
    if (p)
        unlink(p);
    signal(sig, SIG_DFL);
    raise(sig);
}

static mode_t file_mode; /* 0666 less the umask */

static void report(struct options *o, const char *path, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "%s: %s: ", progname, path);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    o->errors++;
}

/* Decrypt the file `in` to `out` through a temporary file beside it. */
static void decrypt_file(struct options *o, const char *in, const char *out,
                         const struct stat *st)
{
    struct stat ost;
    struct timespec times[2];
    char *slash, *tmp;
    int ifd, ofd, ok;

    if (lstat(out, &ost) == 0) {
        report(o, out, "already exists, not overwritten");
        return;
    }
    ifd = open(in, O_RDONLY);
    if (ifd < 0) {
        report(o, in, "%s", strerror(errno));
        return;
    }
    slash = strrchr(out, '/');
    if (slash) {
        tmp = xmalloc((size_t)(slash - out) + 32);
        memcpy(tmp, out, (size_t)(slash - out));
        strcpy(tmp + (slash - out), "/.rclone-decrypt.XXXXXX");
    } else {
        tmp = xstrdup(".rclone-decrypt.XXXXXX");
    }
    ofd = mkstemp(tmp);
    if (ofd < 0) {
        report(o, out, "cannot create a temporary file: %s", strerror(errno));
        free(tmp);
        close(ifd);
        return;
    }
    tmp_path = tmp;
    ok = decrypt_contents(&o->crypt, ifd, ofd, in) == 0;
    if (!ok)
        o->errors++;
    times[0] = st->st_atim;
    times[1] = st->st_mtim;
    if (ok && (fchmod(ofd, file_mode) != 0 || futimens(ofd, times) != 0)) {
        report(o, out, "%s", strerror(errno));
        ok = 0;
    }
    if (close(ofd) != 0 && ok) {
        report(o, out, "%s", strerror(errno));
        ok = 0;
    }
    if (ok && rename(tmp, out) != 0) {
        report(o, out, "%s", strerror(errno));
        ok = 0;
    }
    if (!ok)
        unlink(tmp);
    tmp_path = NULL;
    free(tmp);
    close(ifd);
}

static int compare_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Walk the encrypted directory `src`; enc and dec are its path relative to
 * SRC, encrypted and decrypted; dst is where its plaintext goes (unused
 * with --names). */
static void walk(struct options *o, const char *src, const char *enc,
                 const char *dec, const char *dst)
{
    DIR *d = opendir(src);
    struct dirent *e;
    char **names = NULL;
    size_t count = 0, cap = 0, i;

    if (!d) {
        report(o, src, "%s", strerror(errno));
        return;
    }
    while ((errno = 0, e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (count == cap) {
            char **grown;
            cap = cap ? 2 * cap : 64;
            grown = realloc(names, cap * sizeof *names);
            if (!grown)
                die("out of memory");
            names = grown;
        }
        names[count++] = xstrdup(e->d_name);
    }
    if (errno != 0)
        report(o, src, "%s", strerror(errno));
    closedir(d);
    if (count > 1)
        qsort(names, count, sizeof *names, compare_names);

    for (i = 0; i < count; i++) {
        char *path = join(src, names[i]), *plain, *penc, *pdec, *out = NULL;
        const char *why = "";
        struct stat st;
        int is_dir;

        if (lstat(path, &st) != 0) {
            report(o, path, "%s", strerror(errno));
            free(path);
            continue;
        }
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
            report(o, path, "not a regular file or directory, skipped");
            free(path);
            continue;
        }
        is_dir = S_ISDIR(st.st_mode);
        plain = decrypt_name(&o->crypt, names[i], is_dir, &why);
        if (!plain) {
            report(o, path, "cannot decrypt the name: %s%s", why,
                   is_dir ? "; skipped with its contents" : "");
            free(path);
            continue;
        }
        penc = join(enc, names[i]);
        pdec = join(dec, plain);
        if (o->names_only)
            printf("%s%s\t%s%s\n", penc, is_dir ? "/" : "", pdec,
                   is_dir ? "/" : "");
        else
            out = join(dst, plain);

        if (is_dir) {
            struct stat ost;
            if (!o->names_only && mkdir(out, 0777) != 0 &&
                !(errno == EEXIST && stat(out, &ost) == 0 &&
                  S_ISDIR(ost.st_mode))) {
                report(o, out, "cannot create the directory: %s",
                       strerror(errno));
            } else {
                walk(o, path, penc, pdec, out);
                if (!o->names_only) {
                    struct timespec times[2];
                    times[0] = st.st_atim;
                    times[1] = st.st_mtim;
                    utimensat(AT_FDCWD, out, times, 0);
                }
            }
        } else if (!o->names_only) {
            decrypt_file(o, path, out, &st);
        }
        free(path), free(plain), free(penc), free(pdec), free(out);
    }
    for (i = 0; i < count; i++)
        free(names[i]);
    free(names);
}

/* Read a password or salt: from the file, else from the terminal with no
 * echo. Drops one final newline (LF or CRLF). */
static char *read_secret(const char *file, const char *prompt, size_t *len)
{
    char *buf;
    size_t n = 0, cap = 1024;

    if (file) {
        int fd = open(file, O_RDONLY);
        ssize_t r;
        if (fd < 0)
            die("%s: %s", file, strerror(errno));
        buf = xmalloc(cap);
        while ((r = read_full(fd, buf + n, cap - 1 - n)) > 0) {
            n += (size_t)r;
            if (n == cap - 1) {
                if (cap >= 1 << 20)
                    die("%s: too long for a password", file);
                buf = realloc(buf, cap *= 2);
                if (!buf)
                    die("out of memory");
            }
        }
        if (r < 0)
            die("%s: %s", file, strerror(errno));
        close(fd);
    } else {
        struct termios old, quiet;
        FILE *tty = fopen("/dev/tty", "r+");
        if (!tty)
            die("no terminal to ask for the %s on: give it in a file", prompt);
        buf = xmalloc(cap);
        if (tcgetattr(fileno(tty), &old) != 0)
            die("cannot read the terminal's settings: %s", strerror(errno));
        quiet = old;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        fprintf(tty, "%s: ", prompt);
        fflush(tty);
        tcsetattr(fileno(tty), TCSAFLUSH, &quiet);
        if (!fgets(buf, (int)cap, tty))
            buf[0] = '\0';
        tcsetattr(fileno(tty), TCSAFLUSH, &old);
        fputc('\n', tty);
        fclose(tty);
        n = strlen(buf);
        if (n == cap - 1 && buf[n - 1] != '\n')
            die("the %s is too long", prompt);
    }
    if (n > 0 && buf[n - 1] == '\n')
        n--;
    if (n > 0 && buf[n - 1] == '\r')
        n--;
    buf[n] = '\0';
    *len = n;
    return buf;
}

/* With --obscured, reveal a value; surrounding blanks are ignored. */
static void reveal_secret(char *buf, size_t *len, const char *what)
{
    size_t start = 0, end = *len;
    long n;
    while (start < end && (buf[start] == ' ' || buf[start] == '\t'))
        start++;
    while (end > start && (buf[end - 1] == ' ' || buf[end - 1] == '\t'))
        end--;
    memmove(buf, buf + start, end - start);
    buf[end - start] = '\0';
    if (end == start) {
        *len = 0;
        return;
    }
    n = rclone_reveal(buf);
    if (n < 0)
        die("the %s is not an obscured value from rclone.conf", what);
    *len = (size_t)n;
}

static void mkdir_p(const char *path)
{
    char *p = xstrdup(path), *s;
    struct stat st;
    for (s = p + 1; *s; s++) {
        if (*s != '/')
            continue;
        *s = '\0';
        if (mkdir(p, 0777) != 0 && errno != EEXIST)
            die("%s: %s", p, strerror(errno));
        *s = '/';
    }
    if (mkdir(p, 0777) != 0 && errno != EEXIST)
        die("%s: %s", p, strerror(errno));
    if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode))
        die("%s: not a directory", p);
    free(p);
}

int main(int argc, char **argv)
{
    struct options o;
    const char *password_file = NULL, *salt_file = NULL, *args[2];
    int file_mode_op = 0, self_test_op = 0, obscured = 0, nargs = 0, i;
    char *pw, *salt;
    size_t pwlen, saltlen;
    struct sigaction sa;
    mode_t mask;

    memset(&o, 0, sizeof o);
    o.crypt.mode = NAMES_STANDARD;
    o.crypt.encoding = ENC_BASE32;
    o.crypt.dir_names = 1;
    o.crypt.suffix = ".bin";

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        int more = i + 1 < argc;
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            fputs(usage, stdout);
            return 0;
        } else if (strcmp(a, "--names") == 0) {
            o.names_only = 1;
        } else if (strcmp(a, "--file") == 0) {
            file_mode_op = 1;
        } else if (strcmp(a, "--self-test") == 0) {
            self_test_op = 1;
        } else if (strcmp(a, "--names-off") == 0) {
            o.crypt.mode = NAMES_OFF;
        } else if (strcmp(a, "--names-obfuscate") == 0) {
            o.crypt.mode = NAMES_OBFUSCATE;
        } else if (strcmp(a, "--no-dir-names") == 0) {
            o.crypt.dir_names = 0;
        } else if (strcmp(a, "--obscured") == 0) {
            obscured = 1;
        } else if (strcmp(a, "--encoding") == 0 && more) {
            a = argv[++i];
            if (strcmp(a, "base32") == 0)
                o.crypt.encoding = ENC_BASE32;
            else if (strcmp(a, "base64") == 0)
                o.crypt.encoding = ENC_BASE64;
            else if (strcmp(a, "base32768") == 0)
                o.crypt.encoding = ENC_BASE32768;
            else
                die("unknown encoding %s: base32, base64 or base32768", a);
        } else if (strcmp(a, "--suffix") == 0 && more) {
            a = argv[++i];
            /* cipher.go, setEncryptedSuffix: "none", or a '.' is added */
            if (strcasecmp(a, "none") == 0)
                o.crypt.suffix = "";
            else if (a[0] == '.')
                o.crypt.suffix = a;
            else
                o.crypt.suffix = strcat(strcpy(xmalloc(strlen(a) + 2), "."), a);
        } else if (strcmp(a, "--password-file") == 0 && more) {
            password_file = argv[++i];
        } else if (strcmp(a, "--salt-file") == 0 && more) {
            salt_file = argv[++i];
        } else if (strcmp(a, "--") == 0) {
            for (i++; i < argc; i++) {
                if (nargs == 2)
                    die("too many arguments; see --help");
                args[nargs++] = argv[i];
            }
        } else if (a[0] == '-' && a[1] != '\0') {
            die("unknown option, or one missing its value: %s; see --help", a);
        } else {
            if (nargs == 2)
                die("too many arguments; see --help");
            args[nargs++] = a;
        }
    }

    if (!self_test(self_test_op))
        die("the self-test failed: this build is broken, trust nothing from it");
    if (self_test_op) {
        printf("self-test passed\n");
        return 0;
    }
    if (o.names_only && file_mode_op)
        die("--names and --file exclude each other");
    if (nargs != (o.names_only ? 1 : 2))
        die("%s; see --help",
            nargs < (o.names_only ? 1 : 2) ? "missing arguments"
                                           : "too many arguments");

    pw = read_secret(password_file, "password", &pwlen);
    salt = read_secret(salt_file, "salt (password2; empty for none)", &saltlen);
    if (obscured) {
        reveal_secret(pw, &pwlen, "password");
        reveal_secret(salt, &saltlen, "salt");
    }
    if (pwlen == 0)
        die("empty password");
    crypt_set_keys(&o.crypt, (uint8_t *)pw, pwlen, (uint8_t *)salt, saltlen);
    wipe(pw, pwlen), wipe(salt, saltlen);
    free(pw), free(salt);

    mask = umask(0);
    umask(mask);
    file_mode = 0666 & ~mask;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    if (file_mode_op) {
        struct stat st;
        if (stat(args[0], &st) != 0)
            die("%s: %s", args[0], strerror(errno));
        decrypt_file(&o, args[0], args[1], &st);
    } else {
        struct stat st;
        if (stat(args[0], &st) != 0 || !S_ISDIR(st.st_mode))
            die("%s: not a directory", args[0]);
        if (!o.names_only) {
            char *rs, *rd;
            size_t ls;
            mkdir_p(args[1]);
            rs = realpath(args[0], NULL);
            rd = realpath(args[1], NULL);
            if (!rs || !rd)
                die("cannot resolve %s or %s", args[0], args[1]);
            ls = strlen(rs);
            if (strncmp(rs, rd, ls) == 0 && (rd[ls] == '/' || rd[ls] == '\0'))
                die("DST must not be inside SRC");
            free(rs), free(rd);
        }
        walk(&o, args[0], "", "", o.names_only ? NULL : args[1]);
    }
    if (fflush(stdout) != 0)
        die("cannot write the output: %s", strerror(errno));
    if (o.errors > 0) {
        fprintf(stderr, "%s: %ld error%s\n", progname, o.errors,
                o.errors == 1 ? "" : "s");
        return EXIT_SOME_FAILED;
    }
    return 0;
}
