/* selftest.c —— host 侧自检：SHA-256 / P-256 / ECDSA 正确性 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
#include "p256.h"

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i*2] = H[b[i]>>4]; out[i*2+1] = H[b[i]&15]; }
    out[n*2] = 0;
}

/* ECDSA 验签（用于自检） */
static int verify(const uint8_t pub65[65], const uint8_t hash[32],
                  const uint8_t rb[32], const uint8_t sb[32]) {
    u256 r, s, z, w, u1, u2;
    u256_from_be(&r, rb);
    u256_from_be(&s, sb);
    u256_from_be(&z, hash);
    if (u256_is_zero(&r) || u256_is_zero(&s)) return 0;
    if (u256_cmp(&r, &P256_N) >= 0 || u256_cmp(&s, &P256_N) >= 0) return 0;

    u256_modinv(&w, &s, &P256_N);
    u256_modmul(&u1, &z, &w, &P256_N);
    u256_modmul(&u2, &r, &w, &P256_N);

    point q, p1, p2, sum;
    u256_from_be(&q.x, pub65 + 1);
    u256_from_be(&q.y, pub65 + 33);
    q.inf = 0;
    p256_base_mul(&p1, &u1);
    p256_point_mul(&p2, &u2, &q);
    p256_point_add(&sum, &p1, &p2);
    if (sum.inf) return 0;

    u256 v;
    u256_mod(&v, &sum.x, &P256_N);
    return u256_cmp(&v, &r) == 0;
}

int main(void) {
    int fail = 0;
    char hx[129];

    /* --- SHA-256 标准向量 --- */
    uint8_t d[32];
    sha256("abc", 3, d);
    hex(d, 32, hx);
    const char *want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    printf("[%s] SHA-256(\"abc\") = %s\n", strcmp(hx, want) == 0 ? "PASS" : "FAIL", hx);
    if (strcmp(hx, want)) fail++;

    /* --- 空串 --- */
    sha256("", 0, d);
    hex(d, 32, hx);
    const char *want2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    printf("[%s] SHA-256(\"\")   = %s\n", strcmp(hx, want2) == 0 ? "PASS" : "FAIL", hx);
    if (strcmp(hx, want2)) fail++;

    /* --- 基线：d=1 → Q == G --- */
    u256 one = {{1,0,0,0}};
    uint8_t pub[65];
    p256_pubkey(&one, pub);
    uint8_t gx[32], gy[32];
    u256_to_be(&P256_G.x, gx);
    u256_to_be(&P256_G.y, gy);
    int g_ok = memcmp(pub + 1, gx, 32) == 0 && memcmp(pub + 33, gy, 32) == 0;
    printf("[%s] d=1 → Q==G\n", g_ok ? "PASS" : "FAIL");
    if (!g_ok) fail++;

    /* --- 签名 / 验签往返 --- */
    uint8_t dbe[32];
    memset(dbe, 0, 32);
    dbe[31] = 7;                                    /* d = 7 */
    u256 dk; u256_from_be(&dk, dbe);
    p256_pubkey(&dk, pub);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7 + 3);
    uint8_t h[32];
    sha256(msg, sizeof msg, h);

    int round_ok = 1;
    for (int t = 0; t < 5; t++) {
        uint8_t r[32], s[32];
        if (p256_ecdsa_sign(&dk, h, r, s) != 0) { round_ok = 0; break; }
        if (!verify(pub, h, r, s)) { round_ok = 0; break; }
    }
    printf("[%s] ECDSA 签名/验签 x5\n", round_ok ? "PASS" : "FAIL");
    if (!round_ok) fail++;

    /* --- 输出一组签名，供 host openssl 交叉验证 --- */
    uint8_t r[32], s[32];
    p256_ecdsa_sign(&dk, h, r, s);
    hex(pub, 65, hx);  printf("PUB=%s\n", hx);
    hex(r, 32, hx);    printf("R=%s\n", hx);
    hex(s, 32, hx);    printf("S=%s\n", hx);
    hex(h, 32, hx);    printf("HASH=%s\n", hx);

    printf("\n%s (%d failure%s)\n", fail ? "SELFTEST FAILED" : "ALL PASS",
           fail, fail == 1 ? "" : "s");
    return fail ? 1 : 0;
}
