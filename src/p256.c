/* p256.c —— 零依赖 P-256 ECDSA 实现 */
#include "p256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __ANDROID__
#include <sys/random.h>
#endif

const u256 P256_P = {{ 0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
                       0x0000000000000000ULL, 0xFFFFFFFF00000001ULL }};
/* P = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
   limb0 最低：0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0, 0xFFFFFFFF00000001 */

const u256 P256_N = {{ 0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL,
                       0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL }};
/* N = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551 */

static const uint8_t GX_BE[32] = {
    0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
    0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96
};
static const uint8_t GY_BE[32] = {
    0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
    0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5
};
/* B = 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B */
static const uint8_t B_BE[32] = {
    0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,0xB3,0xEB,0xBD,0x55,0x76,0x98,0x86,0xBC,
    0x65,0x1D,0x06,0xB0,0xCC,0x53,0xB0,0xF6,0x3B,0xCE,0x3C,0x3E,0x27,0xD2,0x60,0x4B
};

point P256_G;

void u256_from_be(u256 *r, const uint8_t be[32]) {
    r->v[3] = ((uint64_t)be[0]<<56)|((uint64_t)be[1]<<48)|((uint64_t)be[2]<<40)|((uint64_t)be[3]<<32)
             |((uint64_t)be[4]<<24)|((uint64_t)be[5]<<16)|((uint64_t)be[6]<<8)|be[7];
    r->v[2] = ((uint64_t)be[8]<<56)|((uint64_t)be[9]<<48)|((uint64_t)be[10]<<40)|((uint64_t)be[11]<<32)
             |((uint64_t)be[12]<<24)|((uint64_t)be[13]<<16)|((uint64_t)be[14]<<8)|be[15];
    r->v[1] = ((uint64_t)be[16]<<56)|((uint64_t)be[17]<<48)|((uint64_t)be[18]<<40)|((uint64_t)be[19]<<32)
             |((uint64_t)be[20]<<24)|((uint64_t)be[21]<<16)|((uint64_t)be[22]<<8)|be[23];
    r->v[0] = ((uint64_t)be[24]<<56)|((uint64_t)be[25]<<48)|((uint64_t)be[26]<<40)|((uint64_t)be[27]<<32)
             |((uint64_t)be[28]<<24)|((uint64_t)be[29]<<16)|((uint64_t)be[30]<<8)|be[31];
}

void u256_to_be(const u256 *a, uint8_t be[32]) {
    for (int i = 0; i < 32; i++) {
        int limb = 3 - (i / 8);
        int sh = 56 - (i % 8) * 8;
        be[i] = (uint8_t)(a->v[limb] >> sh);
    }
}

int u256_is_zero(const u256 *a) {
    return !(a->v[0] | a->v[1] | a->v[2] | a->v[3]);
}

int u256_cmp(const u256 *a, const u256 *b) {
    for (int i = 3; i >= 0; i--) {
        if (a->v[i] < b->v[i]) return -1;
        if (a->v[i] > b->v[i]) return 1;
    }
    return 0;
}

void u256_add(u256 *r, const u256 *a, const u256 *b) {
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 s = (unsigned __int128)a->v[i] + b->v[i] + c;
        r->v[i] = (uint64_t)s;
        c = s >> 64;
    }
}

void u256_sub(u256 *r, const u256 *a, const u256 *b) {
    unsigned __int128 br = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 d = (unsigned __int128)a->v[i] - b->v[i] - br;
        r->v[i] = (uint64_t)d;
        br = (d >> 64) ? 1 : 0;
    }
}

/* 512 位 => 256 位取模（逐位移位长除法，5 limb 余数防溢出） */
static void reduce512(const uint64_t in[8], const u256 *m, u256 *out) {
    uint64_t rem[5] = {0,0,0,0,0};
    uint64_t mm[5]  = {m->v[0], m->v[1], m->v[2], m->v[3], 0};

    for (int bit = 511; bit >= 0; bit--) {
        /* rem <<= 1 */
        for (int i = 4; i > 0; i--) rem[i] = (rem[i] << 1) | (rem[i-1] >> 63);
        rem[0] <<= 1;
        rem[0] |= (in[bit / 64] >> (bit % 64)) & 1ULL;

        /* if rem >= m: rem -= m */
        int ge = 0;
        for (int i = 4; i >= 0; i--) {
            if (rem[i] > mm[i]) { ge = 1; break; }
            if (rem[i] < mm[i]) { ge = 0; break; }
        }
        if (ge) {
            unsigned __int128 br = 0;
            for (int i = 0; i < 5; i++) {
                unsigned __int128 d = (unsigned __int128)rem[i] - mm[i] - br;
                rem[i] = (uint64_t)d;
                br = (d >> 64) ? 1 : 0;
            }
        }
    }
    out->v[0] = rem[0]; out->v[1] = rem[1]; out->v[2] = rem[2]; out->v[3] = rem[3];
}

void u256_mod(u256 *r, const u256 *a, const u256 *m) {
    if (u256_cmp(a, m) < 0) { *r = *a; return; }
    uint64_t in[8] = {a->v[0], a->v[1], a->v[2], a->v[3], 0,0,0,0};
    reduce512(in, m, r);
}

static void mul256(const u256 *a, const u256 *b, uint64_t out[8]) {
    memset(out, 0, 8 * sizeof(uint64_t));
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 cur = (unsigned __int128)a->v[i] * b->v[j]
                                  + out[i+j] + carry;
            out[i+j] = (uint64_t)cur;
            carry = cur >> 64;
        }
        out[i+4] += (uint64_t)carry;
    }
}

void u256_modmul(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    uint64_t prod[8];
    mul256(a, b, prod);
    reduce512(prod, m, r);
}

void u256_modsub(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    if (u256_cmp(a, b) >= 0) { u256_sub(r, a, b); return; }
    u256 t;
    u256_sub(&t, m, b);          /* m - b */
    u256_add(r, &t, a);          /* + a，< m，不会溢出 */
}

void u256_modadd(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    u256 s;
    u256_add(&s, a, b);
    /* 可能进位溢出，用 512 位路径兜底 */
    if (u256_cmp(&s, a) < 0) {
        uint64_t in[8] = {s.v[0], s.v[1], s.v[2], s.v[3], 1,0,0,0};
        reduce512(in, m, r);
    } else if (u256_cmp(&s, m) >= 0) {
        u256_sub(&s, &s, m);
        *r = s;
    } else *r = s;
}

void u256_modinv(u256 *r, const u256 *a, const u256 *m) {
    /* 费马：a^(m-2) mod m */
    u256 e = *m;
    u256 two = {{2,0,0,0}};
    u256_sub(&e, &e, &two);
    u256 base = *a, acc = {{1,0,0,0}};
    for (int i = 0; i < 256; i++) {
        if ((e.v[i/64] >> (i%64)) & 1ULL)
            u256_modmul(&acc, &acc, &base, m);
        u256_modmul(&base, &base, &base, m);
    }
    *r = acc;
}

/* ---------- 曲线运算（仿射，公式直观易验证） ---------- */
static const u256 THREE = {{3,0,0,0}};

static void affine_double(point *r, const point *a) {
    if (a->inf || u256_is_zero(&a->y)) { r->inf = 1; return; }
    u256 num, den, inv, l, x3, y3, t;

    u256_modmul(&num, &a->x, &a->x, &P256_P);
    u256_modmul(&num, &num, &THREE, &P256_P);          /* 3x^2 */
    u256_modsub(&num, &num, &THREE, &P256_P);          /* + a, a = -3 */

    u256_modadd(&den, &a->y, &a->y, &P256_P);          /* 2y */
    u256_modinv(&inv, &den, &P256_P);
    u256_modmul(&l, &num, &inv, &P256_P);              /* l = (3x^2-3)/(2y) */

    u256_modmul(&x3, &l, &l, &P256_P);
    u256_modsub(&x3, &x3, &a->x, &P256_P);
    u256_modsub(&x3, &x3, &a->x, &P256_P);             /* x3 = l^2 - 2x */

    u256_modsub(&t, &a->x, &x3, &P256_P);
    u256_modmul(&y3, &l, &t, &P256_P);
    u256_modsub(&y3, &y3, &a->y, &P256_P);             /* y3 = l(x-x3) - y */

    r->x = x3; r->y = y3; r->inf = 0;
}

static void affine_add(point *r, const point *a, const point *b) {
    if (a->inf) { *r = *b; return; }
    if (b->inf) { *r = *a; return; }
    if (u256_cmp(&a->x, &b->x) == 0) {
        if (u256_cmp(&a->y, &b->y) == 0) { affine_double(r, a); return; }
        r->inf = 1; return;
    }
    u256 num, den, inv, l, x3, y3, t;
    u256_modsub(&num, &b->y, &a->y, &P256_P);
    u256_modsub(&den, &b->x, &a->x, &P256_P);
    u256_modinv(&inv, &den, &P256_P);
    u256_modmul(&l, &num, &inv, &P256_P);
    u256_modmul(&x3, &l, &l, &P256_P);
    u256_modsub(&x3, &x3, &a->x, &P256_P);
    u256_modsub(&x3, &x3, &b->x, &P256_P);
    u256_modsub(&t, &a->x, &x3, &P256_P);
    u256_modmul(&y3, &l, &t, &P256_P);
    u256_modsub(&y3, &y3, &a->y, &P256_P);
    r->x = x3; r->y = y3; r->inf = 0;
}

/* ---------- Jacobian 坐标（点乘用，避免每步求逆） ---------- */
typedef struct { u256 X, Y, Z; } jpoint;

static void jac_double(jpoint *r, const jpoint *a) {
    if (u256_is_zero(&a->Z) || u256_is_zero(&a->Y)) {
        u256 z = {{0,0,0,0}}; r->X = z; r->Y = z; r->Z = z; return;
    }
    u256 yy, s, m, t, xx, zz, z4, X3, Y3, Z3;
    u256_modmul(&yy, &a->Y, &a->Y, &P256_P);
    u256_modmul(&s, &a->X, &yy, &P256_P);
    u256_modadd(&s, &s, &s, &P256_P);
    u256_modadd(&s, &s, &s, &P256_P);                 /* S = 4XY^2 */

    u256_modmul(&xx, &a->X, &a->X, &P256_P);
    u256_modmul(&m, &xx, &THREE, &P256_P);
    u256_modmul(&zz, &a->Z, &a->Z, &P256_P);
    u256_modmul(&z4, &zz, &zz, &P256_P);
    u256_modmul(&t, &z4, &THREE, &P256_P);
    u256_modsub(&m, &m, &t, &P256_P);                 /* M = 3X^2 - 3Z^4 */

    u256_modmul(&X3, &m, &m, &P256_P);
    u256_modsub(&X3, &X3, &s, &P256_P);
    u256_modsub(&X3, &X3, &s, &P256_P);               /* X3 = M^2 - 2S */

    u256_modsub(&t, &s, &X3, &P256_P);
    u256_modmul(&Y3, &m, &t, &P256_P);
    u256_modmul(&yy, &yy, &yy, &P256_P);
    u256_modadd(&yy, &yy, &yy, &P256_P);
    u256_modadd(&yy, &yy, &yy, &P256_P);
    u256_modadd(&yy, &yy, &yy, &P256_P);              /* 8Y^4 */
    u256_modsub(&Y3, &Y3, &yy, &P256_P);

    u256_modmul(&Z3, &a->Y, &a->Z, &P256_P);
    u256_modadd(&Z3, &Z3, &Z3, &P256_P);              /* Z3 = 2YZ */

    r->X = X3; r->Y = Y3; r->Z = Z3;
}

static void jac_add(jpoint *r, const jpoint *a, const jpoint *b) {
    if (u256_is_zero(&a->Z)) { *r = *b; return; }
    if (u256_is_zero(&b->Z)) { *r = *a; return; }
    u256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t, X3, Y3, Z3;
    u256_modmul(&z1z1, &a->Z, &a->Z, &P256_P);
    u256_modmul(&z2z2, &b->Z, &b->Z, &P256_P);
    u256_modmul(&u1, &a->X, &z2z2, &P256_P);
    u256_modmul(&u2, &b->X, &z1z1, &P256_P);
    u256_modmul(&s1, &a->Y, &b->Z, &P256_P);
    u256_modmul(&s1, &s1, &z2z2, &P256_P);
    u256_modmul(&s2, &b->Y, &a->Z, &P256_P);
    u256_modmul(&s2, &s2, &z1z1, &P256_P);

    if (u256_cmp(&u1, &u2) == 0) {
        if (u256_cmp(&s1, &s2) == 0) { jac_double(r, a); return; }
        u256 z = {{0,0,0,0}}; r->X = z; r->Y = z; r->Z = z; return;
    }
    u256_modsub(&h, &u2, &u1, &P256_P);
    u256_modadd(&i, &h, &h, &P256_P);
    u256_modmul(&i, &i, &i, &P256_P);                 /* I = (2H)^2 */
    u256_modmul(&j, &h, &i, &P256_P);                 /* J = H*I */
    u256_modsub(&rr, &s2, &s1, &P256_P);
    u256_modadd(&rr, &rr, &rr, &P256_P);
    u256_modmul(&v, &u1, &i, &P256_P);

    u256_modmul(&X3, &rr, &rr, &P256_P);
    u256_modsub(&X3, &X3, &j, &P256_P);
    u256_modsub(&X3, &X3, &v, &P256_P);
    u256_modsub(&X3, &X3, &v, &P256_P);

    u256_modsub(&t, &v, &X3, &P256_P);
    u256_modmul(&Y3, &rr, &t, &P256_P);
    u256_modmul(&t, &s1, &j, &P256_P);
    u256_modsub(&Y3, &Y3, &t, &P256_P);
    u256_modsub(&Y3, &Y3, &t, &P256_P);

    u256_modadd(&Z3, &a->Z, &b->Z, &P256_P);
    u256_modmul(&Z3, &Z3, &Z3, &P256_P);
    u256_modsub(&Z3, &Z3, &z1z1, &P256_P);
    u256_modsub(&Z3, &Z3, &z2z2, &P256_P);
    u256_modmul(&Z3, &Z3, &h, &P256_P);

    r->X = X3; r->Y = Y3; r->Z = Z3;
}

static void jac_to_affine(point *r, const jpoint *a) {
    if (u256_is_zero(&a->Z)) { r->inf = 1; return; }
    u256 zi, zi2, zi3;
    u256_modinv(&zi, &a->Z, &P256_P);
    u256_modmul(&zi2, &zi, &zi, &P256_P);
    u256_modmul(&zi3, &zi2, &zi, &P256_P);
    u256_modmul(&r->x, &a->X, &zi2, &P256_P);
    u256_modmul(&r->y, &a->Y, &zi3, &P256_P);
    r->inf = 0;
}

/* 4-bit 窗口标量乘（表用仿射，累加用 Jacobian） */
void p256_point_mul(point *r, const u256 *k, const point *p) {
    if (p->inf) { r->inf = 1; return; }
    point tbl[16];
    tbl[0].inf = 1;
    tbl[1] = *p;
    for (int i = 2; i < 16; i++) affine_add(&tbl[i], &tbl[i-1], p);

    jpoint acc;
    u256 z = {{0,0,0,0}};
    acc.X = z; acc.Y = z; acc.Z = z;

    for (int i = 63; i >= 0; i--) {
        for (int j = 0; j < 4; j++) jac_double(&acc, &acc);
        int nib = (int)((k->v[i / 16] >> ((i % 16) * 4)) & 0xF);
        if (nib) {
            jpoint jb;
            jb.X = tbl[nib].x; jb.Y = tbl[nib].y;
            jb.Z = (u256){{1,0,0,0}};
            jac_add(&acc, &acc, &jb);
        }
    }
    jac_to_affine(r, &acc);
}

void p256_point_add(point *r, const point *a, const point *b) {
    affine_add(r, a, b);
}

void p256_base_mul(point *r, const u256 *k) { p256_point_mul(r, k, &P256_G); }

/* 初始化曲线常量（线程安全：由调用方在 init 阶段执行一次） */
__attribute__((constructor)) static void p256_init(void) {
    u256_from_be(&P256_G.x, GX_BE);
    u256_from_be(&P256_G.y, GY_BE);
    P256_G.inf = 0;
}

static int rand_bytes(uint8_t *out, size_t n) {
#ifdef __ANDROID__
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(out + got, n - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
    }
    if (got == n) return 0;
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(out, 1, n, f);
    fclose(f);
    return r == n ? 0 : -1;
}

int p256_pubkey(const u256 *d, uint8_t out65[65]) {
    point q;
    p256_base_mul(&q, d);
    if (q.inf) return -1;
    out65[0] = 0x04;
    u256_to_be(&q.x, out65 + 1);
    u256_to_be(&q.y, out65 + 33);
    return 0;
}

int p256_ecdsa_sign(const u256 *d, const uint8_t hash[32],
                    uint8_t out_r[32], uint8_t out_s[32]) {
    u256 z, r, s, k, kinv, tmp;
    u256_from_be(&z, hash);
    /* z 截断到 n 位（P-256 的 n 是 256 位，直接 mod n） */
    u256_mod(&z, &z, &P256_N);

    for (int attempt = 0; attempt < 32; attempt++) {
        uint8_t kb[32];
        if (rand_bytes(kb, 32) != 0) return -1;
        u256_from_be(&k, kb);
        if (u256_is_zero(&k) || u256_cmp(&k, &P256_N) >= 0) continue;

        point R;
        p256_base_mul(&R, &k);
        if (R.inf) continue;
        u256_mod(&r, &R.x, &P256_N);
        if (u256_is_zero(&r)) continue;

        u256_modinv(&kinv, &k, &P256_N);
        u256_modmul(&tmp, &r, d, &P256_N);
        u256_modadd(&tmp, &tmp, &z, &P256_N);
        u256_modmul(&s, &kinv, &tmp, &P256_N);
        if (u256_is_zero(&s)) continue;

        /* low-s 规范化 */
        u256 half;
        {
            unsigned __int128 carry = 0;
            for (int i = 3; i >= 0; i--) {
                unsigned __int128 cur = (carry << 64) | P256_N.v[i];
                half.v[i] = (uint64_t)(cur >> 1);
                carry = cur & 1;
            }
        }
        if (u256_cmp(&s, &half) > 0) {
            u256_sub(&s, &P256_N, &s);
        }

        u256_to_be(&r, out_r);
        u256_to_be(&s, out_s);
        return 0;
    }
    return -2;
}

/* ECDSA 验签（供工具使用） */
int veil_ecdsa_verify(const uint8_t pub65[65], const uint8_t hash[32],
                      const uint8_t rb[32], const uint8_t sb[32]) {
    u256 r, s, z, w, u1, u2;
    u256_from_be(&r, rb); u256_from_be(&s, sb); u256_from_be(&z, hash);
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
    u256 v; u256_mod(&v, &sum.x, &P256_N);
    return u256_cmp(&v, &r) == 0;
}
