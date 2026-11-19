/* p256.h —— 零依赖 P-256 ECDSA（VeilTEE core） */
#ifndef VEIL_P256_H
#define VEIL_P256_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint64_t v[4]; } u256;          /* 小端 limb */
typedef struct { u256 x, y; int inf; } point;    /* 仿射 */

extern const u256 P256_P;   /* 域素数 */
extern const u256 P256_N;   /* 群阶 */
extern point P256_G;  /* 基点 */

void u256_from_be(u256 *r, const uint8_t be[32]);
void u256_to_be(const u256 *a, uint8_t be[32]);
int  u256_is_zero(const u256 *a);
int  u256_cmp(const u256 *a, const u256 *b);
void u256_add(u256 *r, const u256 *a, const u256 *b);
void u256_sub(u256 *r, const u256 *a, const u256 *b);
void u256_mod(u256 *r, const u256 *a, const u256 *m);          /* a 已是 < 2^256 */
void u256_modmul(u256 *r, const u256 *a, const u256 *b, const u256 *m);
void u256_modadd(u256 *r, const u256 *a, const u256 *b, const u256 *m);
void u256_modsub(u256 *r, const u256 *a, const u256 *b, const u256 *m);
void u256_modinv(u256 *r, const u256 *a, const u256 *m);       /* 费马 */

void p256_point_mul(point *r, const u256 *k, const point *p);
void p256_point_add(point *r, const point *a, const point *b);
void p256_base_mul(point *r, const u256 *k);

/* ECDSA 签名：返回 0 成功；r,s 为 32 字节大端 */
int p256_ecdsa_sign(const u256 *d, const uint8_t hash[32],
                    uint8_t out_r[32], uint8_t out_s[32]);

/* 从私钥推导公钥（未压缩点 04||X||Y，65 字节） */
int p256_pubkey(const u256 *d, uint8_t out65[65]);

#endif
