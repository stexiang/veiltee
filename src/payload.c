/* payload.c —— 注入 keystore2 的载荷：Binder 事务级 attestation 改写 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <android/log.h>
#include <linux/android/binder.h>

#include "attest.h"
#include "veil_cfg.h"

#define TAG "VeilTEE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

typedef int (*ioctl_fn)(int, unsigned long, ...);
static ioctl_fn g_ioctl;

extern int veil_plt_hook(const char *sym, void *newfn, void **oldfn);
extern int veil_rewrite_reply(uint8_t *data, size_t size, uint32_t code,
                              const veil_cfg *cfg);

/* KeyMint IKeyMintDevice 的 AIDL transaction code */
enum {
    TX_GENERATE_KEY    = 3,
    TX_IMPORT_KEY      = 4,
    TX_IMPORT_WRAPPED  = 5,
    TX_UPGRADE_KEY     = 6,
};

static veil_cfg g_cfg;
static __thread uint32_t t_pending_code;
static __thread int      t_have_pending;

/* 扫描 write_buffer，找出本次事务的 code */
static int scan_write(const void *buf, size_t size, uint32_t *code_out) {
    const uint8_t *p = buf;
    size_t off = 0;
    while (off + 8 <= size) {
        uint32_t cmd = *(const uint32_t *)(p + off);
        uint32_t c = cmd & 0xFFFFu;
        if (c == BC_TRANSACTION) {
            if (off + 8 + sizeof(struct binder_transaction_data) > size) return 0;
            const struct binder_transaction_data *tr =
                (const struct binder_transaction_data *)(p + off + 8);
            *code_out = tr->code;
            return 1;
        }
        /* 非目标命令：按 4 字节推进扫描（仅用于找 code，错位无副作用） */
        off += 4;
    }
    return 0;
}

/* 扫描 read_buffer 里的 BR_REPLY，命中就改写 Parcel 数据区 */
static void scan_read(void *buf, size_t size, uint32_t code) {
    uint8_t *p = buf;
    size_t off = 0;
    while (off + 8 <= size) {
        uint32_t cmd = *(uint32_t *)(p + off);
        uint32_t c = cmd & 0xFFFFu;
        if (c == BR_REPLY) {
            if (off + 8 + sizeof(struct binder_transaction_data) > size) return;
            struct binder_transaction_data *tr =
                (struct binder_transaction_data *)(p + off + 8);
            if (tr->data_size && tr->data.ptr.buffer) {
                veil_rewrite_reply((uint8_t *)(uintptr_t)tr->data.ptr.buffer,
                                   tr->data_size, code, &g_cfg);
            }
            off += 8 + sizeof(struct binder_transaction_data);
            continue;
        }
        off += 4;
    }
}

static int veil_ioctl(int fd, unsigned long req, ...) {
    va_list ap; va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    if (!g_ioctl) g_ioctl = (ioctl_fn)dlsym(RTLD_NEXT, "ioctl");
    if (!g_ioctl) return -1;

    if (req != BINDER_WRITE_READ || !arg)
        return g_ioctl(fd, req, arg);

    struct binder_write_read *bwr = (struct binder_write_read *)arg;
    uint32_t code = 0;
    if (bwr->write_size && bwr->write_buffer) {
        if (scan_write((void *)(uintptr_t)bwr->write_buffer, bwr->write_size, &code)) {
            t_pending_code = code;
            t_have_pending = (code == TX_GENERATE_KEY || code == TX_IMPORT_KEY ||
                              code == TX_IMPORT_WRAPPED || code == TX_UPGRADE_KEY);
        }
    }

    int ret = g_ioctl(fd, req, arg);

    if (ret >= 0 && bwr->read_consumed && bwr->read_buffer && t_have_pending) {
        scan_read((void *)(uintptr_t)bwr->read_buffer, bwr->read_consumed, t_pending_code);
        t_have_pending = 0;
    }
    return ret;
}

__attribute__((constructor))
static void veil_payload_init(void) {
    if (veil_cfg_load(&g_cfg, "/data/adb/veiltee/veil.conf") != 0) {
        LOGI("config missing, using defaults");
    }
    if (veil_plt_hook("ioctl", (void *)veil_ioctl, (void **)&g_ioctl) == 0) {
        LOGI("binder hook installed (GOT patch only)");
    } else {
        LOGE("GOT patch failed");
    }
}
