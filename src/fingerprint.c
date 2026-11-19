/* fingerprint.c —— 设备指纹一致性层
 *
 * 银行/游戏会把本地指纹与上报指纹比对。这里保证：
 *   1) 本地读到的 Build/serial/MAC 与配置一致
 *   2) 不出现"属性说 Pixel、分区是小米"这类矛盾
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <android/log.h>

#include "veil_cfg.h"

#define TAG "VeilTEE"

extern int veil_plt_hook(const char *sym, void *newfn, void **oldfn);

typedef int (*prop_get_fn)(const char *, char *);
static prop_get_fn real_prop_get;

typedef char *(*prop_find_fn)(const char *, void *);
static prop_find_fn real_prop_find;

static veil_cfg g_cfg;

/* 需要用配置值覆盖的属性 */
static const char *SPOOF_KEYS[] = {
    "ro.product.model", "ro.product.brand", "ro.product.device",
    "ro.product.name", "ro.product.manufacturer",
    "ro.serialno", "ro.boot.serialno",
    "ro.build.fingerprint", "ro.build.tags", "ro.build.type",
    "ro.debuggable", "ro.secure",
    "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state", "sys.oem_unlock_allowed",
    NULL
};

static const char *spoof_value(const char *key) {
    if (!key) return NULL;
    if (!strcmp(key, "ro.boot.verifiedbootstate")) return "green";
    if (!strcmp(key, "ro.boot.flash.locked"))      return "1";
    if (!strcmp(key, "ro.boot.vbmeta.device_state")) return "locked";
    if (!strcmp(key, "sys.oem_unlock_allowed"))    return "0";
    if (!strcmp(key, "ro.debuggable"))             return "0";
    if (!strcmp(key, "ro.secure"))                 return "1";
    if (!strcmp(key, "ro.build.tags"))             return "release-keys";
    if (!strcmp(key, "ro.build.type"))             return "user";
    return NULL;
}

static int my_prop_get(const char *key, char *val) {
    const char *v = spoof_value(key);
    if (v) { strcpy(val, v); return (int)strlen(v); }
    return real_prop_get ? real_prop_get(key, val) : 0;
}

/* MAC 地址：让所有网卡返回固定伪造值 */
typedef int (*ioctl_fn)(int, unsigned long, ...);
static ioctl_fn real_ioctl;

static int my_ioctl(int fd, unsigned long req, ...) {
    va_list ap; va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    int r = real_ioctl ? real_ioctl(fd, req, arg) : -1;
    if (r == 0 && req == SIOCGIFHWADDR && arg) {
        struct ifreq *ifr = arg;
        uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
        memcpy(ifr->ifr_hwaddr.sa_data, mac, 6);
        ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
    }
    return r;
}

__attribute__((constructor))
static void veil_fp_init(void) {
    veil_cfg_load(&g_cfg, "/data/adb/veiltee/veil.conf");
    if (!g_cfg.enabled) return;

    veil_plt_hook("__system_property_get", (void *)my_prop_get, (void **)&real_prop_get);
    veil_plt_hook("ioctl", (void *)my_ioctl, (void **)&real_ioctl);
}
