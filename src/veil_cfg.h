/* veil_cfg.h —— 统一配置（所有层读同一份，保证一致性） */
#ifndef VEIL_CFG_H
#define VEIL_CFG_H
#include <stdint.h>
#include <stddef.h>

#define VEIL_PEM_MAX 8192

typedef struct {
    int  enabled;
    int  device_locked;
    int  boot_state;          /* 0=Verified */
    int  security_level;      /* 1=TEE */
    int  os_version;
    char patch_level[16];
    char vb_key_hex[65];
    char vb_hash_hex[65];
    char keybox_priv[VEIL_PEM_MAX];
    char keybox_cert[VEIL_PEM_MAX];
    char state_dir[256];
} veil_cfg;

int veil_cfg_load(veil_cfg *c, const char *conf_path);
int veil_hex2bin(const char *hex, uint8_t *out, size_t cap);

#endif
