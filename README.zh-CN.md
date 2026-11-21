<p align="center">
  <img src="https://img.shields.io/badge/Android-12%2B-3ddc84?style=flat-square&logo=android&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" />
</p>

<h1 align="center">VeilTEE</h1>

<p align="center">一个重写 Android 密钥认证的 KernelSU 模块。</p>

---

## 它做什么

```
keystore2  ──►  [ioctl 层拦截]  ──►  重签 leaf  ──►  App
```

模块注入 `keystore2`，在 Binder 层拦下 `generateKey` 事务，返回一张 `RootOfTrust` 显示「已锁定、已校验」的证书。原始认证公钥和 challenge 保持不变，所以 App 自己的签名校验仍然通过。

App 进程内没有注入任何东西。

---

## 安装

```bash
ksud module install VeilTEE-v1.2.0.zip
reboot
su -c /data/adb/veiltee/bin/veilctl verify
```

```
[✓] ro.boot.flash.locked          1
[✓] ro.boot.verifiedbootstate     green
[✓] ro.boot.vbmeta.device_state   locked
[✓] attestation generated         601 bytes
    three-green: 3/3
```

需要 KernelSU 与 Android 12+。包含 `arm64-v8a` 与 `x86_64`。

---

## keybox

`config/keybox.xml` 内置自签测试 CA。它能让 `RootOfTrust` 全绿，但链根不在 Google 信任列表里，严格链校验会失败。

替换前先用工具验证：

```bash
veilctl keybox /sdcard/candidate.xml
```

链根是 `Google Hardware Attestation Root` 返回 `0`，否则返回 `2`。检查项：私钥格式、证书解析、有效期、私钥与公钥匹配、逐级签名验证、根身份。

---

## 配置

```ini
# /data/adb/modules/veiltee/config/veil.conf
enabled=1
device_locked=1        # RootOfTrust.deviceLocked
boot_state=0           # 0=Verified
security_level=1       # 1=TEE
os_version=16
patch_level=2026-11-05
vb_key=                # 留空 → /data/adb/veiltee/vb_key
vb_hash=               # 留空 → /data/adb/veiltee/vb_hash
keybox=/data/adb/modules/veiltee/config/keybox.xml
```

`vb_key` / `vb_hash` 默认取设备真实的 vbmeta digest（由 `post-fs-data.sh` 落盘），保证证书与系统属性同源。

---

## 构建

```bash
cd src
make NDK=$ANDROID_NDK_HOME     # 交叉编译双架构
make host                      # 本机密码学自检
```

`make host` 校验 SHA-256 向量、P-256 点运算、ECDSA 签名往返。不链接任何第三方密码库，P-256 / SHA-256 / DER / X.509 全部在 `src/` 内实现。

---

## 原理

**注入** — `ptrace` 附身，远程 `mmap`，从 `memfd` 加载库，远程 `dlopen`。把 `lr` 置 0 让函数返回变成 `SIGSEGV`，借此捕获调用结果。

**拦截** — `dl_iterate_phdr` 遍历已加载库，按符号名匹配 `R_AARCH64_JUMP_SLOT` 重定位，改写 `ioctl` 的 GOT 槽位。代码段不动。

**改写** — 在 Binder `Parcel` 里扫认证 OID `1.3.6.1.4.1.11129.2.1.17`，用 keybox 私钥重签 leaf，等长替换（用未分配的 context tag 填充）。

**隐藏** — 进程名伪装、`memfd` 加载、libc 层净化 `/proc/self/{status,maps,mountinfo}`。

---

## 边界

- `MEETS_STRONG_INTEGRITY` 需要 TEE 内的设备密钥，结果取决于 keybox 是否有效。
- 模块不修改任何分区，`boot` / `lk` / `vbmeta` 均不触碰。
- 传感器行为分析、多开容器检测不在范围内。

---

## 免责

用于认证协议研究与自有设备调试。

## License

[MIT](LICENSE)
