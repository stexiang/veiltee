<p align="center">
  <img src="https://img.shields.io/badge/Android-12%2B-3ddc84?style=flat-square&logo=android&logoColor=white" />
  <img src="https://img.shields.io/badge/KernelSU-ready-00b894?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-success?style=flat-square" />
</p>

<h1 align="center">VeilTEE</h1>
<p align="center"><b>帷幕</b> —— 一个不依赖 Zygisk / LSPosed 的 KernelSU 模块</p>
<p align="center">在内核层隐藏痕迹，在 Binder 事务层改写 attestation，在证书层重签 leaf</p>

---

## 它是什么

VeilTEE 把 Android 的「设备可信状态」拆成三层，逐层接管：

```
┌──────────────────────────────────────────────────────────────┐
│ L1 净化层   libc 拦截 + memfd 虚拟文件（无需内核补丁）          │
│   open/stat/access/readlink 命中敏感路径 → ENOENT              │
│   /proc/self/{status,maps,mountinfo} → memfd 净化副本          │
│   → 检测方任何读法都拿到干净内容                                │
├──────────────────────────────────────────────────────────────┤
│ L2 事务层   注入 keystore2，PLT/GOT 改写 ioctl                │
│   拦截 BC_TRANSACTION / BR_REPLY，命中 generateKey 时改 reply  │
│   → App 侧零注入、零 so、零 maps 痕迹                          │
├──────────────────────────────────────────────────────────────┤
│ L3 密码层   keybox 重签 leaf                                  │
│   保留原 attestation 公钥 + challenge，只换 RootOfTrust 扩展   │
│   → App 用自己的私钥签 challenge，验签照样通过                  │
└──────────────────────────────────────────────────────────────┘
```

**关键设计**：注入目标是 `keystore2` daemon，不是 App。检测器在 App 进程里找不到任何注入物。

---

## 特性

| 能力 | 实现 |
|---|---|
| **三绿 attestation** | `deviceLocked=TRUE`、`verifiedBootState=Verified`、`verifiedBootKey/Hash` 与 vbmeta 同源 |
| **零第三方依赖** | P-256 / SHA-256 / DER / X.509 全部手写，不链接 OpenSSL |
| **无需 susfs** | 隐藏全靠用户态 + memfd，任意 KernelSU / 内核均可 |
| **无 Zygisk / LSPosed** | ptrace 注入 native daemon，不依赖任何 hook 框架 |
| **GOT-only hook** | 只改 `.got.plt`，代码段零修改，`maps` 无新增可执行段 |
| **memfd 虚拟文件** | 净化后的 `/proc/self/{status,maps,mountinfo}`，任何读法都干净 |
| **检测对抗层** | root / hook / 调试 / 环境 / 指纹 五类检测点统一拦截 |
| **双架构** | `arm64-v8a` + `x86_64` |

---

## 快速开始

```bash
# 1. 安装（任意 KernelSU 版本，不需要 susfs）
ksud module install VeilTEE-v1.2.0.zip

# 2. 重启
reboot

# 3. 体检
su -c /data/adb/modules/veiltee/bin/veilctl verify
su -c /data/adb/modules/veiltee/bin/veilctl keybox
```

预期输出：

```
┌─ VeilTEE 体检报告 ─────────────────────────────
│ [✓] ro.boot.flash.locked                   1
│ [✓] ro.boot.verifiedbootstate              green
│ [✓] ro.boot.vbmeta.device_state            locked
│ [✓] sys.oem_unlock_allowed                 0
│ [✓] ro.boot.veritymode                     enforcing
│ [✓] attestation 生成                       601 bytes
├────────────────────────────────────────────────
│ 三绿: 3/3   KeyAttestation 全绿
└────────────────────────────────────────────────
```

---

## 构建

需要 Android NDK（r26 测试通过）：

```bash
cd src
make NDK=$HOME/Library/Android/sdk/ndk/android-ndk-r26d    # 交叉编译
make host                                                   # 本机密码学自检
```

`make host` 会跑：

```
[PASS] SHA-256("abc")
[PASS] SHA-256("")
[PASS] d=1 → Q==G
[PASS] ECDSA 签名/验签 x5
ALL PASS (0 failures)
```

---

## 目录

```
veiltee/
├── module.prop            KSU 模块元信息
├── customize.sh           安装脚本（按 ABI 选二进制）
├── post-fs-data.sh        属性对齐 + vbmeta digest 落盘 + 二进制落地
├── service.sh             启动 veilteed
├── uninstall.sh
├── sepolicy.rule
├── bin/{arm64-v8a,x86_64}/{libveil.so, libveil_app.so, veilteed, veilctl}
├── config/{veil.conf, keybox.xml}
└── src/
    ├── p256.c             256 位大数 + P-256 + ECDSA
    ├── sha256.c           SHA-256
    ├── der.h              DER/TLV 编码器
    ├── attest.c           KeyDescription + RootOfTrust + X.509 签发
    ├── plthook.c          GOT 改写
    ├── payload.c          Binder 事务拦截
    ├── rewrite.c          Parcel 证书扫描与等长替换
    ├── hardening.c        检测对抗（root/hook/debug）
    ├── fingerprint.c      设备指纹一致性
    ├── injector.c         ptrace 注入
    ├── veilteed.c         主守护
    ├── veilctl.c          体检 CLI
    ├── keybox_check.c     keybox 链验证
    └── selftest.c         host 自检
```

---

## 配置

```ini
# config/veil.conf
enabled=1
device_locked=1        # 第一绿
boot_state=0           # 第二绿：0=Verified
security_level=1       # 1=TEE
os_version=16
patch_level=2026-11-05
vb_key=                # 留空 → 读 /data/adb/veiltee/vb_key
vb_hash=               # 留空 → 读 /data/adb/veiltee/vb_hash
state_dir=/data/adb/veiltee
keybox=/data/adb/modules/veiltee/config/keybox.xml
```

---

## keybox

`config/keybox.xml` 默认是**自签测试 CA**，用于验证完整链路。它能让 `RootOfTrust` 三绿，但链根不在 Google 信任列表。

用 `veilctl keybox` 验证任何 keybox：

```bash
veilctl keybox /sdcard/candidate.xml
```

判定标准只有一条：**链根 subject 是 `Google Hardware Attestation Root`**。

| 来源 | 字段三绿 | 过严格链校验 |
|---|---|---|
| 自签（默认） | ✅ | ❌ |
| AOSP test key | ✅ | ❌ |
| 厂商硬件 keybox | ✅ | ✅（未吊销时） |

---

## 检测覆盖

| 类别 | 检测点 | 拦截位置 |
|---|---|---|
| Root 路径 | `su` / `magisk` / `ksu` 文件 | `open/stat/access/readlink` → `ENOENT` |
| Root 执行 | `Runtime.exec("su")` | `execve` → `ENOENT` |
| 调试 | `PTRACE_TRACEME` | 直接返回 0 |
| TracerPid | `/proc/self/status` | memfd 虚拟文件，值归零 |
| maps 扫描 | `magisk`/`frida`/`xposed`/`libveil` | memfd 虚拟 maps，敏感行剔除 |
| 挂载表 | overlay / magisk | memfd 虚拟挂载表 |
| 属性 | `ro.boot.*` / `ro.debuggable` | `__system_property_get` 覆盖 |
| 设备指纹 | Build / serial / MAC | 属性层 + `SIOCGIFHWADDR` |
| Attestation | `RootOfTrust` | keystore2 层重签 |

---

## 原理速览

1. **注入**：`ptrace(ATTACH)` → 远程 `mmap` → 写 so 路径 → 远程 `dlopen`，构造函数即 hook 安装点。`lr=0` 触发 `SIGSEGV` 捕获返回值，是整个远程调用能跑通的关键。
2. **拦截**：`dl_iterate_phdr` 遍历已加载 so，解析 `DT_JMPREL`，按 `R_AARCH64_JUMP_SLOT` 匹配符号名，改写 GOT 槽位。
3. **改写**：Parcel 是裸字节流，用 ASN.1 特征（OID `1.3.6.1.4.1.11129.2.1.17`）定位证书，保留公钥与 challenge，只替换 `RootOfTrust` 并重签，最后等长替换（未定义 tag 填充）。
4. **签名**：P-256（Jacobian + 4-bit 窗口，单签 ~70ms）+ SHA-256 + 手写 X.509。
5. **隐藏**：进程名伪装（`prctl` + 覆盖 `argv[0]`）→ memfd 内存加载（maps 里是 `/memfd:veil (deleted)`）→ libc 层 `/proc` 净化 → GOT-only hook。全部在用户态完成，不需要内核补丁。

---

## 为什么不需要 susfs

susfs 解决的是「内核可见性」——让 `/proc/mounts`、`/proc/self/maps`、`stat()` 在内核层就看不到模块痕迹。

但对 App 而言，**所有检测最终都走 libc**：

```
File.exists()        → access()
File.length()        → stat()
new FileInputStream  → open()
Runtime.exec("su")   → execve()
Debug.isDebuggerConnected → ptrace()
```

所以 `libveil_app.so` 直接 hook 这几个 libc 函数，**在用户态达到与 susfs 相同的观测效果**：

| 场景 | susfs | 本模块（无 susfs） |
|---|---|---|
| App 扫 `/data/adb/modules` | 内核隐藏 | `open` 返回 `ENOENT` |
| App 读 `/proc/self/maps` | 内核过滤 | memfd 返回净化副本 |
| App 读 `/proc/self/status` | 内核过滤 | `TracerPid` 归零 |
| App `which su` | 内核隐藏 | `access/execve` 返回 `ENOENT` |
| **root shell 直接看** | 需 susfs | 看得到（这是唯一差别） |

最后一行是真实差距：**有 root 权限的检测方**能绕过 libc 看到原始状态。但这类检测在 App 场景中极少——它们需要先拿到 root，而拿到 root 本身就已经是最高级别信号。

### 隐藏三件套（全部用户态）

```c
// 1) 进程名伪装：/proc/pid/cmdline 显示 logd
prctl(PR_SET_NAME, "logd", 0, 0, 0);
memset(argv[0], 0, strlen(argv[0]));
strcpy(argv[0], "logd");

// 2) memfd 内存加载：so 不在磁盘上可加载，maps 显示 /memfd:veil (deleted)
memfd_create("veil") → write(so) → dlopen("/proc/self/fd/N")

// 3) 二进制落地到 /data/adb/veiltee/bin，不从模块目录执行
```

---

## 边界

- `MEETS_STRONG_INTEGRITY` 需要 TEE 内的设备私钥，软件层触及不到；取决于 keybox 是否有效。
- **本模块不改任何分区**，不触碰 `boot` / `lk` / `vbmeta`。
- 若设备此前自行 patch 过引导链（例如改 `lk` 或 `boot` 做伪回锁），分区 hash 会与官方固件不一致。这类「读分区比对 hash」的检测不在覆盖范围内——它需要的是**未修改的分区内容**，和 attestation 是两条独立的链路。
- 传感器行为分析、多开容器检测未覆盖。

---

## 免责

本项目用于 Android 安全机制研究、attestation 协议分析与自有设备调试。使用前请确认你拥有设备的完全控制权，并自行承担一切后果。

---

## License

[MIT](LICENSE) © 2026 VeilTEE Contributors
