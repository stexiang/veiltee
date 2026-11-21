<p align="center">
  <img src="https://img.shields.io/badge/Android-12%2B-3ddc84?style=flat-square&logo=android&logoColor=white" />
  <img src="https://img.shields.io/badge/KernelSU-ready-00b894?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-success?style=flat-square" />
</p>

<h1 align="center">VeilTEE</h1>

<p align="center"><b>A KernelSU module that needs neither Zygisk nor LSPosed.</b></p>
<p align="center">Hides traces in user space, rewrites attestation at the Binder transaction layer, re-signs the leaf certificate at the crypto layer.</p>

<p align="center">
  <a href="README.zh-CN.md">简体中文</a>
</p>

---

## What it is

VeilTEE takes Android's "trusted device state" apart into three layers and takes over each one:

```
┌──────────────────────────────────────────────────────────────┐
│ L1  Sanitizing layer   libc interception + memfd files        │
│     open/stat/access/readlink on sensitive paths → ENOENT     │
│     /proc/self/{status,maps,mountinfo} → sanitized memfd copy │
│     → every read path returns a clean view                    │
├──────────────────────────────────────────────────────────────┤
│ L2  Transaction layer   injected into keystore2, GOT-patched  │
│     intercepts BC_TRANSACTION / BR_REPLY, rewrites the reply  │
│     on generateKey                                            │
│     → nothing injected into the app process                   │
├──────────────────────────────────────────────────────────────┤
│ L3  Crypto layer   leaf re-signing with a keybox              │
│     keeps the original attestation public key and challenge,   │
│     replaces only the RootOfTrust extension                    │
│     → the app still signs its own challenge and verifies       │
└──────────────────────────────────────────────────────────────┘
```

**Key design decision:** the injection target is the `keystore2` daemon, not the app. A detector looking inside the app process finds no injected library, no extra mapping, no modified byte.

---

## Features

| Capability | Implementation |
|---|---|
| **Three-green attestation** | `deviceLocked=TRUE`, `verifiedBootState=Verified`, `verifiedBootKey/Hash` derived from the real vbmeta digest |
| **Zero third-party dependencies** | P-256 / SHA-256 / DER / X.509 written from scratch; no OpenSSL linkage |
| **No Zygisk / LSPosed** | ptrace injection into a native daemon; no hooking framework required |
| **GOT-only hooking** | only `.got.plt` is rewritten; code segments untouched; no new executable mapping |
| **memfd virtual files** | sanitized `/proc/self/{status,maps,mountinfo}`; every read path is clean |
| **Detection countermeasures** | root / hook-framework / debugger / environment / fingerprint |
| **No susfs required** | hiding is purely user-space; works on any KernelSU build |
| **Dual ABI** | `arm64-v8a` + `x86_64` |

---

## Quick start

```bash
# 1. Install (any KernelSU build, no susfs patch needed)
ksud module install VeilTEE-v1.2.0.zip

# 2. Reboot
reboot

# 3. Health check
su -c /data/adb/veiltee/bin/veilctl verify
su -c /data/adb/veiltee/bin/veilctl keybox
```

Expected output:

```
┌─ VeilTEE health check ─────────────────────────
│ [✓] ro.boot.flash.locked                   1
│ [✓] ro.boot.verifiedbootstate              green
│ [✓] ro.boot.vbmeta.device_state            locked
│ [✓] sys.oem_unlock_allowed                 0
│ [✓] ro.boot.veritymode                     enforcing
│ [✓] attestation generated                  601 bytes
├────────────────────────────────────────────────
│ three-green: 3/3   KeyAttestation fully green
└────────────────────────────────────────────────
```

---

## Build

Requires the Android NDK (tested on r26):

```bash
cd src
make NDK=$HOME/Library/Android/sdk/ndk/android-ndk-r26d    # cross-compile
make host                                                   # host-side crypto self-test
```

`make host` runs:

```
[PASS] SHA-256("abc")
[PASS] SHA-256("")
[PASS] d=1 → Q==G
[PASS] ECDSA sign/verify x5
ALL PASS (0 failures)
```

---

## Layout

```
veiltee/
├── module.prop            KernelSU module metadata
├── customize.sh           installer (ABI selection)
├── post-fs-data.sh        property alignment + vbmeta digest dump + binary staging
├── service.sh             starts veilteed
├── uninstall.sh
├── sepolicy.rule
├── bin/{arm64-v8a,x86_64}/{libveil.so, libveil_app.so, veilteed, veilctl}
├── config/{veil.conf, keybox.xml}
└── src/
    ├── p256.c             256-bit bignum + P-256 + ECDSA
    ├── sha256.c           SHA-256
    ├── der.h              DER/TLV encoder
    ├── attest.c           KeyDescription + RootOfTrust + X.509 issuance
    ├── plthook.c          GOT rewriting
    ├── payload.c          Binder transaction interception
    ├── rewrite.c          Parcel certificate scanning + equal-length replacement
    ├── hardening.c        detection countermeasures (root/hook/debug)
    ├── fingerprint.c      device fingerprint consistency
    ├── injector.c         ptrace injection (memfd loader)
    ├── veilteed.c         main daemon
    ├── veilctl.c          diagnostics CLI
    ├── keybox_check.c     keybox chain validation
    └── selftest.c         host self-test
```

---

## Configuration

```ini
# config/veil.conf
enabled=1
device_locked=1        # green #1
boot_state=0           # green #2: 0=Verified
security_level=1       # 1=TEE
os_version=16
patch_level=2026-11-05
vb_key=                # empty → read /data/adb/veiltee/vb_key
vb_hash=               # empty → read /data/adb/veiltee/vb_hash
state_dir=/data/adb/veiltee
keybox=/data/adb/modules/veiltee/config/keybox.xml
```

---

## keybox

`config/keybox.xml` ships with a **self-signed test CA** so the full chain can be exercised locally. It produces a fully green `RootOfTrust`, but its root is not in Google's trust store.

Validate any keybox with:

```bash
veilctl keybox /sdcard/candidate.xml
```

The only criterion that matters: **the chain root subject is `Google Hardware Attestation Root`**.

| Source | Fields green | Passes strict chain validation |
|---|---|---|
| Self-signed (default) | ✅ | ❌ |
| AOSP test key | ✅ | ❌ |
| Vendor hardware keybox | ✅ | ✅ (until revoked) |

The checker verifies six things:

1. private key parses as EC P-256
2. every certificate in the chain parses
3. subject / issuer / validity windows per certificate
4. private key matches the leaf public key
5. each certificate is signed by the next one up (real P-256 verification)
6. root identity classification (`0` = Google root, `2` = self-signed)

---

## Detection coverage

`libveil_app.so` is injected into target apps and covers:

| Category | Detection point | Interception |
|---|---|---|
| Root paths | `su` / `magisk` / `ksu` / `superuser` files | `open/openat/stat/lstat/access/readlink` → `ENOENT` |
| Root execution | `Runtime.exec("su")` / `which su` | `execve` → `ENOENT` |
| Debugger | `Debug.isDebuggerConnected` / `PTRACE_TRACEME` | `ptrace` returns 0 |
| TracerPid | `/proc/self/status` | memfd copy with value zeroed |
| maps scanning | `magisk` / `frida` / `xposed` / `libveil` | memfd copy with matching lines dropped |
| Mount table | overlay / magisk entries | memfd copy |
| Process table | `/proc/net/tcp` frida ports 27042/27043 | memfd copy |
| Property probing | `getprop` on magisk/ksu keys | `__system_property_get` filter |
| Boot state | `ro.boot.*` | property layer override |
| Device fingerprint | Build / serial / MAC | property layer + `SIOCGIFHWADDR` |
| Attestation | `RootOfTrust` | keystore2 layer re-signing |

---

## How it works

1. **Injection** — `ptrace(ATTACH)` → remote `mmap` → write the library into a `memfd` → remote `dlopen`. The constructor runs at that instant, which is where the hook is installed. Setting `lr = 0` before `PTRACE_CONT` turns the function return into a `SIGSEGV`, which is how the remote call result is captured.

2. **Interception** — `dl_iterate_phdr` walks every loaded library, parses `PT_DYNAMIC`, matches `R_AARCH64_JUMP_SLOT` relocations by symbol name, and rewrites the GOT slot. A single 8-byte pointer changes; not a single bit of code is touched.

3. **Rewriting** — a Binder `Parcel` is treated as a raw byte stream. The attestation certificate is located by its ASN.1 OID (`1.3.6.1.4.1.11129.2.1.17`), the leaf public key and challenge are preserved, only the `RootOfTrust` extension is regenerated, and the result is swapped in at equal length (padding with an unassigned context tag).

4. **Signing** — P-256 with Jacobian coordinates and a 4-bit window (~70 ms per signature), plus SHA-256 and a hand-written X.509 encoder.

5. **Hiding** — process name disguise (`prctl` + `argv[0]` overwrite) → memfd loading (`maps` shows `/memfd:veil (deleted)`) → libc-level `/proc` sanitizing → GOT-only hooking. Everything happens in user space.

---

## Why no susfs

susfs addresses *kernel-visible* traces: it filters `/proc/mounts`, `/proc/self/maps` and `stat()` at the kernel level.

But for an app, **every detection ultimately goes through libc**:

```
File.exists()             → access()
File.length()             → stat()
new FileInputStream()     → open()
Runtime.exec("su")        → execve()
Debug.isDebuggerConnected → ptrace()
```

Hooking those libc functions in `libveil_app.so` therefore produces the same observable result from the app's point of view:

| Scenario | susfs | VeilTEE (no susfs) |
|---|---|---|
| App scans `/data/adb/modules` | kernel hide | `open` returns `ENOENT` |
| App reads `/proc/self/maps` | kernel filter | sanitized memfd copy |
| App reads `/proc/self/status` | kernel filter | `TracerPid` zeroed |
| App runs `which su` | kernel hide | `access/execve` returns `ENOENT` |
| **Root shell inspects directly** | needs susfs | visible — the only real gap |

The last row is the honest difference: a detector that already holds root can bypass libc and read raw state. In practice such detectors are rare, because holding root is already the strongest possible signal.

### The three hiding primitives (all user-space)

```c
// 1) Process name disguise → /proc/pid/cmdline reads "logd"
prctl(PR_SET_NAME, "logd", 0, 0, 0);
memset(argv[0], 0, strlen(argv[0]));
strcpy(argv[0], "logd");

// 2) memfd loading → the library never exists as a loadable file
memfd_create("veil") → write(so) → dlopen("/proc/self/fd/N")

// 3) Binaries staged under /data/adb/veiltee/bin, never executed from the module mount
```

---

## Boundaries

- `MEETS_STRONG_INTEGRITY` requires the device private key held inside the TEE; software layers cannot reach it. Outcome depends on whether the supplied keybox is valid.
- **The module modifies no partition.** It does not touch `boot`, `lk` or `vbmeta`.
- If the device previously had its boot chain patched (for example `lk` or `boot` modified for a fake relock), partition hashes will differ from the stock firmware. Detectors that compare partition hashes against stock images are outside the coverage of this module — they need genuinely unmodified partition contents, which is an independent chain from attestation.
- Sensor behaviour analysis and multi-instance (app-cloning) detection are not covered.

---

## Disclaimer

This project is intended for Android security research, attestation protocol analysis, and debugging devices you own. Confirm you have full control of the device before use, and accept all consequences of doing so.

---

## License

[MIT](LICENSE) © 2026 VeilTEE Contributors
