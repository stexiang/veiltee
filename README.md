<p align="center">
  <img src="https://img.shields.io/badge/Android-12%2B-3ddc84?style=flat-square&logo=android&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" />
</p>

<h1 align="center">VeilTEE</h1>

<p align="center">A KernelSU module that rewrites Android key attestation.</p>

---

## What it does

```
keystore2  ──►  [intercept at ioctl]  ──►  re-sign leaf  ──►  app
```

The module injects into `keystore2`, intercepts `generateKey` transactions at the Binder layer, and returns a certificate whose `RootOfTrust` reports a locked, verified bootloader. The attestation public key and challenge are preserved, so the app's own signature check still passes.

Nothing is injected into the app process.

---

## Install

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

Requires KernelSU and Android 12+. `arm64-v8a` and `x86_64` are both included.

---

## keybox

`config/keybox.xml` ships with a self-signed test CA. It produces a fully green `RootOfTrust`, but its root is not in Google's trust store, so strict chain validation fails.

Validate any keybox before replacing it:

```bash
veilctl keybox /sdcard/candidate.xml
```

Returns `0` when the chain root is `Google Hardware Attestation Root`, `2` otherwise. The check covers: private key format, certificate parsing, validity windows, key/public-key match, per-link signature verification, and root identity.

---

## Configuration

```ini
# /data/adb/modules/veiltee/config/veil.conf
enabled=1
device_locked=1        # RootOfTrust.deviceLocked
boot_state=0           # 0=Verified
security_level=1       # 1=TEE
os_version=16
patch_level=2026-11-05
vb_key=                # empty → /data/adb/veiltee/vb_key
vb_hash=               # empty → /data/adb/veiltee/vb_hash
keybox=/data/adb/modules/veiltee/config/keybox.xml
```

`vb_key` and `vb_hash` default to the device's real vbmeta digests, dumped by `post-fs-data.sh`. That keeps the certificate consistent with system properties.

---

## Build

```bash
cd src
make NDK=$ANDROID_NDK_HOME     # cross-compile both ABIs
make host                      # host-side crypto self-test
```

`make host` verifies SHA-256 vectors, P-256 point arithmetic, and ECDSA sign/verify round-trips. No third-party crypto library is linked; P-256, SHA-256, DER and X.509 are implemented in `src/`.

---

## How it works

**Injection** — `ptrace` attach, remote `mmap`, load the library from a `memfd`, remote `dlopen`. Setting `lr = 0` turns the function return into a `SIGSEGV`, which is how the call result is captured.

**Interception** — `dl_iterate_phdr` walks loaded libraries, matches `R_AARCH64_JUMP_SLOT` relocations by symbol name, rewrites the GOT slot for `ioctl`. Code segments are untouched.

**Rewriting** — the Binder `Parcel` is scanned for the attestation OID `1.3.6.1.4.1.11129.2.1.17`. The leaf is re-signed with the keybox private key and replaced at equal length, padded with an unassigned context tag.

**Hiding** — process name disguise, `memfd` loading, and libc-level sanitizing of `/proc/self/{status,maps,mountinfo}`.

---

## Boundaries

- `MEETS_STRONG_INTEGRITY` requires a device key held inside the TEE. Outcome depends on keybox validity.
- The module modifies no partition. `boot`, `lk` and `vbmeta` are untouched.
- Sensor behaviour analysis and app-cloning detection are out of scope.

---

## Disclaimer

Intended for attestation protocol research and debugging devices you own.

## License

[MIT](LICENSE)
