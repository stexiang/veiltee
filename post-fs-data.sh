#!/system/bin/sh
MODDIR=${0%/*}
VEIL_DIR=/data/adb/veiltee
mkdir -p "$VEIL_DIR"

# 1) 属性对齐（zygote 之前）
resetprop ro.boot.flash.locked 1
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.boot.veritymode enforcing
resetprop sys.oem_unlock_allowed 0

# 2) vbmeta digest → state（daemon 生成 verifiedBootHash / verifiedBootKey 用）
VB_DIGEST=$(resetprop ro.boot.vbmeta.digest 2>/dev/null)
VB_KEY=$(resetprop ro.boot.vbmeta.public_key_digest 2>/dev/null)
[ -n "$VB_DIGEST" ] && echo "$VB_DIGEST" > "$VEIL_DIR/vb_hash"
[ -n "$VB_KEY" ]    && echo "$VB_KEY"    > "$VEIL_DIR/vb_key"

# 3) 隐藏（susfs 优先）
if command -v ksud >/dev/null 2>&1 && ksud susfs version >/dev/null 2>&1; then
  ksud susfs add-sus-path "$MODDIR"
  ksud susfs add-sus-path "$VEIL_DIR"
  ksud susfs add-sus-path /data/local/tmp/veil
  ksud susfs add-sus-process veilteed
  echo susfs > "$VEIL_DIR/hide_mode"
else
  umount "$MODDIR" 2>/dev/null
  echo umount > "$VEIL_DIR/hide_mode"
fi

rm -rf /data/local/tmp/veil 2>/dev/null
