#!/system/bin/sh
MODDIR=${0%/*}
VEIL_DIR=/data/adb/veiltee
BIN_DIR=$VEIL_DIR/bin
mkdir -p "$BIN_DIR"

# 1) 属性对齐（zygote 之前）
resetprop ro.boot.flash.locked 1
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.boot.veritymode enforcing
resetprop sys.oem_unlock_allowed 0

# 2) vbmeta digest → state
VB_DIGEST=$(resetprop ro.boot.vbmeta.digest 2>/dev/null)
VB_KEY=$(resetprop ro.boot.vbmeta.public_key_digest 2>/dev/null)
[ -n "$VB_DIGEST" ] && echo "$VB_DIGEST" > "$VEIL_DIR/vb_hash"
[ -n "$VB_KEY" ]    && echo "$VB_KEY"    > "$VEIL_DIR/vb_key"

# 3) 二进制落地到数据目录（不依赖模块目录挂载，也不依赖 susfs）
cp -f "$MODDIR"/bin/libveil.so     "$BIN_DIR/" 2>/dev/null
cp -f "$MODDIR"/bin/libveil_app.so "$BIN_DIR/" 2>/dev/null
cp -f "$MODDIR"/bin/veilteed       "$BIN_DIR/" 2>/dev/null
cp -f "$MODDIR"/bin/veilctl        "$BIN_DIR/" 2>/dev/null
chmod 0700 "$BIN_DIR"/* 2>/dev/null

# 4) 清理可能被扫到的临时文件
rm -rf /data/local/tmp/veil 2>/dev/null
