#!/system/bin/sh
SKIPUNZIP=1

ui_print "- VeilTEE 安装中"

ABI=$(getprop ro.product.cpu.abi)
case "$ABI" in
  arm64*)  ARCH_DIR="arm64-v8a" ;;
  x86_64*) ARCH_DIR="x86_64" ;;
  *) ui_print "! 未知 ABI: $ABI"; abort "  仅支持 arm64-v8a / x86_64" ;;
esac
ui_print "- 目标架构: $ARCH_DIR"

unzip -o "$ZIPFILE" 'config/*' 'sepolicy.rule' 'skip_mount' -d "$MODPATH" >/dev/null 2>&1
for d in "$MODPATH"/bin/*; do
  [ "$(basename "$d")" = "$ARCH_DIR" ] || rm -rf "$d"
done
mv "$MODPATH/bin/$ARCH_DIR"/* "$MODPATH/bin/" 2>/dev/null
rmdir "$MODPATH/bin/$ARCH_DIR" 2>/dev/null

set_perm_recursive "$MODPATH" 0 0 0755 0644
chmod 0755 "$MODPATH/bin/veilteed" "$MODPATH/bin/veilctl"
chmod 0644 "$MODPATH/bin/libveil.so"
chmod 0600 "$MODPATH/config/keybox.xml"
chmod 0755 "$MODPATH"/post-fs-data.sh "$MODPATH"/service.sh "$MODPATH"/uninstall.sh

mkdir -p /data/adb/veiltee
chmod 0700 /data/adb/veiltee

ui_print "- 安装完成，重启生效"
ui_print "- 体检: su -c $MODPATH/bin/veilctl verify"
