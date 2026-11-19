#!/system/bin/sh
BIN=/data/adb/veiltee/bin

for i in $(seq 1 60); do
  pid=$(pidof keystore2 2>/dev/null)
  [ -n "$pid" ] && break
  sleep 0.5
done
[ -z "$pid" ] && exit 0

# 内存加载：--memfd 让 injector 把 so 读进 memfd 再 dlopen
"$BIN/veilteed" \
  --so "$BIN/libveil.so" \
  --harden "$BIN/libveil_app.so" \
  --target keystore2 \
  --watch-all \
  --memfd \
  --interval 3 >/dev/null 2>&1 &
