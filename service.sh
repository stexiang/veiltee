#!/system/bin/sh
MODDIR=${0%/*}
BIN="$MODDIR/bin"

for i in $(seq 1 60); do
  pid=$(pidof keystore2 2>/dev/null)
  [ -n "$pid" ] && break
  sleep 0.5
done
[ -z "$pid" ] && exit 0

"$BIN/veilteed" \
  --so "$BIN/libveil.so" \
  --target keystore2 \
  --watch-all \
  --interval 3 >/dev/null 2>&1 &
