#!/bin/sh
# cg-agent: executes ONLY `nginx -t` and `nginx -s reload`, triggered by files in a shared dir.
# It never executes content from those files. Anyone who can write to the volume can request a reload,
# so the volume must be writable only by the controller.
D=/etc/cyberguard/agent
L=/etc/cyberguard/logs
mkdir -p "$D" "$L"; chmod 755 "$L"
SRC_AUDIT="${CG_AUDIT_SRC:-/var/log/modsec_audit.log}"
SRC_ACCESS=/var/log/nginx/cyberguard.jsonl

# ship SRC DST: append new complete bytes of SRC to DST (offset kept next to DST); cap DST at ~50MB.
ship() {
  src=$1; dst=$2; off="$dst.off"
  [ -f "$src" ] || return 0
  size=$(( $(wc -c < "$src") )); cur=$(( $(cat "$off" 2>/dev/null || echo 0) ))
  [ "$size" -lt "$cur" ] && cur=0
  if [ "$size" -gt "$cur" ]; then
    tail -c +$((cur+1)) "$src" | head -c $((size-cur)) >> "$dst" && echo "$size" > "$off"
  fi
  [ -f "$dst" ] && chmod 644 "$dst"
  if [ -f "$dst" ] && [ "$(( $(wc -c < "$dst") ))" -gt 52428800 ]; then mv -f "$dst" "$dst.1"; fi
}

while true; do
  ship "$SRC_ACCESS" "$L/access.jsonl"
  ship "$SRC_AUDIT" "$L/audit.jsonl"
  for f in "$D"/*.validate "$D"/*.reload; do
    [ -e "$f" ] || continue
    id="${f%.*}"; action="${f##*.}"
    case "$action" in
      validate) out=$(nginx -t 2>&1); rc=$? ;;
      reload)   out=$(nginx -t 2>&1 && nginx -s reload 2>&1); rc=$? ;;
    esac
    rm -f "$f"
    { [ "$rc" = 0 ] && echo OK || echo FAIL; echo "$out"; } > "$id.result.tmp"
    mv "$id.result.tmp" "$id.result"
  done
  sleep 0.3
done
