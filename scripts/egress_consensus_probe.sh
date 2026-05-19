#!/bin/bash
# Probe public egress IPs through multiple echo endpoints, then compare with
# Claude Code API route evidence. Useful when a router/TUN stack applies split
# routing by domain.

set -euo pipefail

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "== public egress samples =="

sample() {
  local name=$1
  local url=$2
  local parser=${3:-raw}
  local out=""

  if [ "$parser" = "json_ip" ]; then
    out=$(curl -4 -sS -m 6 "$url" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ip",""))' 2>/dev/null || true)
  else
    out=$(curl -4 -sS -m 6 "$url" 2>/dev/null | tr -d '\r\n ' || true)
  fi

  if [ -n "$out" ]; then
    printf '%-14s %s\n' "$name:" "$out"
    printf '%s\n' "$out" >> "$tmpdir/ips"
  else
    printf '%-14s %s\n' "$name:" "failed"
  fi
}

sample "ipify" "https://api.ipify.org"
sample "ipinfo" "https://ipinfo.io/ip"
sample "ifconfig" "https://ifconfig.co/ip"
sample "ipwhois" "https://ipwho.is/" "json_ip"

echo
if [ -s "$tmpdir/ips" ]; then
  unique_count=$(sort -u "$tmpdir/ips" | wc -l | tr -d ' ')
  echo "unique_egress_count: $unique_count"
  echo "unique_egress_ips:"
  sort -u "$tmpdir/ips" | sed 's/^/- /'
  if [ "$unique_count" -gt 1 ]; then
    echo "split_egress: true"
    echo "note: multiple public IPs were observed; endpoint/domain split routing is active or likely."
  else
    echo "split_egress: false"
  fi
else
  echo "unique_egress_count: 0"
  echo "split_egress: unknown"
fi

echo
echo "== claude api route evidence =="
"$(dirname "$0")/domain_route_probe.sh" api.anthropic.com
