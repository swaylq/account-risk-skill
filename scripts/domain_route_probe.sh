#!/bin/bash
# Probe routing evidence for the Claude Code API domain.
#
# This cannot make the remote API server echo the source public IP. Instead it
# records the evidence available from the client side: DNS answers, local route,
# curl local/remote socket IPs, HTTP status, and Cloudflare colo via cf-ray when
# present. Use it to detect split-egress symptoms for specific API domains.

set -euo pipefail

domains=("$@")
if [ "${#domains[@]}" -eq 0 ]; then
  domains=(api.anthropic.com)
fi

for domain in "${domains[@]}"; do
  echo "== $domain =="
  ips=$(dig +short "$domain" A | sed '/[^0-9.]/d' | paste -sd ' ' -)
  echo "dns_a: ${ips:-none}"

  first_ip=$(printf '%s\n' "$ips" | awk '{print $1}')
  if [ -n "${first_ip:-}" ]; then
    route_line=$(route -n get "$first_ip" 2>/dev/null | awk '
      /gateway:/ {gw=$2}
      /interface:/ {iface=$2}
      END {
        if (gw || iface) printf "gateway=%s interface=%s", gw, iface;
      }
    ')
    echo "route: ${route_line:-unknown}"
  else
    echo "route: unknown"
  fi

  tmp_headers=$(mktemp)
  curl_line=$(
    curl -4 -sS -D "$tmp_headers" -o /dev/null \
      -w 'remote_ip=%{remote_ip} local_ip=%{local_ip} http_code=%{http_code}' \
      "https://${domain}/" 2>/dev/null || true
  )
  echo "curl: ${curl_line:-failed}"
  cf_ray=$(awk 'BEGIN{IGNORECASE=1} /^cf-ray:/ {sub(/\r$/,""); print $2; exit}' "$tmp_headers")
  server=$(awk 'BEGIN{IGNORECASE=1} /^server:/ {sub(/\r$/,""); print $2; exit}' "$tmp_headers")
  [ -n "${server:-}" ] && echo "server: $server"
  [ -n "${cf_ray:-}" ] && echo "cf_ray: $cf_ray"
  echo "note: remote_ip is the API target IP, not your public egress/source IP."
  rm -f "$tmp_headers"
  echo
done
