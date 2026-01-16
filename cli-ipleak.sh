#!/usr/bin/env bash
# cli-ipleak — IP/DNS leak and routing diagnostic
# Overview:
#   A single-file Bash tool to quickly assess IP/DNS leaks and basic routing.
#   It prints your public IPv4/IPv6 addresses, key routing info, DNS
#   configuration and behavior, a short optional DNS capture, and a hop-by-hop
#   trace to a well-known anycast IP. Where possible it also fetches background
#   info (ASN/ISP/geo) for your public IPs to help interpret results.
# Usage:
#   cli-ipleak.sh [--no-capture] [--no-sudo] [--capture-seconds N]
#                 [--no-geo] [--explain] [-h|--help]
# Key ideas:
#   - Best-effort: missing tools or blocked networks won’t abort the run.
#   - Fast: short timeouts and fallback endpoints keep it snappy.
#   - Transparent: optional explainers describe what/why for each section.
# Dependencies:
#   Required: bash, curl, ip (iproute2)
#   Optional: dig/nslookup, resolvectl/systemd-resolve, tcpdump, mtr/traceroute,
#             ss (iproute2), jq
# Notes:
#   - Some networks block DNS over TCP/53 or drop “whoami/myip” query names.
#     The script includes UDP and HTTPS fallbacks to still surface your egress IP.

set -euo pipefail

# Strict mode:
#   -e: exit on unhandled error
#   -u: error on unset variables
#   -o pipefail: propagate failures in pipelines

# Runtime flags (see --help):
#   NO_SUDO:     avoid sudo for packet capture
#   DO_CAPTURE:  run a short tcpdump DNS capture
#   CAPTURE_SECONDS: capture duration in seconds
#   DO_GEO:      query background info (ASN/ISP/geo) for public IPs
#   EXPLAIN:     print one–two line explainer per section
NO_SUDO=0
DO_CAPTURE=1
CAPTURE_SECONDS=5
DO_GEO=1
EXPLAIN=0
PROG="${0##*/}"
VERSION="0.1.0"

die() { echo "${PROG}: $*" >&2; exit 2; }

# Lightweight flag parsing (no external getopts dependencies).
while [[ ${1:-} ]]; do
  case "$1" in
    --no-sudo) NO_SUDO=1 ;;
    --no-capture) DO_CAPTURE=0 ;;
    --capture-seconds)
      [[ -n ${2:-} ]] || die "--capture-seconds requires a value"
      [[ ${2} =~ ^[0-9]+$ ]] || die "--capture-seconds must be a positive integer"
      CAPTURE_SECONDS=$2
      shift
      ;;
    --no-geo) DO_GEO=0 ;;
    -h|--help)
      cat <<EOF
Usage: $PROG [OPTIONS]

IP/DNS leak and routing diagnostic. Shows public IPv4/IPv6, routing,
DNS configuration, resolver behavior, brief DNS capture, and path traces.

Options:
  --explain              Print short explainer text under each section.
  --no-capture           Skip tcpdump DNS capture.
  --no-sudo              Do not use sudo for tcpdump capture.
  --capture-seconds N    Set DNS capture duration (default: 5).
  --no-geo               Skip ASN/ISP/geo lookups for public IPs.
  -V, --version          Show version and exit.
  -h, --help             Show this help and exit.

Notes:
  - Optional tools: dig, tcpdump, mtr/traceroute, resolvectl, ss, jq.
  - Many checks are best-effort and won’t abort the script if they fail.

Examples:
  $PROG --explain
  $PROG --no-capture --no-geo
  $PROG --capture-seconds 10 --no-sudo
EOF
      exit 0
      ;;
    -V|--version)
      echo "$PROG $VERSION"; exit 0 ;;
    --explain) EXPLAIN=1 ;;
    *) echo "${PROG}: unknown option: $1" >&2; echo "Try '$PROG --help'" >&2; exit 2 ;;
  esac
  shift || true
done

# have CMD → return 0 if command exists
have() { command -v "$1" >/dev/null 2>&1; }

# ex "line1" "line2" → prints when --explain is set
ex() {
  # Print one or more lines only when --explain is set
  if (( EXPLAIN )); then
    for line in "$@"; do
      echo "$line"
    done
  fi
}

curl_try_ip() {
  # Fetch public IP using multiple providers with short timeouts.
  # Params:
  #   $1 = 4|6 → address family; selects curl -4/-6
  # Behavior:
  #   Iterates over a small set of HTTPS endpoints and returns on first success.
  #   Designed to be quick and resilient; errors are swallowed.
  local fam="$1"
  local flag="-${fam}"
  have curl || return 1
  local -a endpoints=(
    "https://ifconfig.co"
    "https://api.ipify.org"
    "https://ipinfo.io/ip"
    "https://icanhazip.com"
  )
  for url in "${endpoints[@]}"; do
    if out=$(curl -fsS $flag --max-time 5 --connect-timeout 3 "$url" 2>/dev/null | tr -d '\r' | head -n1); then
      [[ -n "$out" ]] && echo "$out" && return 0
    fi
  done
  return 1
}

# Run a dig query with UDP, then TCP fallback. Prints first short answer.
# Usage: dig_first_answer SERVER NAME TYPE [FAM]
#  SERVER: resolver address or empty for system default
#  FAM:    4 or 6 to force address family (optional)
dig_first_answer() {
  # Resolve a name and print the first "short" answer.
  # Params:
  #   $1 server  → resolver address (empty = system default)
  #   $2 name    → query name
  #   $3 qtype   → record type (A, AAAA, TXT, ...)
  #   $4 fam     → optional 4|6 to force AF for contacting the resolver
  # Behavior:
  #   Tries UDP first, then falls back to TCP. Returns non-zero on no answer.
  local server="$1" name="$2" qtype="$3" fam="${4:-}"
  local famflag=""; [[ "$fam" == "4" ]] && famflag="-4"; [[ "$fam" == "6" ]] && famflag="-6"
  local base_opts="+short +timeout=3 +tries=1"
  local out=""
  if [[ -n "$server" ]]; then
    out=$(dig $famflag @"$server" "$name" "$qtype" $base_opts 2>/dev/null | sed 's/\r//') || true
    if [[ -z "$out" ]]; then
      out=$(dig +tcp $famflag @"$server" "$name" "$qtype" $base_opts 2>/dev/null | sed 's/\r//') || true
    fi
  else
    out=$(dig $famflag "$name" "$qtype" $base_opts 2>/dev/null | sed 's/\r//') || true
    if [[ -z "$out" ]]; then
      out=$(dig +tcp $famflag "$name" "$qtype" $base_opts 2>/dev/null | sed 's/\r//') || true
    fi
  fi
  if [[ -n "$out" ]]; then
    echo "$out" | head -n1
    return 0
  fi
  return 1
}

reverse_dns() {
  # Reverse DNS (PTR) lookup with graceful fallbacks.
  # Params:
  #   $1 = ip (v4 or v6)
  # Tools tried in order: dig → host → nslookup → getent
  local ip="$1"
  if have dig; then
    dig +timeout=2 +tries=1 -x "$ip" +short 2>/dev/null | sed 's/\.$//' | head -n1
  elif have host; then
    host "$ip" 2>/dev/null | awk '/pointer/ {print $5}' | sed 's/\.$//' | head -n1
  elif have nslookup; then
    nslookup "$ip" 2>/dev/null | awk -F'name = ' '/name = /{print $2}' | sed 's/\.$//' | head -n1
  elif have getent; then
    getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -n1
  else
    return 1
  fi
}

print_geo_info() {
  # Query public APIs for background info (ASN/ISP/geo) for an IP.
  # Params:
  #   $1 = ip
  # Sources:
  #   - ipinfo.io (JSON)
  #   - ip-api.com (JSON)
  # Notes:
  #   Network timeouts are short; output is filtered if jq is present.
  local ip="$1"
  [[ $DO_GEO -eq 1 ]] || { echo "(geo lookups disabled)"; return 0; }
  if have curl; then
    echo "-- ipinfo.io --"
    if have jq; then
      curl -fsS --max-time 5 --connect-timeout 3 "https://ipinfo.io/${ip}/json" \
        | jq -r '[
            {k:"ip",v:.ip},
            {k:"hostname",v:.hostname},
            {k:"org",v:.org},
            {k:"city",v:.city},
            {k:"region",v:.region},
            {k:"country",v:.country},
            {k:"loc",v:.loc},
            {k:"timezone",v:.timezone},
            {k:"anycast",v:.anycast}
          ] | .[] | select(.v!=null) | "\(.k): \(.v)"' || echo "(ipinfo.io query failed)"
    else
      curl -fsS --max-time 5 --connect-timeout 3 "https://ipinfo.io/${ip}/json" || echo "(ipinfo.io query failed)"
    fi
    echo
    echo "-- ip-api.com --"
    if have jq; then
      curl -fsS --max-time 5 --connect-timeout 3 \
        "https://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting,mobile,query" \
        | jq -r 'if .status=="success" then [
            {k:"as",v:.as},
            {k:"asname",v:.asname},
            {k:"isp",v:.isp},
            {k:"org",v:.org},
            {k:"country",v:.country},
            {k:"region",v:.regionName},
            {k:"city",v:.city},
            {k:"zip",v:.zip},
            {k:"lat",v:(.lat|tostring)},
            {k:"lon",v:(.lon|tostring)},
            {k:"timezone",v:.timezone},
            {k:"reverse",v:.reverse},
            {k:"proxy",v:(.proxy|tostring)},
            {k:"hosting",v:(.hosting|tostring)},
            {k:"mobile",v:(.mobile|tostring)}
          ] | .[] | select(.v!="" and .v!="null") | "\(.k): \(.v)" else .message end' \
        || echo "(ip-api.com query failed)"
    else
      curl -fsS --max-time 5 --connect-timeout 3 \
        "https://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,proxy,hosting,mobile,query" \
        || echo "(ip-api.com query failed)"
    fi
  else
    echo "curl not available; skipping geo/ASN lookups"
  fi
}

## Section: Public IP (IPv4)
echo "=== Public IP (IPv4) ==="
ex \
  "Queries multiple services to reveal your public IPv4 address." \
  "Confirms whether traffic exits via your VPN or ISP."
if ip4=$(curl_try_ip 4); then
  echo "$ip4"
  rev4=$(reverse_dns "$ip4" || true)
  if [[ -n "$rev4" ]]; then
    echo "Reverse DNS: $rev4"
  else
    echo "Reverse DNS: (none or lookup failed)"
  fi
  echo
  echo "IPv4 background info"
  print_geo_info "$ip4"
else
  echo "Unable to determine IPv4 public IP (no network or curl)"
fi

echo
## Section: Public IP (IPv6)
echo "=== Public IP (IPv6) ==="
ex \
  "Attempts to detect your public IPv6 address." \
  "If your VPN lacks IPv6 support, it should be disabled to avoid leaks."
if ip6=$(curl_try_ip 6); then
  echo "$ip6"
  rev6=$(reverse_dns "$ip6" || true)
  if [[ -n "$rev6" ]]; then
    echo "Reverse DNS: $rev6"
  else
    echo "Reverse DNS: (none or lookup failed)"
  fi
  echo
  echo "IPv6 background info"
  print_geo_info "$ip6"
else
  echo "No IPv6 or IPv6 request failed"
fi

echo
## Section: Default routes
echo "=== Default routes (kernel) ==="
ex \
  "Shows the system's default IPv4/IPv6 gateways." \
  "Useful to verify that your VPN installs and owns the default route."
ip -4 route show default || true
ip -6 route show default || true

echo
## Section: Route to 8.8.8.8
echo "=== Kernel route -> 8.8.8.8 (source IP used) ==="
ex \
  "Asks the kernel which interface and source IP would be used to reach 8.8.8.8." \
  "Reveals the actual egress path your stack will take."
ip route get 8.8.8.8 || true

echo
## Section: Interface addresses
echo "=== Interface addresses (global scope) ==="
ex \
  "Lists globally scoped addresses on local interfaces." \
  "Unexpected global addresses may indicate potential leak paths."
ip -o -4 addr show scope global 2>/dev/null | awk '{print $2,$4}' || true
ip -o -6 addr show scope global 2>/dev/null | awk '{print $2,$4}' || true

echo
## Section: DNS configuration
echo "=== DNS config (resolvectl and /etc/resolv.conf) ==="
ex \
  "Displays configured resolvers and resolver status." \
  "Misconfiguration can cause DNS queries to bypass your tunnel."
if have resolvectl; then
  resolvectl status 2>/dev/null || true
elif have systemd-resolve; then
  systemd-resolve --status 2>/dev/null || true
fi
echo "---- /etc/resolv.conf ----"
cat /etc/resolv.conf 2>/dev/null || true
echo "---- parsed nameservers ----"
grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' || true

echo
## Section: DNS probes
echo "=== DNS probe (Google / Cloudflare / System default) ==="
ex \
  "Resolves a test name via public and system resolvers." \
  "Compares answers and shows how resolvers see your client IP."
if have dig; then
  echo "Google (8.8.8.8):"
  if ! dig_first_answer 8.8.8.8 example.com A; then echo "(no answer or blocked)"; fi
  echo "Cloudflare (1.1.1.1):"
  if ! dig_first_answer 1.1.1.1 example.com A; then echo "(no answer or blocked)"; fi
  echo "System resolver:"
  if ! dig_first_answer "" example.com A; then echo "(no answer or blocked)"; fi
  echo
  echo "Resolver-provided client IP checks (some networks filter these):"
  ex \
    "Shows the IP address as seen by various resolvers." \
    "Uses UDP and HTTPS methods to avoid DNS/53 filtering."
  echo "Google myaddr (UDP):"
  {
    dig +short +timeout=2 +tries=1 @ns1.google.com o-o.myaddr.l.google.com TXT 2>/dev/null | tr -d '"' | head -n1 || true
  } | awk 'NF{print; f=1} END{if(!f) print "(no answer or blocked)"}'
  if have curl; then
    echo "Google myaddr via HTTPS (DoH):"
    if have jq; then
      curl -fsS --max-time 5 --connect-timeout 3 'https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT' -H 'accept: application/dns-json' \
        | jq -r '.Answer[0].data // empty' | tr -d '"' | awk 'NF{print; f=1} END{if(!f) print "(no answer or blocked)"}'
    else
      curl -fsS --max-time 5 --connect-timeout 3 'https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT' -H 'accept: application/dns-json' 2>/dev/null \
        | sed -n 's/.*"data":"\([^"]*\)".*/\1/p' | head -n1 | awk 'NF{print; f=1} END{if(!f) print "(no answer or blocked)"}'
    fi
    echo "Cloudflare trace via HTTPS:"
    curl -fsS --max-time 5 --connect-timeout 3 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}' | awk 'NF{print; f=1} END{if(!f) print "(no answer or blocked)"}'
  fi
  echo "Cloudflare whoami (may be filtered):"
  if ! dig_first_answer 1.1.1.1 whoami.cloudflare TXT 4; then
    if ! dig_first_answer 1.0.0.1 whoami.cloudflare TXT 4; then
      if ! dig_first_answer 2606:4700:4700::1111 whoami.cloudflare TXT 6; then
        if ! dig_first_answer 2606:4700:4700::1001 whoami.cloudflare TXT 6; then
          echo "(no answer or blocked)"
        fi
      fi
    fi
  fi
  echo "OpenDNS (IPv4, may be filtered):"
  if ! dig_first_answer 208.67.222.222 myip.opendns.com A 4; then
    if ! dig_first_answer 208.67.220.220 myip.opendns.com A 4; then
      if ! dig_first_answer resolver1.opendns.com myip.opendns.com A 4; then
        echo "(no answer or blocked)"
      fi
    fi
  fi
else
  echo "dig not found. Install 'dig' (bind9-dnsutils) for detailed DNS tests."
  if have nslookup; then
    echo "Fallback via nslookup (system resolver):"
    nslookup -querytype=A example.com 2>/dev/null | awk '/^Address: /{print $2}' || true
  fi
fi

echo
## Section: Local DNS listeners
echo "=== DNS listeners (local port 53) ==="
ex \
  "Checks for local processes bound to port 53." \
  "Local forwarders or containers may override your resolver."
if have ss; then
  ss -tupln 2>/dev/null | awk '$5 ~ /:53$/ {print}' || true
fi

echo
## Section: Short DNS capture
echo "=== Short DNS capture ("${CAPTURE_SECONDS}"s) - shows destination IPs for DNS queries ==="
ex \
  "Briefly captures outbound DNS (port 53) to see where queries go." \
  "Helps detect cleartext DNS leaks or unexpected resolvers."
if (( DO_CAPTURE )); then
  if have tcpdump; then
    if ! have timeout; then
      echo "timeout not installed; skipping DNS capture"
    elif (( NO_SUDO )); then
      echo "Skipping sudo; attempting capture without elevated privileges..."
      timeout "${CAPTURE_SECONDS}" tcpdump -n -i any port 53 2>/dev/null | awk '{print $1,$2,$3,$4,$5,$6}' || true
    elif have sudo; then
      echo "Running tcpdump for ${CAPTURE_SECONDS}s... (may prompt for sudo)"
      sudo timeout "${CAPTURE_SECONDS}" tcpdump -n -i any port 53 2>/dev/null | awk '{print $1,$2,$3,$4,$5,$6}' || true
    else
      echo "sudo not available; attempting capture without elevated privileges..."
      timeout "${CAPTURE_SECONDS}" tcpdump -n -i any port 53 2>/dev/null | awk '{print $1,$2,$3,$4,$5,$6}' || true
    fi
  else
    echo "tcpdump not installed (install tcpdump for packet capture)"
  fi
else
  echo "Capture disabled via --no-capture"
fi

echo
## Section: Traceroute/MTR
echo "=== Traceroute to 1.1.1.1 (shows hops) ==="
ex \
  "Maps hop-by-hop path to Cloudflare's anycast IP." \
  "Early hops reveal whether traffic goes through the VPN or ISP."
if have mtr; then
  mtr --report --report-cycles 3 1.1.1.1 || true
elif have traceroute; then
  traceroute 1.1.1.1 || true
else
  echo "mtr/traceroute not installed"
fi

echo
echo "=== Done ==="
