cli-ipleak
===========

A simple, self-contained CLI script to sanity-check for IP/DNS leaks and routing issues. It reports your public IPv4/IPv6, default routes, the kernel-selected egress IP, DNS configuration and resolution behavior, brief DNS capture targets, and basic path traces. It also provides optional background info (ASN/ISP/geo) for your public IPs.

Features
--------
- Public IP detection (IPv4/IPv6) via multiple providers with timeouts
- Reverse DNS for detected public IPs
- Optional background info from ipinfo.io and ip-api.com
- Routing context: default routes, interface global addresses, route to 8.8.8.8
- DNS configuration: systemd-resolved status and `/etc/resolv.conf` parsing
- DNS probes: Google, Cloudflare, and system resolver comparisons
- Resolver “client IP” checks with resilient paths (Google myaddr, DoH, HTTPS trace)
- Optional short DNS capture (tcpdump) to see port 53 egress
- Traceroute/MTR to 1.1.1.1 to visualize hops
- Explain mode to show what/why under each section
- Helpful `--help` with usage, options, notes, and examples

Usage
-----
Run the script:

- Basic: `bash cli-ipleak.sh`
- With explainers: `bash cli-ipleak.sh --explain`

Options:
- `--explain` — Print short explainer text under each section
- `--no-capture` — Skip tcpdump DNS capture
- `--no-sudo` — Do not use sudo for tcpdump capture
- `--capture-seconds N` — DNS capture duration (default: 5)
- `--no-geo` — Skip ASN/ISP/geo lookups for public IPs
- `-h`, `--help` — Show help and exit

Examples:
- `bash cli-ipleak.sh --explain`
- `bash cli-ipleak.sh --no-capture --no-geo`
- `bash cli-ipleak.sh --capture-seconds 10 --no-sudo`

What to look for
----------------
- Public IPv4/IPv6 should match your VPN egress or intended exit. If your VPN does not support IPv6, IPv6 should be disabled or tunneled to avoid leaks.
- `ip route get 8.8.8.8` should show a VPN interface/source when the VPN is active.
- DNS: System resolver and the capture (when enabled) should indicate your intended resolvers (VPN DNS, DoT/DoH endpoints, etc.), not your ISP.
- Traceroute first hops should reflect the VPN path, not your ISP gateway.

Dependencies
------------
Required:
- `bash`
- `curl`
- `ip` (from iproute2)

Optional (enables richer output and/or fallbacks):
- `dig` (bind9-dnsutils) or `nslookup`
- `resolvectl` (systemd-resolved) or `systemd-resolve`
- `tcpdump` (for the short DNS capture; may require sudo)
- `mtr` (preferred) or `traceroute`
- `ss` (from iproute2) for local DNS listeners
- `jq` (pretty JSON extraction for background lookups and DoH)

Permissions
-----------
- The DNS capture uses `tcpdump` and may prompt for sudo. Use `--no-sudo` to avoid elevation or `--no-capture` to skip entirely.

Notes on filtered networks
--------------------------
- Some networks/VPNs block TCP/53 and/or drop “whoami/myip” DNS queries via DPI. The script includes resilient checks (Google myaddr over UDP/DoH and Cloudflare HTTPS trace) so you still get signal even when DNS/53 is filtered.

License
-------
MIT — see `LICENSE`.
