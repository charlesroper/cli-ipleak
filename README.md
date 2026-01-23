# cli-ipleak

A simple, self-contained CLI script to check for IP/DNS leaks and routing issues. Use this to verify that your VPN or proxy is working correctly and that your system isn't leaking identifying information to your ISP.

## Features

- **IP Detection:** Reports public IPv4 and IPv6 addresses with reverse DNS and optional geo-location data.
- **Routing Checks:** Verifies default routes and the kernel-selected egress path for traffic to common targets (e.g., `8.8.8.8`).
- **DNS Diagnostics:** Parses `/etc/resolv.conf`, checks `systemd-resolved` status, and compares resolution behavior across multiple providers.
- **Leak Detection:** Uses Google "myaddr" (UDP/DoH) and Cloudflare HTTPS traces to identify the "client IP" seen by DNS resolvers.
- **Traffic Visualization:** Includes a short DNS packet capture and path traces via `mtr` or `traceroute`.

## Prerequisites

### Required
- `bash`
- `curl`
- `ip` (from `iproute2`)

### Optional (Recommended for full output)
- `dig` or `nslookup` (DNS lookups)
- `tcpdump` (DNS packet capture; requires sudo)
- `mtr` or `traceroute` (Path tracing)
- `jq` (JSON parsing for geo-location data)

## Usage

Run the script directly with bash:

```bash
bash cli-ipleak.sh
```

### Common Options

- `--explain`: Adds a brief explanation under each section to help you interpret the results.
- `--no-capture`: Skips the `tcpdump` DNS capture (useful if you don't have sudo access).
- `--no-geo`: Skips ASN, ISP, and geographic lookups for your public IPs.
- `--capture-seconds N`: Sets the DNS capture duration (default is 5 seconds).

### Examples

**Run with explanations:**
```bash
bash cli-ipleak.sh --explain
```

**Run without sudo requirements or geo lookups:**
```bash
bash cli-ipleak.sh --no-capture --no-geo
```

## What to Check

When running this tool, look for the following signs of a leak:

1. **Public IP:** Your IPv4 and IPv6 addresses should match your VPN's exit node. If your VPN doesn't support IPv6, ensure it is disabled or tunneled; otherwise, your real IPv6 address may leak.
2. **Routes:** `ip route get 8.8.8.8` should show your VPN interface as the gateway.
3. **DNS Resolvers:** The "System Resolver" and "Client IP" sections should show your intended DNS providers (e.g., VPN DNS, Cloudflare, Google), not your ISP's servers.
4. **Traceroute:** The first few hops should reflect your VPN path, not your local ISP gateway.

## Permissions

The DNS capture feature uses `tcpdump` and typically requires `sudo`. If you want to avoid a password prompt, use the `--no-capture` or `--no-sudo` flags.

## License

MIT — See `LICENSE` for details.
