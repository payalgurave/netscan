#!/usr/bin/env python3
"""
netscan - a small ping-sweep network scanner.

Features
  * Auto-detects your local subnet (uses psutil if installed, otherwise /24)
  * Parallel ping sweep with configurable threads and timeout
  * Reverse-DNS hostname lookup and per-host response time
  * Table output on screen, optional JSON or CSV export

Examples
  python netscan.py                       # scan the local network
  python netscan.py 192.168.1             # scan 192.168.1.0/24
  python netscan.py 10.0.0.0/22 -t 2 -w 200
  python netscan.py -o results.json       # save as JSON
  python netscan.py -o results.csv        # save as CSV
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import math
import platform
import re
import socket
import subprocess
import sys
import time

OS = platform.system().lower()          # 'windows', 'linux', 'darwin'
MAX_HOSTS_DEFAULT = 65536               # refuse anything bigger than a /16 unless --force

BANNER = r"""
  _   _      _    _____
 | \ | |    | |  / ____|
 |  \| | ___| |_| (___   ___ __ _ _ __
 | . ` |/ _ \ __|\___ \ / __/ _` | '_ \
 | |\  |  __/ |_ ____) | (_| (_| | | | |
 |_| \_|\___|\__|_____/ \___\__,_|_| |_|
"""


def detect_local_network():
    """Return the local IPv4 network (e.g. 192.168.1.0/24)."""
    # Find the IP of the interface used for outbound traffic. No packets are
    # actually sent: connecting a UDP socket only selects a route.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        local_ip = probe.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"
    finally:
        probe.close()

    prefix = 24  # sensible default if we cannot read the real mask
    try:
        import psutil  # optional dependency: pip install psutil

        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{addr.netmask}").prefixlen
    except ImportError:
        pass

    return ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)


def parse_network(text):
    """Turn user input into an IPv4 network.

    Accepts: 192.168.1 | 192.168.1.0 | 192.168.1.0/24 | 10.0.0.5/22
    """
    if text is None:
        return detect_local_network()
    text = text.strip()
    if re.fullmatch(r"\d+\.\d+\.\d+", text):             # 192.168.1
        text += ".0/24"
    elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", text):      # 192.168.1.5
        text += "/24"
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid network '{text}': {exc}")


def build_ping_command(ip, timeout_ms):
    """Build the OS-specific single-ping command."""
    if OS == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    if OS == "darwin":                                   # macOS: -W is milliseconds
        return ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    return ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout_ms / 1000))), ip]  # Linux: seconds


def probe_host(ip, timeout_ms, resolve):
    """Ping one host. Returns a result dict if it replied, otherwise None."""
    ip = str(ip)
    cmd = build_ping_command(ip, timeout_ms)
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout_ms / 1000 + 2,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    elapsed_ms = (time.perf_counter() - started) * 1000

    out = proc.stdout or ""
    # Exit code 0 means a reply on Linux/macOS. Windows can return 0 for
    # "destination unreachable", so there we also require a TTL in the reply.
    replied = proc.returncode == 0 and (OS != "windows" or "ttl" in out.lower())
    if not replied:
        return None

    # Prefer the RTT reported by ping itself; fall back to our own timing.
    match = re.search(r"time[=<]\s*([\d.]+)", out, re.IGNORECASE)
    rtt = float(match.group(1)) if match else round(elapsed_ms, 1)

    hostname = ""
    if resolve:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = ""

    return {"ip": ip, "hostname": hostname, "rtt_ms": rtt}


def scan(network, threads, timeout_ms, resolve):
    """Sweep every host in the network and return replies (partial if Ctrl+C)."""
    hosts = list(network.hosts()) or [network.network_address]   # /32 has no .hosts()
    total = len(hosts)
    found, done = [], 0

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    futures = [executor.submit(probe_host, h, timeout_ms, resolve) for h in hosts]
    try:
        for future in concurrent.futures.as_completed(futures):
            done += 1
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                found.append(result)
            print(f"\rProgress: {done}/{total}  online: {len(found)}", end="", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted, showing results so far...", file=sys.stderr)
        executor.shutdown(wait=False, cancel_futures=True)
    else:
        executor.shutdown()
    print(file=sys.stderr)

    return sorted(found, key=lambda r: ipaddress.ip_address(r["ip"]))


def print_table(results):
    if not results:
        print("No hosts replied.")
        return
    name_w = max(8, *(len(r["hostname"]) for r in results))
    print(f"\n{'IP ADDRESS':<16} {'HOSTNAME':<{name_w}} RTT (ms)")
    print("-" * (16 + 1 + name_w + 1 + 8))
    for r in results:
        print(f"{r['ip']:<16} {r['hostname'] or '-':<{name_w}} {r['rtt_ms']}")
    print(f"\n{len(results)} host(s) online.")


def save_results(results, path):
    """Write results as JSON or CSV depending on the file extension."""
    if path.lower().endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["ip", "hostname", "rtt_ms"])
            writer.writeheader()
            writer.writerows(results)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    print(f"Saved results to {path}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="Scan a network for online devices using a parallel ping sweep.",
        epilog="Only scan networks you own or have permission to test.",
    )
    parser.add_argument(
        "network", nargs="?", type=parse_network, default=None,
        help="network to scan: 192.168.1 | 192.168.1.0/24 (default: auto-detect)",
    )
    parser.add_argument("-w", "--timeout", type=int, default=1000, metavar="MS",
                        help="per-host timeout in milliseconds (default: 1000)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="number of parallel workers (default: 100)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="save results to FILE (.json or .csv)")
    parser.add_argument("--no-resolve", action="store_true",
                        help="skip reverse-DNS hostname lookups (faster)")
    parser.add_argument("--force", action="store_true",
                        help=f"allow scanning more than {MAX_HOSTS_DEFAULT} addresses")
    parser.add_argument("--no-banner", action="store_true", help="hide the ASCII banner")
    return parser


def main():
    args = build_parser().parse_args()

    if args.threads < 1 or args.timeout < 1:
        sys.exit("Error: --threads and --timeout must be positive numbers.")

    network = args.network if args.network is not None else detect_local_network()
    if network.version != 4:
        sys.exit("Error: only IPv4 networks are supported.")
    if network.num_addresses > MAX_HOSTS_DEFAULT and not args.force:
        sys.exit(f"Error: {network} has {network.num_addresses} addresses. Use --force to scan it anyway.")

    if not args.no_banner:
        print(BANNER)
    print(f"Scanning {network} ({network.num_addresses} addresses) "
          f"with {args.threads} threads, {args.timeout} ms timeout")

    started = time.perf_counter()
    results = scan(network, args.threads, args.timeout, not args.no_resolve)
    print_table(results)
    print(f"Finished in {time.perf_counter() - started:.1f}s")

    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()