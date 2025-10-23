#!/usr/bin/env python3
"""
Port Scanner (simple, fast, and educational)
Author: Open for Hacktoberfest contributions
Dependencies: only Python standard library (3.6+)
Usage:
    python3 port_scanner.py --host example.com --ports 1-1024 --timeout 0.5 --workers 100
"""

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def parse_ports(port_arg):
    """Parse ports like '22,80,443,8000-8100' or '1-1024'"""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def scan_port(host, port, timeout):
    """Attempt to connect to host:port. Return (port, open_bool, banner)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = None
                try:
                    # Try to receive a short banner (non-blocking-ish)
                    s.settimeout(0.8)
                    banner = s.recv(1024)
                    if banner:
                        try:
                            banner = banner.decode(errors="replace").strip()
                        except Exception:
                            banner = repr(banner)
                except Exception:
                    banner = None
                return (port, True, banner)
    except KeyboardInterrupt:
        raise
    except Exception:
        pass
    return (port, False, None)

def resolve_host(target):
    """Resolve hostname to IPv4; return (ip, canonical_name)"""
    try:
        info = socket.getaddrinfo(target, None, family=socket.AF_INET)
        ip = info[0][4][0]
        try:
            cname = socket.gethostbyaddr(ip)[0]
        except Exception:
            cname = target
        return ip, cname
    except socket.gaierror:
        raise ValueError(f"Cannot resolve host: {target}")

def main():
    parser = argparse.ArgumentParser(description="Simple Port Scanner (educational)")
    parser.add_argument("--host", "-H", required=True, help="Target hostname or IP")
    parser.add_argument("--ports", "-p", default="1-1024",
                        help="Ports (e.g. 22,80,443 or 1-1024). Default: 1-1024")
    parser.add_argument("--timeout", "-t", type=float, default=0.5, help="Socket timeout seconds (default 0.5)")
    parser.add_argument("--workers", "-w", type=int, default=100, help="Concurrent worker threads (default 100)")
    parser.add_argument("--save", "-s", help="Save results to this file (optional)")
    args = parser.parse_args()

    try:
        ip, cname = resolve_host(args.host)
    except ValueError as e:
        print("❌", e)
        return

    ports = parse_ports(args.ports)
    print(f"🔎 Scanning {len(ports)} ports on {args.host} ({ip})")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    open_ports = []

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_port = {executor.submit(scan_port, ip, p, args.timeout): p for p in ports}
            for future in as_completed(future_to_port):
                p = future_to_port[future]
                try:
                    port, is_open, banner = future.result()
                    if is_open:
                        open_ports.append((port, banner))
                        banner_text = f" — banner: {banner}" if banner else ""
                        print(f"[OPEN] {port}{banner_text}")
                except KeyboardInterrupt:
                    print("\nAborted by user.")
                    return
                except Exception as ex:
                    # Non-fatal per-port errors
                    pass
    except KeyboardInterrupt:
        print("\nAborted by user.")
        return

    print("\n✅ Scan complete")
    print(f"Open ports ({len(open_ports)}):")
    for port, banner in sorted(open_ports):
        if banner:
            print(f" - {port}  |  {banner}")
        else:
            print(f" - {port}")

    if args.save:
        try:
            import json
            data = {
                "target": args.host,
                "ip": ip,
                "scanned_at": datetime.now().isoformat(),
                "open_ports": [{"port": p, "banner": b} for p, b in open_ports]
            }
            with open(args.save, "w") as f:
                json.dump(data, f, indent=2)
            print(f"\n💾 Results saved to {args.save}")
        except Exception as e:
            print("❌ Failed to save:", e)

if __name__ == "__main__":
    main()
