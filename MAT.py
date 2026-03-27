#!/usr/bin/env python3
"""
╔╦╗╔═╗╔╦╗
║║║╠═╣ ║ 
╩ ╩╩ ╩ ╩ 
My Attack Tactic (MAT) - Network Scanner v1.0
TCP/UDP Port Scanner + Service/Banner Detection
Usage: python mat_scanner.py
"""

import socket
import threading
import ipaddress
import sys
import time
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLORS (works on Linux/macOS/Windows 10+)
# ─────────────────────────────────────────────────────────────────────────────
def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = supports_color()

class C:
    RED     = "\033[91m"  if USE_COLOR else ""
    YELLOW  = "\033[93m"  if USE_COLOR else ""
    GREEN   = "\033[92m"  if USE_COLOR else ""
    CYAN    = "\033[96m"  if USE_COLOR else ""
    WHITE   = "\033[97m"  if USE_COLOR else ""
    MAGENTA = "\033[95m"  if USE_COLOR else ""
    DIM     = "\033[2m"   if USE_COLOR else ""
    BOLD    = "\033[1m"   if USE_COLOR else ""
    RESET   = "\033[0m"   if USE_COLOR else ""

def c(color, text):
    return f"{color}{text}{C.RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN SERVICES
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_SERVICES = {
    20: "FTP-DATA",   21: "FTP",         22: "SSH",         23: "TELNET",
    25: "SMTP",       53: "DNS",          67: "DHCP",        69: "TFTP",
    80: "HTTP",       88: "KERBEROS",    110: "POP3",       111: "RPC",
    123: "NTP",      135: "MSRPC",       137: "NETBIOS-NS", 139: "NETBIOS-SSN",
    143: "IMAP",     161: "SNMP",        389: "LDAP",       443: "HTTPS",
    445: "SMB",      465: "SMTPS",       500: "IKE",        512: "REXEC",
    514: "SYSLOG",   587: "SMTP-SUB",    636: "LDAPS",      873: "RSYNC",
    993: "IMAPS",    995: "POP3S",      1080: "SOCKS",     1194: "OPENVPN",
   1433: "MSSQL",   1521: "ORACLE",     1723: "PPTP",      1883: "MQTT",
   2049: "NFS",     2181: "ZOOKEEPER",  2375: "DOCKER",    2376: "DOCKER-TLS",
   3000: "DEV-SRV", 3306: "MYSQL",      3389: "RDP",       3690: "SVN",
   4444: "MSPLOIT", 5000: "FLASK/UPNP", 5432: "POSTGRES",  5900: "VNC",
   5985: "WINRM",   6379: "REDIS",      6443: "K8S-API",   7001: "WEBLOGIC",
   8080: "HTTP-ALT",8443: "HTTPS-ALT",  8888: "JUPYTER",   9200: "ELASTICSEARCH",
  10250: "KUBELET", 11211: "MEMCACHED", 27017: "MONGODB",
}

RISKY_PORTS = {
    21:    ("FTP - plaintext credentials",              C.RED),
    23:    ("TELNET - completely unencrypted!",         C.RED),
    445:   ("SMB - EternalBlue/ransomware vector",      C.RED),
    3389:  ("RDP - brute-force target",                 C.RED),
    4444:  ("Metasploit default listener?",             C.RED),
    6379:  ("Redis - often unauthenticated",            C.RED),
    27017: ("MongoDB - check authentication!",          C.RED),
    2375:  ("Docker API - critical exposure",           C.RED),
    9200:  ("Elasticsearch - check auth!",              C.RED),
    11211: ("Memcached - DDoS amplification risk",      C.YELLOW),
    5900:  ("VNC - brute-force target",                 C.YELLOW),
    8080:  ("HTTP-ALT - info disclosure possible",      C.YELLOW),
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def hr(char="─", width=70, color=None):
    col = color if color else C.DIM
    print(f"{col}{char * width}{C.RESET}")

def print_banner():
    print()
    print(C.RED  + C.BOLD + "  ███╗   ███╗ █████╗ ████████╗" + C.RESET)
    print(C.RED           + "  ████╗ ████║██╔══██╗╚══██╔══╝" + C.RESET)
    print(C.YELLOW        + "  ██╔████╔██║███████║   ██║   "  + C.RESET)
    print(C.YELLOW        + "  ██║╚██╔╝██║██╔══██║   ██║   "  + C.RESET)
    print(C.GREEN         + "  ██║ ╚═╝ ██║██║  ██║   ██║   "  + C.RESET)
    print(C.GREEN         + "  ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   "  + C.RESET)
    print()
    print(C.WHITE + C.BOLD + "  My Attack Tactic" + C.RESET +
          C.CYAN            + " v1.0"              + C.RESET +
          C.DIM             + "  •  Network Scanner" + C.RESET)
    print(C.DIM + "  TCP/UDP Port Scanner + Service/Banner Detection" + C.RESET)
    print()
    hr("═", 70, C.RED)
    print(C.YELLOW + "  ⚠  FOR AUTHORIZED USE ONLY — Unauthorized scanning is illegal." + C.RESET)
    hr("═", 70, C.RED)
    print()

def ask(prompt, default=None):
    hint = f" [{default}]" if default is not None else ""
    try:
        val = input(C.CYAN + f"  {prompt}{hint}: " + C.RESET).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)
    return val if val else (str(default) if default is not None else "")

def confirm(prompt, default=False):
    hint = " [Y/n]" if default else " [y/N]"
    try:
        val = input(C.CYAN + f"  {prompt}{hint}: " + C.RESET).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)
    if val == "":
        return default
    return val in ("y", "yes")

def progress_bar(done, total, width=40):
    pct  = done / total if total else 0
    fill = int(pct * width)
    bar  = C.GREEN + "█" * fill + C.DIM + "░" * (width - fill) + C.RESET
    return f"  [{bar}] {C.CYAN}{done}/{total}{C.RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# RESOLVE TARGET
# ─────────────────────────────────────────────────────────────────────────────
def resolve_target(target):
    try:
        ip = str(ipaddress.ip_address(target))
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "N/A"
        return ip, hostname
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror:
        return None, None

# ─────────────────────────────────────────────────────────────────────────────
# BANNER GRAB
# ─────────────────────────────────────────────────────────────────────────────
def grab_banner(ip, port, timeout=2.0):
    probes = [b"HEAD / HTTP/1.0\r\n\r\n", b"\r\n", b""]
    for probe in probes:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                if probe:
                    s.sendall(probe)
                s.settimeout(timeout)
                banner = b""
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) > 512:
                        break
                decoded    = banner.decode("utf-8", errors="replace").strip()
                first_line = decoded.splitlines()[0][:80] if decoded else ""
                if first_line:
                    return first_line
        except Exception:
            continue
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNERS
# ─────────────────────────────────────────────────────────────────────────────
def scan_tcp_port(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = KNOWN_SERVICES.get(port, "UNKNOWN")
            banner  = grab_banner(ip, port)
            return {"port": port, "proto": "TCP", "state": "OPEN",
                    "service": service, "banner": banner}
    except Exception:
        return None

def scan_udp_port(ip, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 8, (ip, port))
            try:
                data, _ = s.recvfrom(1024)
                service = KNOWN_SERVICES.get(port, "UNKNOWN")
                banner  = data.decode("utf-8", errors="replace").strip()[:80]
                return {"port": port, "proto": "UDP", "state": "OPEN|FILTERED",
                        "service": service, "banner": banner}
            except socket.timeout:
                service = KNOWN_SERVICES.get(port, "UNKNOWN")
                return {"port": port, "proto": "UDP", "state": "OPEN|FILTERED",
                        "service": service, "banner": ""}
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENGINE WITH LIVE PROGRESS
# ─────────────────────────────────────────────────────────────────────────────
def run_scan(ip, ports, scan_udp, threads, timeout):
    results = []
    lock    = threading.Lock()
    done    = [0]

    def update(total):
        sys.stdout.write(f"\r{progress_bar(done[0], total)}  ")
        sys.stdout.flush()

    print(C.YELLOW + f"\n  Scanning TCP ports ({len(ports)} total)...\n" + C.RESET)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_tcp_port, ip, p, timeout): p for p in ports}
        for f in as_completed(futures):
            result = f.result()
            with lock:
                done[0] += 1
                if result:
                    results.append(result)
            update(len(ports))
    print()

    if scan_udp:
        udp_ports = [p for p in ports if p in KNOWN_SERVICES]
        done[0]   = 0
        print(C.YELLOW + f"\n  Scanning UDP ports ({len(udp_ports)} well-known)...\n" + C.RESET)
        with ThreadPoolExecutor(max_workers=max(1, threads // 2)) as ex:
            futures = {ex.submit(scan_udp_port, ip, p, timeout): p for p in udp_ports}
            for f in as_completed(futures):
                result = f.result()
                with lock:
                    done[0] += 1
                    if result:
                        already = any(r["port"] == result["port"] and r["proto"] == "TCP" for r in results)
                        if not already:
                            results.append(result)
                update(len(udp_ports))
        print()

    return sorted(results, key=lambda x: (x["port"], x["proto"]))

# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY RESULTS
# ─────────────────────────────────────────────────────────────────────────────
def display_results(results, ip, hostname, start_time, port_range, scan_udp):
    elapsed = (datetime.now() - start_time).total_seconds()

    print()
    hr("═", 70, C.RED)
    print(C.RED + C.BOLD + "  SCAN RESULTS" + C.RESET)
    hr("═", 70, C.RED)
    print()

    fields = [
        ("Target IP",  C.GREEN  + ip + C.RESET),
        ("Hostname",   hostname),
        ("Port Range", port_range),
        ("Protocols",  "TCP + UDP" if scan_udp else "TCP only"),
        ("Scan Time",  f"{elapsed:.2f}s"),
        ("Timestamp",  start_time.strftime("%Y-%m-%d %H:%M:%S")),
        ("Open Ports", C.YELLOW + str(len(results)) + C.RESET),
    ]
    for label, value in fields:
        print(f"  {C.DIM}{label:<12}{C.RESET}  {value}")
    print()

    if not results:
        print(C.YELLOW + "  ⚠  No open ports found in the specified range." + C.RESET)
        print()
        return

    hr()
    print(
        C.RED     + f"  {'PORT':<8}" + C.RESET +
        C.MAGENTA + f"{'PROTO':<8}"  + C.RESET +
        C.WHITE   + f"{'STATE':<16}" + C.RESET +
        C.YELLOW  + f"{'SERVICE':<20}" + C.RESET +
        C.DIM     + "BANNER" + C.RESET
    )
    hr()

    for r in results:
        sc     = C.GREEN if r["state"] == "OPEN" else C.YELLOW
        banner = r["banner"] if r["banner"] else C.DIM + "—" + C.RESET
        print(
            C.CYAN    + f"  {r['port']:<8}" + C.RESET +
            C.MAGENTA + f"{r['proto']:<8}"  + C.RESET +
            sc        + f"{r['state']:<16}" + C.RESET +
            C.YELLOW  + f"{r['service']:<20}" + C.RESET +
            C.DIM     + banner + C.RESET
        )

    hr()
    print()

    open_ports = {r["port"] for r in results}
    warnings   = [(p, msg, col) for p, (msg, col) in RISKY_PORTS.items() if p in open_ports]
    if warnings:
        print(C.RED + C.BOLD + "  ⚡ RISK HIGHLIGHTS" + C.RESET)
        hr("─", 70, C.RED)
        for port, msg, col in warnings:
            print(f"  {C.CYAN}:{port:<6}{C.RESET}  {col}{msg}{C.RESET}")
        hr("─", 70, C.RED)
        print()

# ─────────────────────────────────────────────────────────────────────────────
# PORT RANGE PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

PROFILES = {
    "1": ("Top common (1-1024)",   "1-1024"),
    "2": ("Full common (1-10000)", "1-10000"),
    "3": ("Extended (1-65535)",    "1-65535"),
    "4": ("Custom",                None),
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    accepted = confirm("I confirm I have authorization to scan the target", default=False)
    if not accepted:
        print(C.RED + "\n  Exiting. Scan cancelled.\n" + C.RESET)
        sys.exit(0)
    print()

    target = ask("TARGET (IP or hostname)")
    if not target:
        print(C.RED + "  No target provided. Exiting." + C.RESET)
        sys.exit(1)

    print(C.DIM + f"  Resolving {target}..." + C.RESET, end="", flush=True)
    ip, hostname = resolve_target(target)
    if not ip:
        print(C.RED + f"\n  Could not resolve '{target}'." + C.RESET)
        sys.exit(1)
    print(f"\r  {C.GREEN}✓{C.RESET} Resolved → {C.WHITE}{ip}{C.RESET} ({C.CYAN}{hostname}{C.RESET})\n")

    print(C.CYAN + "  PORT PROFILE" + C.RESET)
    for k, (label, _) in PROFILES.items():
        print(f"    {C.WHITE}[{k}]{C.RESET} {label}")
    print()

    choice = ask("Select profile [1-4]", default="1")
    if choice not in PROFILES:
        choice = "1"

    label, port_range_str = PROFILES[choice]
    if choice == "4":
        port_range_str = ask("Enter ports (e.g. 22,80,443 or 1-1024)")

    ports = parse_ports(port_range_str)
    print(f"  {C.GREEN}✓{C.RESET} {label} — {C.WHITE}{len(ports)}{C.RESET} ports\n")

    scan_udp = confirm("Enable UDP scanning? (slower)", default=False)
    threads  = int(ask("Threads", default=100))
    timeout  = float(ask("Timeout in seconds", default="1.0"))

    print()
    hr("═", 70, C.RED)
    print(C.RED + C.BOLD + "  SCANNING" + C.RESET)
    hr("═", 70, C.RED)
    print(C.DIM + f"  Starting against {C.WHITE}{ip}{C.RESET}{C.DIM} at {datetime.now().strftime('%H:%M:%S')}" + C.RESET)

    start_time = datetime.now()
    results    = run_scan(ip, ports, scan_udp, threads, timeout)
    display_results(results, ip, hostname, start_time, port_range_str, scan_udp)

    save = confirm("Save results to file?", default=False)
    if save:
        fname = f"mat_scan_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, "w") as f:
            f.write("MAT Scanner v1.0 - Scan Report\n")
            f.write(f"Target : {ip} ({hostname})\n")
            f.write(f"Date   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Ports  : {port_range_str}\n\n")
            f.write(f"{'PORT':<8}{'PROTO':<8}{'STATE':<16}{'SERVICE':<20}BANNER\n")
            f.write("-" * 80 + "\n")
            for r in results:
                f.write(f"{r['port']:<8}{r['proto']:<8}{r['state']:<16}{r['service']:<20}{r['banner']}\n")
        print(f"  {C.GREEN}✓{C.RESET} Saved to {C.WHITE}{fname}{C.RESET}")

    print()
    hr("═", 70, C.DIM)
    print(C.DIM + "  MAT scan complete." + C.RESET)
    hr("═", 70, C.DIM)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C.RED + "\n\n  ✗ Scan interrupted by user.\n" + C.RESET)
        sys.exit(0)
