## What it does

Two-stage detection tool for CVE-2025-58060,  authentication bypass vulnerability in the Common UNIX Printing System (CUPS). Rather than relying on version numbers alone, the tool combines a banner-based version check with an active auth bypass probe. This helps confirming real vulnerability status even when the Server header truncates the patch version.

**Stage 1 — Version check**
Reads the `Server:` HTTP header from the CUPS web interface on port 631 and compares the detected version against the patched threshold `(2, 4, 13)`. If the banner only reports `CUPS/2.4` (truncated), the tool flags this and defers to Stage 2.

**Stage 2 — Active auth bypass probe**
Sends a crafted HTTP GET request to `/admin/` with a `Basic` Authorization header containing arbitrary credentials. On a vulnerable system, CUPS skips the authentication type check and returns HTTP 200. A patched system returns HTTP 401.

---

## Usage

```bash
# Check local machine only
python3 cups_detector.py

# Probe a single host
python3 cups_detector.py 192.168.1.10

# Scan a subnet
python3 cups_detector.py 192.168.1.0/24

# Scan an IP range
python3 cups_detector.py 192.168.1.1-20
```
---

## Requirements

- Python 3.6+
- No third-party libraries — standard library only (`subprocess`, `socket`, `http.client`, `ipaddress`, `base64`, `argparse`)

---

## Disclaimer

This tool is for demo and security assessment only. 
Only run against systems you own or have explicit written permission to test. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA) or equivalent laws in your jurisdiction.
