import subprocess
import sys

VULNERABLE_VERSION = (2, 4, 13)

def get_cups_version():
    try:
        result = subprocess.run(
            ["cups-config", "--version"],
            capture_output=True,
            text=True
        )
        version_str = result.stdout.strip()
        return tuple(map(int, version_str.split(".")))
    except FileNotFoundError:
        print("cups-config not found. Is CUPS installed?")
        sys.exit(1)

def is_vulnerable(version):
    return version < VULNERABLE_VERSION

def main():
    # Mock version for presentation
    version_str = "2.4.12"  # simulate a vulnerable version
    version = tuple(map(int, version_str.split(".")))
    print(f"Detected CUPS version: {'.'.join(map(str, version))}")
    if is_vulnerable(version):
        print("System is VULNERABLE to CVE-2025-58060")
    else:
        print("System is NOT vulnerable")

if __name__ == "__main__":
    main()
