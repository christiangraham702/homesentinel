"""
Service/version scan for a host or list of hosts (uses Nmap).
Examples:
  python -m sensor.scan --host 192.168.68.10
  python -m sensor.scan --hosts-file /tmp/hosts.txt --ports 1-1024
"""

from __future__ import annotations
import argparse
import subprocess
from pathlib import Path
from typing import Iterable, List

from core.nmap_parse import services_from_nmap_xml
from core.jsonutil import to_json
from core.config import settings

# add near top
PROFILES = {
    "fast": [
        "-sV",
        "-Pn",
        "-n",
        "-T4",
        "--host-timeout",
        "60s",
        "--max-retries",
        "1",
    ],
    "standard": [
        "-sV",
        "-Pn",
        "-n",
        "-T3",
        "--max-retries",
        "2",
    ],
    "deep": [
        "-sV",
        "-Pn",
        "-n",
        "-T3",
        "--max-retries",
        "2",
        "--script",
        "default,safe,version,discovery",
    ],
    "udp100": [
        "-sU",
        "-Pn",
        "-n",
        "-T2",
        "--top-ports",
        "100",
        "--max-retries",
        "2",
    ],
}


def run_nmap(host: str, ports: str | None, profile: str) -> str:
    base = ["nmap", "-oX", "-"] + PROFILES[profile]
    if ports and profile != "udp100":
        base += ["-p", ports]
    base.append(host)
    xml = subprocess.check_output(base, text=True, timeout=3600)
    return xml


def _iter_hosts(args) -> Iterable[str]:
    if args.host:
        yield args.host
    if args.hosts_file:
        for line in Path(args.hosts_file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def main():
    ap = argparse.ArgumentParser(description="Home scan (nmap)")
    ap.add_argument("--host", help="Single host/IP to scan")
    ap.add_argument("--hosts-file", help="FIle with one host/IP per line")
    ap.add_argument("--ports", default=settings.scan_ports, help="POrt spec (e.g., 1-1024,22,80)")
    ap.add_argument(
        "--profile", choices=list(PROFILES.keys()), help="Scan shit at: fast|standard|deep|udp100"
    )
    args = ap.parse_args()

    any_host = False
    for host in _iter_hosts(args):
        any_host = True
        print(f"scanning {host}")
        xml = run_nmap(host, args.ports, args.profile)
        for svc in services_from_nmap_xml(xml):
            print(to_json(svc))
    if not any_host:
        ap.error("Provide --host or --hosts-file")


if __name__ == "__main__":
    main()
