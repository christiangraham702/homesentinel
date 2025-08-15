"""
Discovery CLI (MVP scaffold)
Usage:
  python -m homesentinel.sensor.discover --cidr 192.168.1.0/24
"""
from __future__ import annotations
import argparse
import ipaddress
import socket
from datetime import datetime, timezone
from core.config import settings
from core.schemas import HostSeen
from core.jsonutil import to_json

def _hostname_for(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

def discover_dummy(cidr: str):
    """Placeholder generator to prove the CLI & schema.
    Emits just the gateway (.1) and your local machine (best-effort)."""
    net = ipaddress.ip_network(cidr, strict=False)
    # Common home gateway guess (first usable)
    gw = str(list(net.hosts())[0]) if net.num_addresses > 2 else str(net.network_address + 1)
    yield HostSeen(ip=ipaddress.ip_address(gw), hostname=_hostname_for(gw), src="manual")

    # Local machine (approx): resolve primary IP if possible
    try:
        # May give 127.0.0.1 depending on OS; okay for scaffold
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        yield HostSeen(ip=ipaddress.ip_address(local_ip), hostname=_hostname_for(local_ip), src="manual")
    except Exception:
        pass

# add to your file, then swap into main() when you’re ready
def discover_arp(cidr: str, iface: str | None = None, timeout: int = 2):
    from scapy.all import ARP, Ether, srp  # local import so non-root runner still works

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    # srp sends/receives at layer 2; returns (answered, unanswered)
    ans, _ = srp(pkt, timeout=timeout, iface=iface, verbose=False)

    for _, resp in ans:
        ip = resp.psrc          # the host’s IP
        mac = resp.hwsrc        # the host’s MAC
        yield HostSeen(
            ip=ipaddress.ip_address(ip),
            mac=mac,
            hostname=_hostname_for(ip),
            src="arp",
        )

def main():
    parser = argparse.ArgumentParser(description="HomeSentinel discovery")
    parser.add_argument("--cidr", default=settings.network_cidr)
    parser.add_argument("--iface", default=None, help="Network interface (optional)")
    parser.add_argument("--timeout", type=int, default=2)
    args = parser.parse_args()

    for evt in discover_arp(args.cidr, iface=args.iface, timeout=args.timeout):
        print(to_json(evt))



if __name__ == "__main__":
    main()
