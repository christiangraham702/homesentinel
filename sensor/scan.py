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
from typing import Iterable, List, Optional, Tuple

from core.nmap_parse import services_from_nmap_xml
from core.jsonutil import to_json
from core.config import settings
from core.schemas import ServiceObserved

import json, os
from datetime import datetime, timezone


def append_jsonl(path: str, obj) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(to_json(obj) + "\n")
        f.flush()


def save_xml(save_dir: str, host: str, xml_text: str) -> None:
    Path(save_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    fname = f"{host.replace(':', '_')}_{ts}.xml"
    (Path(save_dir) / fname).write_text(xml_text, encoding="utf-8")


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


def run_nmap(
    host: str, ports: Optional[str] | None, profile: str, timeout_s: int = 3600
) -> Tuple[Optional[str], Optional[str]]:
    base = ["nmap", "-oX", "-"] + PROFILES[profile]
    if ports and profile != "udp100":
        base += ["-p", ports]
    base.append(host)
    try:
        proc = subprocess.run(base, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired:
        return None, f"timeout after {timeout_s}"

    xml = proc.stdout if proc.stdout else None

    if proc.returncode == 0:
        return xml, None

    err = proc.stderr.strip() or f"nmap exited {proc.returncode} on host {host}"
    return xml, err


def _iter_hosts(args) -> Iterable[str]:
    if args.host:
        yield args.host
    if args.hosts_file:
        for line in Path(args.hosts_file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def main():
    ap = argparse.ArgumentParser(description="HomeSentinel service scan (Nmap)")
    ap.add_argument("--host", help="Single host/IP to scan")
    ap.add_argument("--hosts-file", help="File with one host/IP per line")
    ap.add_argument(
        "--ports", default=settings.scan_ports, help="Port spec (e.g., 1-1024,22,80,443)"
    )
    ap.add_argument("--profile", choices=list(PROFILES.keys()), default="standard")
    ap.add_argument("--out-jsonl")
    ap.add_argument("--save-xml-dir")
    ap.add_argument("--errors-jsonl")
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    any_host = False
    for host in _iter_hosts(args):
        any_host = True
        try:
            xml, err = run_nmap(host, args.ports, args.profile, timeout_s=args.timeout)

            # Save raw XML if requested (even when err is non-None)
            if xml and args.save - xml - dir:
                save_xml(args.save - xml - dir, host, xml)

            if xml:
                # Parse what we got; a non-zero nmap exit may still yield good XML
                try:
                    for svc in services_from_nmap_xml(xml):
                        line = to_json(svc)
                        print(line)  # keep streaming to stdout
                        if args.out_jsonl:
                            append_jsonl(args.out_jsonl, svc)
                except Exception as parse_exc:
                    # Parser failed; log error with host
                    if args.errors_jsonl:
                        append_jsonl(
                            args.errors_jsonl,
                            {
                                "ts": datetime.now(timezone.utc).isoformat(),
                                "host": host,
                                "stage": "parse",
                                "error": str(parse_exc),
                            },
                        )
            if err:
                # Record the error for this host, but DO NOT raise
                if args.errors_jsonl:
                    append_jsonl(
                        args.errors_jsonl,
                        {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "host": host,
                            "stage": "nmap",
                            "error": err,
                        },
                    )
        except KeyboardInterrupt:
            # graceful stop: don't lose what we've already written
            print("\n[scan] interrupted by user", flush=True)
            break
        except Exception as e:
            # Catch-all so one host never kills the run
            if args.errors_jsonl:
                append_jsonl(
                    args.errors_jsonl,
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "host": host,
                        "stage": "python",
                        "error": repr(e),
                    },
                )
            # continue to next host

    if not any_host:
        ap.error("Provide --host or --hosts-file")


if __name__ == "__main__":
    main()
