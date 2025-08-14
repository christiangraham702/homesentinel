awesome — let’s lock in a tight, do-able plan for the discovery slice of your MVP. you’ll write small, testable pieces and see value quickly.

Week 1–2 plan (discovery + first visibility)

0) Project scaffolding (1–2 hrs)

Goal: a place to put code with configs you can run anywhere.
	•	repo layout:

homesentinel/
  api/                # FastAPI service (later)
  sensor/             # discovery + scanning CLI
  core/               # shared models/utils
  storage/            # db + migrations (sqlite to start)
  configs/            # .env.example, allowlist.yaml, settings.json
  scripts/            # dev helpers
  tests/
  README.md
  pyproject.toml      # or requirements.txt

	•	dependencies (initial): scapy, python-dotenv, pydantic, requests (nmap later)
	•	config files:
	•	configs/.env.example → NETWORK_CIDR=192.168.1.0/24, WEBHOOK_URL=, SCAN_PORTS=1-1024
	•	configs/allowlist.yaml for password tests (later)

Acceptance criteria: python -m sensor.discover --cidr 192.168.1.0/24 prints JSON events.

⸻

1) Device discovery via ARP + ping sweep (1 day)

Goal: find live hosts reliably.
	•	Active: ARP sweep with scapy (fast + LAN-friendly)
	•	Confirm: optional nmap -sn or ICMP ping on hits (toggle)
	•	Normalize: create a consistent event record

Interfaces
	•	CLI:

python -m sensor.discover --cidr 192.168.1.0/24 --confirm-ping


	•	event schema (core/schemas.py):

class HostSeen(BaseModel):
    type: Literal["host_seen"] = "host_seen"
    ts: datetime
    ip: IPvAnyAddress
    mac: str | None
    hostname: str | None
    vendor: str | None
    src: Literal["arp","ping","nmap-sn"]



Tasks
	•	implement sensor/discover.py:
	•	arp_sweep(cidr) -> list[HostSeen]
	•	confirm_alive(ip) -> bool (ping)
	•	resolve_hostname(ip) -> str|None
	•	optional OUI lookup (local file or skip for now)
	•	print as JSON lines or POST to API (Phase 3)

Tests / checks
	•	run on your LAN; verify your Pi, phone, laptop appear.
	•	try wrong subnet → graceful error.

Acceptance criteria: prints a list of host_seen events with IP/MAC/hostname.

⸻

2) DHCP lease pull (optional, parallel 0.5 day)

Goal: catch devices that are quiet but have leases.
	•	If you run Pi-hole: parse /etc/pihole/dhcp.leases
	•	If router has web interface with JSON/HTML table, add a parser later (not MVP)

Interface

python -m sensor.dhcp --source pihole --path /etc/pihole/dhcp.leases

Output: host_seen events with src="dhcp".

Acceptance criteria: events emitted for leases that ARP may miss.

⸻

3) Service fingerprinting (nmap) (1–2 days)

Goal: for each live host, learn open ports + banners.
	•	start simple: call nmap via subprocess (no need for a wrapper yet)
	•	nmap -sV -T4 -Pn -p 1-1024 -oX - <ip>
	•	later: top-1000 or targeted common ports, plus UDP if you want
	•	parse XML → normalize to ServiceObserved schema
	•	rate-limit: max concurrent scans (e.g., 4) and per-host cooldown.

Interfaces
	•	CLI:

python -m sensor.scan --host 192.168.1.37 --ports 1-1024
python -m sensor.scan --hosts-file hosts.txt


	•	schema:

class ServiceObserved(BaseModel):
    type: Literal["service"] = "service"
    ts: datetime
    ip: IPvAnyAddress
    port: int
    proto: Literal["tcp","udp"]
    product: str|None
    version: str|None
    cpe: str|None



Acceptance criteria: for a given IP, emit service events (e.g., 22/tcp OpenSSH 9.x).

⸻

4) Basic risk scoring (heuristics) (0.5 day)

Goal: a simple “is this interesting?” score per device.
	•	rules (start tiny):
	•	+50 if port in {23 telnet, 21 ftp, 5900 vnc, 445 smb}
	•	+20 if HTTP title indicates router/admin panel
	•	+10 if SSH/OpenSSH version < 7.4 (rough string compare; okay for MVP)
	•	+15 if new port opened since last scan (we’ll track later)
	•	implement core/risk.py:

def risk_for_services(services: list[ServiceObserved]) -> int:
    ...



Acceptance criteria: calling function returns a score 0..100+ for a device snapshot.

⸻

5) Persistence (SQLite MVP) (0.5–1 day)

Goal: remember hosts/services and last seen.
	•	create storage/db.py with sqlite3 and simple helpers
	•	tables: device, service, scan, event (minimal)
	•	on host_seen → upsert device (ip, mac, hostname, vendor, timestamps)
	•	on service → upsert by (device_id, port/proto) and update product/version

Acceptance criteria: run discover + scan, then query DB to see rows populated.

⸻

6) Alerts (webhook) for “new device” or “new open port” (0.5 day)

Goal: immediate feedback loop.
	•	core/alerts.py:
	•	send_webhook(event_dict) to Discord/Slack webhook from .env
	•	“new device” = device first_seen within last X minutes
	•	“new open port” = service row created in last X minutes

Acceptance criteria: you get a message in your Discord channel when a new device joins or new service appears.

⸻

7) Tiny dashboard (list only) (0.5–1 day)

Goal: make it feel real without boiling the ocean.
	•	FastAPI with two routes:
	•	GET /devices → JSON list
	•	GET / → simple HTMX/templated page that lists devices + risk + last_seen
	•	Poll every 15s (client-side) to refresh.

Acceptance criteria: open http://<host>:8000 and see a table of devices with risk scores.

⸻

8) Orchestration (runner) (0.5 day)

Goal: one command to do recurring discovery + scans.
	•	sensor/runner.py:
	•	every N minutes:
	•	discover hosts
	•	pick hosts not scanned in last M minutes → scan
	•	update DB, compute risk, send alerts
	•	CLI:

python -m sensor.runner --cidr 192.168.1.0/24 --interval 300



Acceptance criteria: leave it running; watch dashboard + alerts update over time.

⸻

9) Testing plan (quick wins)
	•	Unit:
	•	parse nmap XML fixtures → services list
	•	risk rules for crafted service sets
	•	Integration:
	•	run discover on a tiny CIDR (e.g., /30 in a test lab VM)
	•	temp SQLite file; run discover→scan→assert rows
	•	Manual:
	•	start an SSH server in a container, confirm it’s discovered and scored
	•	toggle a port open/closed; verify “new open port” alert fires once

⸻

10) Guardrails & gotchas
	•	Permissions: ARP sweep/sniff may require root; plan to run sensor with sudo on Pi.
	•	Rate limiting: don’t hammer your router or IoT devices; default --interval 300.
	•	False positives: banner version checks are fuzzy; that’s ok for MVP.
	•	Config safety: .env for webhooks, make sure you don’t commit secrets.
	•	Ethics: only scan your own LAN; make “scope” explicit in README.

⸻

Command cheatsheet to aim for

# discover
python -m sensor.discover --cidr 192.168.1.0/24 > /tmp/hosts.jsonl

# scan one host
python -m sensor.scan --host 192.168.1.10 --ports 1-1024

# run the loop
python -m sensor.runner --cidr 192.168.1.0/24 --interval 300

# start API/dashboard
uvicorn api.main:app --reload --port 8000


⸻

Definition of done for “Discovery MVP”
	•	host_seen events from ARP (and optional DHCP)
	•	nmap service events for known hosts
	•	basic risk score per device
	•	data persisted in SQLite
	•	webhook alerts for new device / new port
	•	minimal dashboard shows devices, services, risk, last seen
	•	runner loops cleanly with rate limiting

⸻

want me to draft the Pydantic schemas and the nmap XML parser function signatures next? those two pieces tend to unblock everything else fast.
