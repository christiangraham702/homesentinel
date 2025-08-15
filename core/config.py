import os 
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    network_cidr: str = os.getenv("NETWORK_CIDR", "192.168.1.0/24")
    scan_ports: str = os.getenv("SCAN_PORTS", "1-1024")
    webhook_url: str | None = os.getenv("WEBHOOK_URL") or None

settings = Settings()

