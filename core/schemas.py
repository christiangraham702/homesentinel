from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Optional, Union
from pydantic import BaseModel, Field

IPAddress = Union[IPv4Address, IPv6Address]

class HostSeen(BaseModel):
    type: Literal["host_seen"] = "host_seen"
    ts: datetime = Field(default_factory=lambda: datetime.now())
    ip: IPAddress
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    src: Literal["arp", "ping", "nmap-sn", "dhcp", "manual"] = "manual"


class ServiceObserved(BaseModel):
    type: Literal["service"] = "service"
    ts: datetime = Field(default_factory=lambda: datetime.now())
    ip: IPAddress
    port: int 
    proto: Literal["tcp", "udp"] = "tcp"
    state: Literal["open", "closed", "filtered", "unknown"] = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None


