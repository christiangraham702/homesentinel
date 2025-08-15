import json
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address 
from pydantic import BaseModel

def to_json(obj) -> str:
    def default(o):
        if isinstance(o, BaseModel):
            return o.model_dump()
        if isinstance(o, (IPv4Address, IPv6Address)):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        raise TypeError(f"type not serializable:  {type(o)}")
    return json.dumps(obj, default=default, separators=(",",":"), ensure_ascii=False)

