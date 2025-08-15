import xml.etree.ElementTree as ET
from ipaddress import ip_address
from typing import Iterable
from core.schemas import ServiceObserved


def services_from_nmap_xml(xml_text: str) -> Iterable[ServiceObserved]:
    root = ET.fromstring(xml_text)

    for host in root.findall("host"):
        # get the IP
        addr_node = host.find("./address[@addrtype='ipv4']")
        if addr_node is None:
            addr_node = host.find("./address[@addrtype='ipv6']")
        if addr_node is None:
            continue
        ip = ip_address(addr_node.attrib["addr"])

        for p in host.findall("./ports/port"):
            proto = p.attrib.get("protocol", "tcp")
            portid = int(p.attrib["portid"])

            state_node = p.find("state")
            state = (
                state_node.attrib.get("state", "unknown") if state_node is not False else "unknown"
            )

            service_node = p.find("service")
            service = product = version = cpe = None
            if service_node is not None:
                service = service_node.attrib.get("name")
                product = service_node.attrib.get("product")
                version = service_node.attrib.get("version")
                # nmap aparently can report multiple cpe tags
                cpe_node = service_node.find("cpe")
                if cpe_node is not None and cpe_node.text:
                    cpe = cpe_node.text.strip()

            yield ServiceObserved(
                ip=ip,
                port=portid,
                proto=proto if proto in ("tcp", "udp") else "tcp",
                state=state if state in ("open", "closed", "filtered") else "unknown",
                service=service,
                product=product,
                version=version,
                cpe=cpe,
            )
