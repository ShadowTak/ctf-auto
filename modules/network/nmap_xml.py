"""Nmap XML ingestion for offline reports and competition workflows."""
import xml.etree.ElementTree as ET


def parse_xml(source):
    """Return normalized host/port records from an Nmap XML file or string."""
    if hasattr(source, "read"):
        root = ET.parse(source).getroot()
    elif isinstance(source, (bytes, bytearray)):
        root = ET.fromstring(bytes(source))
    else:
        with open(str(source), "rb") as handle:
            root = ET.parse(handle).getroot()
    hosts = []
    for host in root.findall("host"):
        addresses = [node.get("addr", "") for node in host.findall("address")]
        hostnames = [node.get("name", "") for node in host.findall("./hostnames/hostname")]
        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            scripts = []
            for script in port.findall("./script"):
                scripts.append({"id": script.get("id", ""),
                                "output": script.get("output", "")})
            ports.append({"port": int(port.get("portid", "0") or 0),
                          "protocol": port.get("protocol", "tcp"),
                          "service": service.get("name", "") if service is not None else "",
                          "product": service.get("product", "") if service is not None else "",
                          "version": service.get("version", "") if service is not None else "",
                          "scripts": scripts})
        hosts.append({"addresses": addresses, "hostnames": hostnames, "ports": ports})
    return hosts


def flatten_services(source):
    """Flatten XML into scanner-compatible {port: service/info} records."""
    result = {}
    for host in parse_xml(source):
        for item in host["ports"]:
            info = " ".join(x for x in (item["product"], item["version"]) if x).strip()
            if item["scripts"]:
                script_ids = ", ".join(x["id"] for x in item["scripts"] if x["id"])
                info = (info + " | NSE: " + script_ids).strip(" |")
            result[item["port"]] = {"service": item["service"] or "unknown",
                                     "info": info,
                                     "protocol": item["protocol"],
                                     "scripts": item["scripts"]}
    return result
