import os
import sys
import subprocess
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts_result = []
    for host in root.findall('host'):
        ip_addr = host.find("address").get("addr")
        ports_result = []
        for port in host.findall("ports/port"):
            port_id = port.get("portid")
            state = port.find("state").get("state")
            service_elem = port.find("service")
            service = service_elem.get("name") if service_elem is not None else "Unknown"
            product = service_elem.get("product") if service_elem is not None else None
            version = service_elem.get("version") if service_elem is not None else None
            scripts_result = []
            for script in port.findall("script"):
                scripts_result.append({
                    "id": script.get("id"),
                    "output": script.get("output"),
                })
            ports_result.append({
                "port": port_id,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "scripts": scripts_result,  # bos liste olabilir, zafiyet yoksa
            })
        hosts_result.append({
            "ip": ip_addr,
            "ports": ports_result,
        })
    return {
        "target": hosts_result[0]["ip"] if hosts_result else None,
        "hosts": hosts_result,
    }


def run_nmap(target):
    result = subprocess.run(
        ["nmap", "-sV", "--version-intensity", "9", "-sC", "--script", "vuln", "-T4", "-v",
         "-p", "3000,8081", "-oX", "ciktimiz.xml", target],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {
            "error": True,
            "message": "Nmap calisirken bir hata olustu.",
            "stderr": result.stderr,
        }
    return parse_nmap_xml("ciktimiz.xml")

if __name__ == "__main__":
    import json
    print(json.dumps(run_nmap("127.0.0.1"), indent=2, ensure_ascii=False))