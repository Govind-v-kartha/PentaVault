"""Port scanner module — wrapper around python-nmap."""

from __future__ import annotations

import shutil
from typing import Any

from scanner.utils.logger import get_logger

log = get_logger("port_scanner")


def scan_ports(
    target: str,
    ports: str = "1-1024",
    arguments: str = "-sV -O --host-timeout 300",
) -> dict[str, Any]:
    """Run an Nmap scan against *target* and return structured results.

    Requires ``nmap`` to be installed on the host system and ``python-nmap``
    as a Python dependency. Falls back gracefully when unavailable.
    """
    if shutil.which("nmap") is None:
        log.warning("nmap binary not found on PATH — skipping port scan")
        return {"open_ports": [], "services": {}, "os_guess": "Unknown"}

    try:
        import nmap  # type: ignore[import-untyped]
    except ImportError:
        log.warning("python-nmap not installed — skipping port scan")
        return {"open_ports": [], "services": {}, "os_guess": "Unknown"}

    nm = nmap.PortScanner()
    log.info("Starting Nmap scan on %s (ports %s)", target, ports)

    try:
        nm.scan(hosts=target, ports=ports, arguments=arguments)
    except nmap.PortScannerError as exc:
        log.error("Nmap scan error: %s", exc)
        return {"open_ports": [], "services": {}, "os_guess": "Unknown"}

    open_ports: list[int] = []
    services: dict[str, str] = {}

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto]):
                state = nm[host][proto][port]["state"]
                if state == "open":
                    open_ports.append(port)
                    svc = nm[host][proto][port]
                    name = svc.get("product", svc.get("name", "unknown"))
                    version = svc.get("version", "")
                    services[str(port)] = f"{name} {version}".strip()

    os_guess = "Unknown"
    for host in nm.all_hosts():
        os_matches = nm[host].get("osmatch", [])
        if os_matches:
            os_guess = os_matches[0].get("name", "Unknown")
            break

    log.info("Nmap scan complete — %d open ports", len(open_ports))
    return {
        "open_ports": open_ports,
        "services": services,
        "os_guess": os_guess,
    }
