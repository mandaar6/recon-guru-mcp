"""port_scan — open ports and service/version detection for live hosts.

For each host (by default read from ``/workspace/live_hosts.txt``) it:
  1. resolves the hostname to an IP,
  2. discovers open ports with ``naabu`` (fast), then
  3. runs ``nmap -sV`` on those ports for service/version detection.

Fallbacks keep it working as binaries come online: with no ``naabu`` it lets
``nmap --top-ports`` do discovery; with no ``nmap`` it records bare open ports
from ``naabu``; with neither it reports cleanly that no scanner is available.

Results are written to ``/workspace/ports.json`` in the schema
``{host: {ip, open_ports: [{port, protocol, service, version, cves, exploits}]}}``
— the same shape ``exploit_lookup`` and ``report_gen`` consume. **Tier 1.**

Both ``naabu`` and ``nmap`` live in the Docker image, so a real scan runs in
the container; on a bare host without them the tool degrades gracefully.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
import xml.etree.ElementTree as ET

from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

SOURCE_DEFAULT = "live_hosts.txt"
OUT_FILE = "ports.json"


async def _resolve(host: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except Exception:
        return None


async def _naabu_ports(ip: str) -> list[int]:
    res = await run_tool(
        ["naabu", "-host", ip, "-silent", "-json"],
        timeout_s=settings.timeout_for("naabu"),
    )
    if not res.ok:
        return []
    ports: set[int] = set()
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ports.add(int(json.loads(line).get("port")))
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
    return sorted(ports)


async def _nmap_services(ip: str, port_spec: str | None) -> list[dict]:
    """Run nmap -sV. port_spec is a string like '80,443', or None for top-ports."""
    pspec = ["-p", port_spec] if port_spec else ["--top-ports", "100"]
    res = await run_tool(
        ["nmap", "-sV", "-T4", "--open", "-Pn", *pspec, "-oX", "-", ip],
        timeout_s=settings.timeout_for("nmap"),
    )
    return _parse_nmap_xml(res.stdout)


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    entries: list[dict] = []
    if not xml_text.strip():
        return entries
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return entries
    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for pe in ports_elem.findall("port"):
            state = pe.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = pe.find("service")
            service = version = ""
            if svc is not None:
                service = svc.get("product") or svc.get("name") or ""
                version = svc.get("version") or ""
            entries.append(
                {
                    "port": int(pe.get("portid", 0)),
                    "protocol": pe.get("protocol", "tcp"),
                    "service": service,
                    "version": version,
                    "cves": [],       # filled later by exploit_lookup
                    "exploits": [],
                }
            )
    return entries


def _bare_ports(ports: list[int]) -> list[dict]:
    return [
        {"port": p, "protocol": "tcp", "service": "", "version": "",
         "cves": [], "exploits": []}
        for p in ports
    ]


@mcp.tool()
async def port_scan(target: str = "", source_file: str = SOURCE_DEFAULT,
                    ports: str = "", project: str = "") -> dict:
    """Scan live hosts for open ports and detect services/versions.

    Args:
        target: Optional single host or comma-separated hosts. When empty, the
            host list is read from the workspace file.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "live_hosts.txt" (what live_probe writes).
        ports: Optional explicit port spec (e.g. "80,443,8080" or "1-1000").
            When given, nmap scans exactly those with service detection and
            naabu discovery is skipped. When empty, naabu discovers open ports
            (or nmap's top-100 if naabu isn't available).

    Returns:
        An envelope: hosts scanned, how many had open ports, total open ports,
        which scanner was used, the distinct services found, a per-host
        summary sample, any unresolved hosts, and the output file path. Full
        detail is written to ports.json.
    """
    workspace.use_project(project, target)
    if target.strip():
        raw_hosts = [h.strip() for h in target.split(",") if h.strip()]
    else:
        raw_hosts = workspace.read_lines(source_file)
        if not raw_hosts:
            return {
                "ok": False,
                "error": (
                    f"no hosts: workspace file '{source_file}' is empty. "
                    "Run live_probe first, or pass target=..."
                ),
            }

    valid: list[str] = []
    for h in raw_hosts:
        try:
            valid.append(validate_target(h))
        except InvalidTarget:
            pass
    hosts = scope.filter_in_scope(sorted(set(valid)))
    if not hosts:
        return {"ok": False, "error": "no valid, in-scope hosts to scan"}

    naabu_ok = shutil.which("naabu") is not None
    nmap_ok = shutil.which("nmap") is not None
    if not naabu_ok and not nmap_ok:
        return {
            "ok": False,
            "error": (
                "no port scanner available: neither naabu nor nmap is installed. "
                "They are provided by the Docker image — run this tool in the container."
            ),
        }

    results: dict[str, dict] = {}
    unresolved: list[str] = []
    sem = asyncio.Semaphore(min(settings.max_concurrency, 10))  # nmap is heavier

    async def scan_host(host: str):
        async with sem:
            ip = await _resolve(host)
            if not ip:
                unresolved.append(host)
                return
            if ports.strip():
                entries = (
                    await _nmap_services(ip, ports.strip()) if nmap_ok
                    else _bare_ports([int(p) for p in ports.split(",") if p.strip().isdigit()])
                )
            elif naabu_ok:
                found = await _naabu_ports(ip)
                if not found:
                    entries = []
                elif nmap_ok:
                    entries = await _nmap_services(ip, ",".join(map(str, found)))
                else:
                    entries = _bare_ports(found)
            else:  # nmap only
                entries = await _nmap_services(ip, None)
            results[host] = {"ip": ip, "open_ports": entries}

    await asyncio.gather(*(scan_host(h) for h in hosts))
    out_path = workspace.write_json(OUT_FILE, results)

    total_ports = sum(len(v["open_ports"]) for v in results.values())
    with_ports = sum(1 for v in results.values() if v["open_ports"])
    services = sorted(
        {
            f"{p['service']} {p['version']}".strip()
            for v in results.values()
            for p in v["open_ports"]
            if p["service"]
        }
    )
    summary = {
        host: [
            f"{p['port']}/{p['protocol']} {p['service']} {p['version']}".strip()
            for p in v["open_ports"]
        ]
        for host, v in list(results.items())[:20]
    }

    if naabu_ok and nmap_ok:
        scanner = "naabu + nmap -sV"
    elif nmap_ok:
        scanner = "nmap --top-ports 100 -sV"
    else:
        scanner = "naabu only (no nmap for service detection)"

    note_bits = []
    if unresolved:
        note_bits.append(f"{len(unresolved)} host(s) did not resolve")

    return {
        "ok": True,
        "hosts_scanned": len(hosts),
        "hosts_with_open_ports": with_ports,
        "total_open_ports": total_ports,
        "scanner": scanner,
        "services": services[:50],
        "output_file": str(out_path),
        "summary": summary,
        "unresolved": unresolved[:20],
        "note": "; ".join(note_bits),
    }
