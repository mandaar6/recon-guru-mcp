"""collect_findings — correlate all recon data into one ranked findings list.

This is the Stage-4 differentiator. It reads the canonical workspace files that
exist (ports, exploits, tech stack, shodan) and **joins** them by
``host / ip / port / service`` into a single de-duplicated, severity-ranked
``/workspace/findings.json``. CVE findings are enriched with the CVSS-derived
severity from ``exploits.json``, so "80/tcp Apache 2.4.49 → CVE-2021-41773
(critical)" becomes one correlated record instead of three disconnected facts.

Directly observed findings (open ports, missing headers) are marked validated;
version-inferred ones (CVEs, exploits) are left for the brain's validation gate
(the playbook layer). The brain triages this list; it doesn't re-derive it.
"""

from __future__ import annotations

from .. import findings, workspace
from ..app import mcp


@mcp.tool()
async def collect_findings() -> dict:
    """Correlate recon results into one structured, ranked findings list.

    Reads ports.json, exploits.json, tech_stack.json, and shodan.json from the
    workspace and writes findings.json — findings keyed on host/ip/port/service,
    de-duplicated, severity-ranked, each with an integrity hash and a
    validated/confidence grounding flag.

    Returns:
        An envelope: total findings, counts by severity and type, the
        highest-severity findings, and the output file path. The full list is
        written to findings.json.
    """
    ports = workspace.read_json("ports.json", {}) or {}
    exploits = workspace.read_json("exploits.json", {}) or {}
    tech = workspace.read_json("http_probe.json", {}) or {}  # tech + missing headers
    shodan = workspace.read_json("shodan.json", {}) or {}

    if not (ports or tech or shodan):
        return {
            "ok": False,
            "error": (
                "nothing to correlate — run port_scan / tech_stack / "
                "shodan_enrich first"
            ),
        }

    items: list[dict] = []

    # --- ports + CVEs + exploits (joined by service:version) -------------
    for host, hinfo in ports.items():
        ip = hinfo.get("ip", "")
        for p in hinfo.get("open_ports", []):
            svc = (p.get("service") or "").strip()
            ver = (p.get("version") or "").strip()
            svc_ver = f"{svc} {ver}".strip()
            port = p.get("port")
            proto = p.get("protocol", "tcp")

            items.append(findings.make_finding(
                "open_port", host=host, ip=ip, port=port, service=svc,
                version=ver, severity="info", tool="port_scan",
                evidence=f"{port}/{proto} {svc_ver}".strip(),
            ))

            # CVE details (CVSS → severity) come from exploits.json by svc_ver.
            cve_details = {
                c.get("id"): c
                for c in exploits.get(svc_ver, {}).get("cves", [])
            }
            for cid in p.get("cves", []):
                det = cve_details.get(cid, {})
                items.append(findings.make_finding(
                    "cve", host=host, ip=ip, port=port, service=svc,
                    version=ver, ref=cid,
                    severity=findings.severity_from_cvss(det.get("cvss")),
                    tool="exploit_lookup",
                    evidence=(det.get("description", "") or f"{svc_ver} {cid}"),
                ))
            for title in p.get("exploits", []):
                items.append(findings.make_finding(
                    "exploit", host=host, ip=ip, port=port, service=svc,
                    version=ver, ref=str(title)[:80], severity="high",
                    tool="exploit_lookup", evidence=str(title),
                ))

    # --- missing security headers ---------------------------------------
    for host, tinfo in tech.items():
        techs = tinfo.get("technologies", [])
        for h in tinfo.get("missing_headers", []):
            items.append(findings.make_finding(
                "missing_header", host=host, ref=h, severity="low",
                tool="tech_stack", evidence=f"missing security header: {h}",
                tech=techs,
            ))

    # --- Shodan-flagged vulns -------------------------------------------
    for host, sinfo in shodan.items():
        ip = sinfo.get("ip", "")
        for cid in sinfo.get("vulns", []):
            items.append(findings.make_finding(
                "shodan_vuln", host=host, ip=ip, ref=cid, severity="medium",
                tool="shodan_enrich", evidence=f"Shodan flagged {cid} on {ip}",
            ))

    ordered = findings.save_findings(items)

    by_sev: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in ordered:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    top = [
        {"severity": f["severity"], "type": f["type"], "host": f["host"],
         "port": f["port"], "ref": f["ref"], "validated": f["validated"]}
        for f in ordered
        if f["severity"] in ("critical", "high", "medium")
    ][:25]

    unvalidated = sum(1 for f in ordered if not f["validated"])
    note = (
        f"{unvalidated} finding(s) are version-inferred and await the "
        "validation gate" if unvalidated else "all findings are directly observed"
    )

    return {
        "ok": True,
        "total_findings": len(ordered),
        "by_severity": by_sev,
        "by_type": by_type,
        "top": top,
        "output_file": str(workspace.path(findings.FINDINGS_FILE)),
        "note": note,
    }


@mcp.tool()
async def validate_finding(finding_id: str, validated: bool = True,
                           confidence: str = "confirmed",
                           rationale: str = "") -> dict:
    """Record the validation gate's verdict on a finding.

    The brain *is* the validation gate: after judging whether a
    version-inferred finding (e.g. a CVE matched by service/version) is actually
    exploitable in this context, it calls this to persist the verdict. The
    finding's integrity hash is unaffected — it covers only the factual fields —
    so this records judgment without rewriting the underlying fact.

    Args:
        finding_id: The finding's id (from collect_findings' output / findings.json).
        validated: True if the finding passed the gate, False if rejected.
        confidence: Short label, e.g. "confirmed", "false-positive", "needs-manual".
        rationale: One-line reason for the verdict.

    Returns:
        The updated finding, or an error if the id isn't found.
    """
    items = findings.load_findings()
    for f in items:
        if f.get("id") == finding_id:
            f["validated"] = bool(validated)
            f["confidence"] = confidence
            if rationale:
                f["rationale"] = rationale[:500]
            findings.save_findings(items)
            return {"ok": True, "finding": f}
    return {"ok": False, "error": f"no finding with id '{finding_id}'"}
