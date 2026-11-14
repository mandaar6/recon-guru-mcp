"""Structured findings — the join that makes correlation a lookup, not a guess.

A *finding* is a normalized record keyed on ``host / ip / port / service`` so
facts from different tools line up. Each raw tool writes its own workspace file;
the ``collect_findings`` tool harvests them into one de-duplicated,
severity-ranked ``findings.json``. Every finding carries:

  * a stable ``id`` (content hash of its key fields) — so re-running a tool
    updates rather than duplicates;
  * an ``output_hash`` — integrity, so a downstream verifier (not the LLM) can
    confirm a finding wasn't altered;
  * ``validated`` + ``confidence`` — the **grounding** dimension. Directly
    observed facts (an open port, a missing header) are validated on sight;
    version-inferred ones (a CVE matched by service/version) are *not* — they
    await the brain's validation gate (the playbook layer, Stage 8).

The brain triages findings; it never has to re-derive them.
"""

from __future__ import annotations

import hashlib
import json

from . import workspace

FINDINGS_FILE = "findings.json"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Finding types that are directly observed (true on sight) vs inferred.
_OBSERVED_TYPES = {"open_port", "missing_header"}

# output_hash covers only the immutable *factual* fields, so the brain updating
# the validation verdict (validated/confidence/rationale/severity) never breaks
# the integrity anchor of the underlying fact.
_HASHED_FIELDS = ("type", "host", "ip", "port", "service", "version", "ref",
                  "evidence", "tool")


def severity_from_cvss(score) -> str:
    """Map a CVSS base score to a severity bucket."""
    if score is None:
        return "medium"  # a known CVE with no score still matters
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


def _grounding(ftype: str) -> tuple[bool, str]:
    """(validated, confidence) by finding type."""
    if ftype in _OBSERVED_TYPES:
        return True, "observed"
    return False, "version-inferred"  # pending the brain's validation gate


def finding_id(f: dict) -> str:
    key = "|".join(
        str(f.get(k, "")) for k in ("type", "host", "port", "service", "ref")
    )
    return "fnd-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def make_finding(ftype: str, *, host: str = "", ip: str = "", port=None,
                 service: str = "", version: str = "", ref: str = "",
                 severity: str = "info", evidence: str = "", tool: str = "",
                 tech: list | None = None) -> dict:
    """Build a normalized finding with id, grounding, and integrity hash."""
    validated, confidence = _grounding(ftype)
    f = {
        "type": ftype,
        "host": host,
        "ip": ip,
        "port": port,
        "service": service,
        "version": version,
        "ref": ref,
        "severity": severity,
        "evidence": (evidence or "")[:500],
        "tool": tool,
        "tech": tech or [],
        "validated": validated,
        "confidence": confidence,
    }
    f["id"] = finding_id(f)
    payload = json.dumps({k: f[k] for k in _HASHED_FIELDS}, sort_keys=True)
    f["output_hash"] = "sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:16]
    return f


def load_findings() -> list[dict]:
    data = workspace.read_json(FINDINGS_FILE, [])
    return data if isinstance(data, list) else []


def save_findings(items: list[dict]) -> list[dict]:
    """De-duplicate by id and write severity-ranked. Returns the final list."""
    by_id = {f["id"]: f for f in items}
    ordered = sorted(
        by_id.values(),
        key=lambda x: (
            -SEVERITY_ORDER.get(x.get("severity", "info"), 0),
            x.get("host", ""),
            x.get("port") or 0,
        ),
    )
    workspace.write_json(FINDINGS_FILE, ordered)
    return ordered
