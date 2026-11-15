"""secret_scan — find leaked secrets in the target's JavaScript via trufflehog.

Web apps frequently leak API keys/tokens in their JS bundles. This tool takes
the JS URLs found by ``crawl``/``url_collect`` (from ``/workspace/urls.txt``),
downloads them to an isolated temp dir, and runs ``trufflehog filesystem`` over
them. Detections are written to ``/workspace/secrets.json``.

**Tier 2.** Needs the ``trufflehog`` binary (in the Docker image). Bounded by
``max_files`` to stay quick. Supports `auth` for fetching protected JS.
"""

from __future__ import annotations

import asyncio
import json
import shutil

import httpx

from .. import auth as _auth
from .. import workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool

SOURCE_DEFAULT = "urls.txt"
OUT_FILE = "secrets.json"
JS_DIR = "_js_downloads"


def _is_js(url: str) -> bool:
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith((".js", ".mjs", ".json", ".map"))


@mcp.tool()
async def secret_scan(source_file: str = SOURCE_DEFAULT, max_files: int = 40,
                      auth: str = "", project: str = "") -> dict:
    """Scan the target's JavaScript for leaked secrets (trufflehog).

    Args:
        source_file: Workspace URL list to pull JS files from. Defaults to
            "urls.txt" (crawl / url_collect output).
        max_files: Max JS files to download and scan. Default 40.
        auth: Optional raw HTTP header(s) for fetching protected JS.

    Returns:
        An envelope: files scanned, secrets found, detector-type breakdown, a
        redacted sample, and the output file path. Detail → secrets.json.
    """
    workspace.use_project(project)
    urls = [u for u in workspace.read_lines(source_file) if _is_js(u)][:max_files]
    if not urls:
        return {
            "ok": False,
            "error": (
                f"no JS URLs in '{source_file}'. Run crawl / url_collect first."
            ),
        }

    js_dir = workspace.path(JS_DIR)
    if js_dir.exists():
        shutil.rmtree(js_dir, ignore_errors=True)
    js_dir.mkdir(parents=True, exist_ok=True)

    sem = asyncio.Semaphore(min(settings.max_concurrency, 10))
    downloaded = 0

    async def fetch(i: int, url: str):
        nonlocal downloaded
        async with sem:
            try:
                async with httpx.AsyncClient(
                    verify=False, follow_redirects=True,
                    headers={"User-Agent": settings.user_agent, **_auth.header_dict(auth)},
                ) as client:
                    r = await client.get(url, timeout=15)
                    if r.status_code == 200 and r.content:
                        (js_dir / f"{i}.js").write_bytes(r.content[:2_000_000])
                        downloaded += 1
            except Exception:
                pass

    await asyncio.gather(*(fetch(i, u) for i, u in enumerate(urls)))

    if downloaded == 0:
        return {"ok": True, "files_scanned": 0, "secrets_found": 0,
                "note": "no JS files could be downloaded"}

    result = await run_tool(
        ["trufflehog", "filesystem", str(js_dir), "--json", "--no-update"],
        timeout_s=settings.timeout_for("trufflehog"),
    )
    if not result.ok and "not installed" in (result.note or ""):
        return {
            "ok": False,
            "error": "trufflehog not available — run in the Docker image",
            "note": result.note,
        }

    secrets = []
    by_detector: dict[str, int] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = d.get("DetectorName") or d.get("DetectorType") or "unknown"
        if detector == "unknown" and "SourceMetadata" not in d:
            continue  # skip non-finding log lines
        secrets.append({
            "detector": detector,
            "verified": d.get("Verified", False),
            "redacted": (d.get("Redacted") or d.get("Raw") or "")[:60],
        })
        by_detector[detector] = by_detector.get(detector, 0) + 1

    workspace.write_json(OUT_FILE, secrets)
    shutil.rmtree(js_dir, ignore_errors=True)

    return {
        "ok": True,
        "files_scanned": downloaded,
        "secrets_found": len(secrets),
        "by_detector": by_detector,
        "verified": sum(1 for s in secrets if s["verified"]),
        "output_file": str(workspace.path(OUT_FILE)),
        "sample": secrets[:10],
        "note": "no secrets found" if not secrets else "",
    }
