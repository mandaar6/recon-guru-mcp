"""Runtime configuration — everything a cloner can tune without touching code.

All settings are read from environment variables (and, if present, a `.env`
file at the project root), with safe defaults baked in. This is the single place
that knows about timeouts, limits, politeness, wordlists, and optional API keys.

Why env + .env rather than hardcoded constants:
  * a cloner configures the server by copying `.env.example` to `.env` — no code
    edits, no fork;
  * secrets (API keys) live in `.env`, which is git-ignored, so they never land
    in the repo;
  * the same variables work when the server runs in Docker (pass `--env-file`)
    or under a harness (set them in the MCP client config's `env` block).

Every variable is namespaced with the `RECONGURU_` prefix so it can't collide
with other tools' environment (e.g. `RECONGURU_SHODAN_API_KEY`, not a bare
`SHODAN_API_KEY`). See `.env.example` for the full documented list.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# httpx logs every request URL at INFO. That's noise, and a Shodan-style
# key-in-URL would otherwise land in the server's stderr logs — so silence it.
logging.getLogger("httpx").setLevel(logging.WARNING)


class Settings(BaseSettings):
    """Typed, validated configuration loaded from the environment / `.env`."""

    model_config = SettingsConfigDict(
        env_prefix="RECONGURU_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",            # unknown env vars are ignored, not fatal
        case_sensitive=False,
    )

    # --- Transport -------------------------------------------------------
    # "stdio" (default, harness-launched) or "http" (shared/remote).
    transport: str = "stdio"
    # Bearer token required on the HTTP endpoint (blank = unauthenticated —
    # only safe behind network isolation / a reverse proxy). HTTP mode only.
    http_auth_token: str = ""
    http_host: str = "127.0.0.1"   # bind loopback by default, not 0.0.0.0
    http_port: int = 8000

    # --- Sandbox runner --------------------------------------------------
    # Default per-tool-call wall-clock budget. Heavy tools override this via
    # `timeout_for()` below (e.g. nuclei) or by passing timeout_s explicitly.
    default_timeout_s: int = 300
    # Characters of stdout+stderr returned to the harness (bulk data goes to
    # the workspace file instead, so this only caps the *envelope*).
    max_output_chars: int = 100_000

    # --- Politeness / concurrency ---------------------------------------
    max_concurrency: int = 20          # max parallel sub-requests inside a tool
    rate_limit_ms: int = 0             # delay between a tool's own requests
    stealth: bool = False              # slower, jittered, quieter when true
    user_agent: str = "reconguru-mcp/0.1 (+authorized-testing)"

    # Authenticated recon: one or more raw HTTP header lines (newline-separated)
    # that HTTP tools inject, e.g. "Cookie: session=…" or "Authorization:
    # Bearer …". Kept in .env (git-ignored) and never logged. The toolkit never
    # logs in — the user supplies a session captured in their own/the harness's
    # browser. A tool's per-call `auth` argument overrides this.
    auth_header: str = ""

    # --- Workspace -------------------------------------------------------
    # Where tools read/write shared data. Matches the Docker VOLUME.
    workspace_dir: str = "/workspace"

    # --- Wordlists (paths inside the image / host) -----------------------
    dns_wordlist: str = "/opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    content_wordlist: str = "/opt/seclists/Discovery/Web-Content/common.txt"

    # --- nuclei ----------------------------------------------------------
    nuclei_severity: str = ""          # e.g. "medium,high,critical" ("" = all)
    nuclei_templates: str = ""         # custom template dir ("" = built-in)

    # --- Optional API keys (blank = that source is skipped) --------------
    shodan_api_key: str = Field(default="")
    virustotal_api_key: str = Field(default="")
    securitytrails_api_key: str = Field(default="")
    urlscan_api_key: str = Field(default="")
    censys_api_id: str = Field(default="")
    censys_api_secret: str = Field(default="")
    github_token: str = Field(default="")
    chaos_api_key: str = Field(default="")
    nvd_api_key: str = Field(default="")  # lifts NVD rate limits for exploit_lookup

    # --------------------------------------------------------------------
    def timeout_for(self, tool: str) -> int:
        """Per-tool timeout.

        Looks for a `RECONGURU_TIMEOUT_<TOOL>` override (e.g.
        `RECONGURU_TIMEOUT_NUCLEI=1800`); otherwise uses a built-in default
        that is generous for known-heavy tools, falling back to
        `default_timeout_s`.
        """
        override = os.getenv(f"RECONGURU_TIMEOUT_{tool.upper()}")
        if override and override.strip().isdigit():
            return int(override.strip())
        return _HEAVY_TOOL_TIMEOUTS.get(tool.lower(), self.default_timeout_s)


# Sensible per-tool budgets so one global 300s doesn't starve a big scan or
# make a quick lookup wait. Overridable per tool via RECONGURU_TIMEOUT_<TOOL>.
_HEAVY_TOOL_TIMEOUTS: dict[str, int] = {
    "nuclei": 1800,       # templated scan over many hosts
    "ffuf": 900,          # content discovery with a real wordlist
    "katana": 600,        # crawl
    "naabu": 600,         # full-range port sweep
    "httpx": 600,         # rich probe over many hosts
    "dnsx": 300,
    "gau": 300,           # historical URL fetch
    "subfinder": 180,
    "arjun": 600,         # param discovery sends many probes
    "trufflehog": 300,    # secret scan over downloaded JS
    "wafw00f": 120,
}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide Settings (loaded once, cached)."""
    return Settings()


# Convenience module-level handle.
settings = get_settings()
