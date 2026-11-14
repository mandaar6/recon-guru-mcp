# reconguru-mcp sandbox image.
#
# Everything — the MCP server AND the recon tool binaries — runs inside this
# container. On any host (Windows via WSL2, macOS, Linux) the tools execute in
# an isolated Linux sandbox with no access to the host filesystem.
#
# Multi-stage: a Go builder compiles the ProjectDiscovery tools, then a slim
# runtime image carries the server plus every recon binary the ported tools
# use. Tools that still lack a binary here degrade gracefully (the sandbox
# runner reports "binary not found" instead of crashing).

# ---- Builder: compile the ProjectDiscovery Go tools --------------------------
FROM golang:1.23-bookworm AS gobuild
# naabu links libpcap (CGO) for its scans.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
# GOTOOLCHAIN=auto lets `go install` download the newer Go toolchain that
# recent naabu/nuclei require, instead of failing on the base image's version.
ENV CGO_ENABLED=1 GOBIN=/out GOTOOLCHAIN=auto
RUN mkdir -p /out \
    # @latest keeps the build working without chasing exact tags; pin these to
    # specific versions for reproducible production images.
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/ffuf/ffuf/v2@latest

# ---- Runtime image -----------------------------------------------------------
FROM python:3.12-slim

# OS packages: recon tool binaries + runtime libs.
#   nmap     — service/version detection (port_scan)
#   libpcap  — naabu runtime dependency
#   git/curl — fetch the exploit DB and wordlists below
# (tech fingerprinting is now httpx -td; whatweb/Ruby dropped to slim the image.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        libpcap0.8 \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# searchsploit (ExploitDB) for exploit_lookup's local matches — shallow clone.
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# trufflehog (secret scanning) — official install script fetches the prebuilt binary.
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin

# Wordlists: only the two defaults reconguru-mcp references (not all ~1GB of
# SecLists). Cloners who want the full set can mount it and point the
# RECONGURU_*_WORKLIST vars at it.
RUN mkdir -p /opt/seclists/Discovery/DNS /opt/seclists/Discovery/Web-Content \
    && curl -fsSL -o /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
    && curl -fsSL -o /opt/seclists/Discovery/Web-Content/common.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

# ---- Non-root user ------------------------------------------------------------
# Tools run unprivileged. nmap/naabu fall back to TCP connect scans; SYN scans
# (-sS) need --cap-add=NET_RAW at run time.
RUN useradd --create-home --uid 1000 recon

WORKDIR /app

# ---- Python dependencies (cached layer) ---------------------------------------
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ProjectDiscovery binaries from the builder stage. These MUST land after the
# pip install: the python `httpx` library (a dependency) ships its own `httpx`
# console script to /usr/local/bin, which would otherwise clobber the PD httpx
# binary. Copying here lets the PD tool win on PATH (the python httpx library
# is still importable; only its CLI stub is replaced).
COPY --from=gobuild /out/naabu /usr/local/bin/naabu
COPY --from=gobuild /out/nuclei /usr/local/bin/nuclei
COPY --from=gobuild /out/httpx /usr/local/bin/httpx
COPY --from=gobuild /out/katana /usr/local/bin/katana
COPY --from=gobuild /out/dnsx /usr/local/bin/dnsx
COPY --from=gobuild /out/gau /usr/local/bin/gau
COPY --from=gobuild /out/ffuf /usr/local/bin/ffuf

# Python-based recon CLIs (small): wafw00f (WAF detect), arjun (param discovery).
RUN pip install --no-cache-dir wafw00f arjun

# ---- Application --------------------------------------------------------------
COPY pyproject.toml ./
COPY reconguru_mcp ./reconguru_mcp
COPY tests ./tests

# ---- Workspace: where tools read/write scan results ---------------------------
RUN mkdir -p /workspace && chown recon:recon /workspace
VOLUME ["/workspace"]

USER recon
ENV RECONGURU_TRANSPORT=stdio \
    PYTHONUNBUFFERED=1

# Default: run the MCP server over stdio. A harness launches this with
#   docker run -i --rm reconguru-mcp
# Override the entrypoint to run other commands, e.g. the smoke test:
#   docker run --rm --entrypoint python reconguru-mcp tests/smoke_test.py
ENTRYPOINT ["python", "-m", "reconguru_mcp"]
