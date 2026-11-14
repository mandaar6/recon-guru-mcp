# reconguru-mcp sandbox image.
#
# Everything — the MCP server AND the recon tool binaries — runs inside this
# container. On any host (Windows via WSL2, macOS, Linux) the tools execute in
# an isolated Linux sandbox with no access to the host filesystem.
#
# Stage 1 shipped the server + the nmap tool. This image bakes nmap in so a
# real scan actually runs. More tool binaries get added here as the registry
# grows (Stage 3+).

FROM python:3.12-slim

# ---- OS packages: the recon tool binaries -------------------------------------
# Add new tools' apt packages here (this is the "sudo apt install" step).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- Non-root user ------------------------------------------------------------
# Tools run as an unprivileged user. (A non-privileged nmap uses a TCP connect
# scan automatically; SYN scans like -sS need --cap-add=NET_RAW at run time.)
RUN useradd --create-home --uid 1000 recon

WORKDIR /app

# ---- Python dependencies (cached layer) ---------------------------------------
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

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
