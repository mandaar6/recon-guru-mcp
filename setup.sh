#!/usr/bin/env bash
#
# reconguru-mcp — one-time setup (macOS / Linux / WSL).
# Windows (native PowerShell) users: run  setup.ps1  instead.
#
# What this does, interactively:
#   1. checks Docker, builds the image if it's missing
#   2. asks for a WORKSPACE folder on your machine (mandatory) — this is where
#      scope lists go in and scan results come out, so they're always yours,
#      editable with any text editor, and NOT trapped inside the container
#   3. creates .env from .env.example (optionally collects API keys)
#   4. wires your harness to the server (or prints the exact config to paste)
#
# Re-running is safe: it won't clobber an existing .env or your scope files.

set -euo pipefail

IMAGE="reconguru-mcp:latest"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '%s\n' "$*"; }
head() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ask "prompt" "default" -> echoes the answer (default used on empty input)
ask() {
  local prompt="$1" default="${2-}" ans
  if [ -n "$default" ]; then
    read -r -p "$prompt [$default]: " ans || true
    printf '%s' "${ans:-$default}"
  else
    read -r -p "$prompt: " ans || true
    printf '%s' "$ans"
  fi
}

head "reconguru-mcp setup"

# ---------------------------------------------------------------- 1. Docker ---
if ! command -v docker >/dev/null 2>&1; then
  say "ERROR: 'docker' is not on your PATH. Install Docker, start it, then re-run."
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  say "ERROR: Docker is installed but not running. Start Docker Desktop / the daemon and re-run."
  exit 1
fi

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  say "✓ Image '$IMAGE' is already built."
else
  say "Image '$IMAGE' is not built yet."
  case "$(ask "Build it now? (Y/n)" "Y")" in
    [Nn]*) say "Skipped. Build later with:  docker build -t $IMAGE \"$REPO_DIR\"" ;;
    *)     docker build -t "$IMAGE" "$REPO_DIR" ;;
  esac
fi

# ------------------------------------------------------------- 2. Workspace ---
head "Workspace folder (required)"
say "Scope lists and every scan's output live here, on your machine."
default_ws="$HOME/reconguru-workspace"
ws=""
while [ -z "$ws" ]; do
  ws="$(ask "Workspace path" "$default_ws")"
  [ -z "$ws" ] && say "A workspace path is required."
done
ws="${ws/#\~/$HOME}"                 # expand a leading ~
mkdir -p "$ws"
ws="$(cd "$ws" && pwd)"              # make absolute (Docker needs an absolute path)
say "✓ Workspace: $ws"

# Seed EMPTY scope files. Empty = "scan anything not excluded" (scope is opt-in);
# a non-empty include list means ONLY those patterns are in scope.
[ -f "$ws/scope_include.txt" ] || : > "$ws/scope_include.txt"
[ -f "$ws/scope_exclude.txt" ] || : > "$ws/scope_exclude.txt"
say "✓ Scope files ready (one pattern per line, e.g. *.example.com or 192.0.2.0/24):"
say "    $ws/scope_include.txt   (allowlist — empty means allow all)"
say "    $ws/scope_exclude.txt   (denylist)"

# ------------------------------------------------------------------- 3. .env ---
head "Settings & API keys (.env)"
ENV_PATH="$REPO_DIR/.env"
if [ -f "$ENV_PATH" ]; then
  say "✓ .env already exists ($ENV_PATH) — leaving it as-is."
else
  cp "$REPO_DIR/.env.example" "$ENV_PATH"
  say "✓ Created $ENV_PATH from .env.example (git-ignored, so keys stay out of the repo)."
  case "$(ask "Enter API keys now? They're all optional (y/N)" "N")" in
    [Yy]*)
      {
        printf '\n# --- keys added by setup (%s) ---\n' "$(date -u +%FT%TZ 2>/dev/null || date)"
        # Read the key list on fd 3 so `ask` (which reads real stdin on fd 0)
        # doesn't swallow these lines instead of the user's typed value.
        while IFS='|' read -r var label <&3; do
          val="$(ask "  $label (Enter to skip)" "")"
          [ -n "$val" ] && printf 'RECONGURU_%s=%s\n' "$var" "$val"
        done 3<<'KEYS'
SHODAN_API_KEY|Shodan
VIRUSTOTAL_API_KEY|VirusTotal
SECURITYTRAILS_API_KEY|SecurityTrails
URLSCAN_API_KEY|URLScan
CENSYS_API_ID|Censys API ID
CENSYS_API_SECRET|Censys API secret
GITHUB_TOKEN|GitHub token
CHAOS_API_KEY|Chaos (ProjectDiscovery)
NVD_API_KEY|NVD (lifts CVE lookup limits)
KEYS
      } >> "$ENV_PATH"
      say "✓ Keys written to $ENV_PATH."
      ;;
    *) say "Skipped — the toolkit works without keys (those sources are just skipped)." ;;
  esac
  say "  Edit $ENV_PATH any time to add/change keys or timeouts."
fi

# -------------------------------------------------------------- 4. Harness ---
# Everything below is derived from two absolute paths: the workspace and .env.
# The docker args are identical across harnesses — only the file FORMAT differs.
HARDEN='"--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","512","--memory","2g","--cpus","2"'

json_block() {
  cat <<JSON
{
  "mcpServers": {
    "reconguru": {
      "command": "docker",
      "args": ["run","-i","--rm",
               $HARDEN,
               "-v","$ws:/workspace",
               "--env-file","$ENV_PATH",
               "reconguru-mcp:latest"]
    }
  }
}
JSON
}

toml_block() {
  cat <<TOML
[mcp_servers.reconguru]
command = "docker"
args = ["run","-i","--rm",
        $HARDEN,
        "-v","$ws:/workspace",
        "--env-file","$ENV_PATH",
        "reconguru-mcp:latest"]
TOML
}

cli_cmd=(claude mcp add reconguru -- docker run -i --rm
         --cap-drop ALL --security-opt no-new-privileges
         --pids-limit 512 --memory 2g --cpus 2
         -v "$ws:/workspace" --env-file "$ENV_PATH" "$IMAGE")

SNIPPET="$ws/reconguru-mcp-config.txt"
{ say "# reconguru-mcp — MCP server config (generated by setup)"; say ""; json_block; } > "$SNIPPET"

head "Connect your harness"
say "  1) Claude Code (CLI)"
say "  2) Claude Desktop"
say "  3) Cursor"
say "  4) Codex"
say "  5) Other / just show me the config"
case "$(ask "Which harness?" "1")" in
  1)
    if command -v claude >/dev/null 2>&1; then
      say "Running: claude mcp add reconguru -- docker run ... (hardened)"
      "${cli_cmd[@]}"
      say "✓ Added to Claude Code. Start a new session and ask it to recon an authorized target."
    else
      say "The 'claude' CLI isn't on your PATH. Run this yourself:"
      printf '  %q ' "${cli_cmd[@]}"; echo
    fi
    ;;
  2) say "Paste this into claude_desktop_config.json"
     say "  (macOS: ~/Library/Application Support/Claude/  |  Windows: %APPDATA%\\Claude\\):"
     json_block ;;
  3) say "Paste this into .cursor/mcp.json in your project:"; json_block ;;
  4) say "Add this to ~/.codex/config.toml:"; toml_block ;;
  *) say "Generic MCP config (command = docker, args as below) — put it in your harness's MCP config:"
     json_block ;;
esac

head "Done"
say "A copy of the JSON config is saved at: $SNIPPET"
say "Edit scope lists any time at:          $ws/scope_include.txt"
say "Scan results (report.html, findings.json, …) will appear in: $ws"
