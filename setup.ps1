<#
  reconguru-mcp - one-time setup (Windows / PowerShell).
  macOS / Linux / WSL users: run  ./setup.sh  instead.

  What this does, interactively:
    1. checks Docker, builds the image if it's missing
    2. asks for a WORKSPACE folder on your machine (mandatory) - scope lists go
       in and scan results come out there, so they're always yours, editable in
       any text editor, and NOT trapped inside the container
    3. creates .env from .env.example (optionally collects API keys)
    4. wires your harness to the server (or prints the exact config to paste)

  Re-running is safe: it won't clobber an existing .env or your scope files.

  If PowerShell blocks the script, run it as:
    powershell -ExecutionPolicy Bypass -File .\setup.ps1
#>

$ErrorActionPreference = "Stop"
$Image   = "reconguru-mcp:latest"
$RepoDir = $PSScriptRoot

function Head($t) { Write-Host ""; Write-Host $t -ForegroundColor Cyan }
function Ask($prompt, $default) {
  if ($default) {
    $a = Read-Host "$prompt [$default]"
    if ([string]::IsNullOrWhiteSpace($a)) { return $default } else { return $a }
  } else {
    return Read-Host $prompt
  }
}
# Docker on Windows takes forward-slash absolute paths fine (C:/Users/me/ws).
function DockerPath($p) { return ($p -replace '\\','/') }

Head "reconguru-mcp setup"

# ---------------------------------------------------------------- 1. Docker ---
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "ERROR: 'docker' is not on your PATH. Install Docker Desktop, start it, then re-run." -ForegroundColor Red
  exit 1
}
docker info *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Host "ERROR: Docker is installed but not running. Start Docker Desktop and re-run." -ForegroundColor Red
  exit 1
}

docker image inspect $Image *> $null
if ($LASTEXITCODE -eq 0) {
  Write-Host "OK  Image '$Image' is already built."
} else {
  Write-Host "Image '$Image' is not built yet."
  if ((Ask "Build it now? (Y/n)" "Y") -notmatch '^[Nn]') {
    docker build -t $Image $RepoDir
    if ($LASTEXITCODE -ne 0) { Write-Host "Build failed." -ForegroundColor Red; exit 1 }
  } else {
    Write-Host "Skipped. Build later with:  docker build -t $Image `"$RepoDir`""
  }
}

# ------------------------------------------------------------- 2. Workspace ---
Head "Workspace folder (required)"
Write-Host "Scope lists and every scan's output live here, on your machine."
$defaultWs = Join-Path $HOME "reconguru-workspace"
$ws = ""
while ([string]::IsNullOrWhiteSpace($ws)) {
  $ws = Ask "Workspace path" $defaultWs
  if ([string]::IsNullOrWhiteSpace($ws)) { Write-Host "A workspace path is required." }
}
New-Item -ItemType Directory -Force -Path $ws | Out-Null
$ws = (Resolve-Path $ws).Path
$wsD = DockerPath $ws
Write-Host "OK  Workspace: $ws"

# Seed EMPTY scope files. Empty = "scan anything not excluded" (scope is opt-in);
# a non-empty include list means ONLY those patterns are in scope.
foreach ($f in @("scope_include.txt","scope_exclude.txt")) {
  $p = Join-Path $ws $f
  if (-not (Test-Path $p)) { New-Item -ItemType File -Path $p | Out-Null }
}
Write-Host "OK  Scope files ready (one pattern per line, e.g. *.example.com or 192.0.2.0/24):"
Write-Host "      $ws\scope_include.txt   (allowlist - empty means allow all)"
Write-Host "      $ws\scope_exclude.txt   (denylist)"

# ------------------------------------------------------------------- 3. .env ---
Head "Settings & API keys (.env)"
$EnvPath = Join-Path $RepoDir ".env"
$EnvD    = DockerPath $EnvPath
if (Test-Path $EnvPath) {
  Write-Host "OK  .env already exists ($EnvPath) - leaving it as-is."
} else {
  Copy-Item (Join-Path $RepoDir ".env.example") $EnvPath
  Write-Host "OK  Created $EnvPath from .env.example (git-ignored, so keys stay out of the repo)."
  if ((Ask "Enter API keys now? They're all optional (y/N)" "N") -match '^[Yy]') {
    $keys = [ordered]@{
      "SHODAN_API_KEY"         = "Shodan"
      "VIRUSTOTAL_API_KEY"     = "VirusTotal"
      "SECURITYTRAILS_API_KEY" = "SecurityTrails"
      "URLSCAN_API_KEY"        = "URLScan"
      "CENSYS_API_ID"          = "Censys API ID"
      "CENSYS_API_SECRET"      = "Censys API secret"
      "GITHUB_TOKEN"           = "GitHub token"
      "CHAOS_API_KEY"          = "Chaos (ProjectDiscovery)"
      "NVD_API_KEY"            = "NVD (lifts CVE lookup limits)"
    }
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Add-Content -Path $EnvPath -Encoding utf8 -Value "`n# --- keys added by setup ($stamp) ---"
    foreach ($var in $keys.Keys) {
      $val = Ask "  $($keys[$var]) (Enter to skip)" ""
      if (-not [string]::IsNullOrWhiteSpace($val)) {
        Add-Content -Path $EnvPath -Encoding utf8 -Value "RECONGURU_$var=$val"
      }
    }
    Write-Host "OK  Keys written to $EnvPath."
  } else {
    Write-Host "Skipped - the toolkit works without keys (those sources are just skipped)."
  }
  Write-Host "  Edit $EnvPath any time to add/change keys or timeouts."
}

# -------------------------------------------------------------- 4. Harness ---
# The docker args are identical across harnesses - only the file FORMAT differs.
$harden = '"--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","512","--memory","2g","--cpus","2"'

function JsonBlock {
@"
{
  "mcpServers": {
    "reconguru": {
      "command": "docker",
      "args": ["run","-i","--rm",
               $harden,
               "-v","$($wsD):/workspace",
               "--env-file","$EnvD",
               "reconguru-mcp:latest"]
    }
  }
}
"@
}

function TomlBlock {
@"
[mcp_servers.reconguru]
command = "docker"
args = ["run","-i","--rm",
        $harden,
        "-v","$($wsD):/workspace",
        "--env-file","$EnvD",
        "reconguru-mcp:latest"]
"@
}

$cliArgs = @("mcp","add","reconguru","--","docker","run","-i","--rm",
             "--cap-drop","ALL","--security-opt","no-new-privileges",
             "--pids-limit","512","--memory","2g","--cpus","2",
             "-v","$($wsD):/workspace","--env-file",$EnvD,$Image)

$snippet = Join-Path $ws "reconguru-mcp-config.txt"
"# reconguru-mcp - MCP server config (generated by setup)`n`n$(JsonBlock)" |
  Out-File -FilePath $snippet -Encoding utf8

Head "Connect your harness"
Write-Host "  1) Claude Code (CLI)"
Write-Host "  2) Claude Desktop"
Write-Host "  3) Cursor"
Write-Host "  4) Codex"
Write-Host "  5) Other / just show me the config"
switch (Ask "Which harness?" "1") {
  "1" {
    if (Get-Command claude -ErrorAction SilentlyContinue) {
      Write-Host "Running: claude mcp add reconguru -- docker run ... (hardened)"
      & claude @cliArgs
      Write-Host "OK  Added to Claude Code. Start a new session and ask it to recon an authorized target."
    } else {
      Write-Host "The 'claude' CLI isn't on your PATH. Run this yourself:"
      Write-Host ("  claude " + ($cliArgs -join " "))
    }
  }
  "2" { Write-Host "Paste this into claude_desktop_config.json (Windows: %APPDATA%\Claude\):"; JsonBlock }
  "3" { Write-Host "Paste this into .cursor\mcp.json in your project:"; JsonBlock }
  "4" { Write-Host "Add this to ~/.codex/config.toml:"; TomlBlock }
  default { Write-Host "Generic MCP config (command = docker, args as below):"; JsonBlock }
}

Head "Done"
Write-Host "A copy of the JSON config is saved at: $snippet"
Write-Host "Edit scope lists any time at:          $ws\scope_include.txt"
Write-Host "Scan results (report.html, findings.json, ...) will appear in: $ws"
