"""The sandbox runner — how every tool actually executes.

A tool function assembles an argument *list* (binary + flags + target) and
hands it to `run_tool()`. This module runs that binary as a subprocess,
captures stdout/stderr, enforces a timeout, and caps the output size.

Key safety properties:
  * Commands are run with an argument LIST and never through a shell
    (no `shell=True`), so there is no shell for a target/flag to inject into.
  * A per-call timeout kills runaway or hung scans.
  * Output is capped so a huge scan can't blow up the harness context.

In Stage 1 this runs on the host (wherever the server runs). In Stage 2 the
whole server — this runner included — runs inside a Docker container, so the
binaries execute in an isolated, no-host-access Linux sandbox.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass

from .config import settings

# Fallback constants if settings are unavailable; normally the configured
# values in `settings` win (see run_tool).
DEFAULT_TIMEOUT_S = 300          # 5 minutes per tool call
DEFAULT_MAX_OUTPUT = 100_000     # characters of stdout+stderr kept


@dataclass
class ToolResult:
    """Structured result of running one external tool."""

    ok: bool
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    truncated: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "command": " ".join(self.command),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_s": round(self.duration_s, 2),
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "note": self.note,
        }


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    """Keep the head and tail of long output (results often live at the end)."""
    if len(text) <= limit:
        return text, False
    head = limit // 2
    tail = limit - head
    omitted = len(text) - head - tail
    return (
        text[:head]
        + f"\n\n...[{omitted} characters omitted]...\n\n"
        + text[-tail:],
        True,
    )


async def run_tool(
    argv: list[str],
    *,
    timeout_s: int | None = None,
    max_output: int | None = None,
    cwd: str | None = None,
) -> ToolResult:
    """Run `argv` as a subprocess and return a ToolResult.

    `argv[0]` is the binary name; it is resolved on PATH. If the binary is not
    installed, a clear, non-crashing ToolResult is returned so the agent can
    react instead of the server erroring out.

    `timeout_s` and `max_output` default to the configured values in
    `settings` (RECONGURU_DEFAULT_TIMEOUT_S / RECONGURU_MAX_OUTPUT_CHARS). A
    tool can pass an explicit value — e.g. `settings.timeout_for("nuclei")` —
    to override per call.
    """
    if timeout_s is None:
        timeout_s = settings.default_timeout_s
    if max_output is None:
        max_output = settings.max_output_chars

    if not argv:
        return ToolResult(
            ok=False, command=[], exit_code=None, stdout="", stderr="empty command",
            duration_s=0.0, note="no command was provided",
        )

    binary = argv[0]
    if shutil.which(binary) is None:
        return ToolResult(
            ok=False,
            command=argv,
            exit_code=None,
            stdout="",
            stderr=f"binary not found on PATH: {binary}",
            duration_s=0.0,
            note=(
                f"'{binary}' is not installed in this environment. Install it on "
                f"the host (Stage 1) or bake it into the Docker image (Stage 2)."
            ),
        )

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except OSError as e:
        return ToolResult(
            ok=False, command=argv, exit_code=None, stdout="", stderr=str(e),
            duration_s=time.monotonic() - start, note=f"failed to start process: {e}",
        )

    timed_out = False
    try:
        raw_out, raw_err = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        try:
            raw_out, raw_err = await proc.communicate()
        except Exception:
            raw_out, raw_err = b"", b""

    duration = time.monotonic() - start
    stdout = (raw_out or b"").decode("utf-8", errors="replace")
    stderr = (raw_err or b"").decode("utf-8", errors="replace")

    stdout, t1 = _truncate(stdout, max_output)
    stderr, t2 = _truncate(stderr, max_output)

    exit_code = proc.returncode
    note = ""
    if timed_out:
        note = f"timed out after {timeout_s}s and was killed"
    ok = (not timed_out) and (exit_code == 0)

    return ToolResult(
        ok=ok,
        command=argv,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        timed_out=timed_out,
        truncated=t1 or t2,
        note=note,
    )
