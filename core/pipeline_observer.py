"""
PipelineObserver — Real-time observability + evidence audit for ZeroKit pipeline.

Features:
  1. Real-time terminal display: phase banners, per-tool result lines, phase summaries
  2. Exit Code Gate: tool findings are ONLY accepted if exit_code == 0
  3. Audit file: storage/audits/run_{timestamp}.json with full evidence trail

Usage in Orchestrator:
    observer = PipelineObserver(repo_path=context.repo_path)
    context.observer = observer

    # In each phase:
    with observer.phase(4, "Detection"):
        result = observer.record_tool(
            tool="semgrep",
            command="semgrep --config ...",
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            findings=findings_list,
        )
        if result.accepted:  # Only True if exit_code == 0
            context.static_findings.extend(result.findings)

    observer.write_audit()
"""

import os
import sys
import json
import hashlib
import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# ANSI color codes for terminal (auto-disabled if not a TTY)
# ═══════════════════════════════════════════════════════════════════
_IS_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    if not _IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"

BOLD   = lambda t: _c("1", t)
GREEN  = lambda t: _c("32", t)
YELLOW = lambda t: _c("33", t)
RED    = lambda t: _c("31", t)
CYAN   = lambda t: _c("36", t)
DIM    = lambda t: _c("2", t)
BLUE   = lambda t: _c("34", t)


# ═══════════════════════════════════════════════════════════════════
# Data models for audit trail
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ToolEvidence:
    """Immutable evidence record for one tool invocation."""
    tool: str
    command: str
    exit_code: int
    accepted: bool          # True only if exit_code == 0
    stdout_hash: str        # SHA256 of raw stdout (anti-tamper)
    stderr_snippet: str     # First 500 chars of stderr
    finding_count: int
    finding_ids: List[str]
    duration_sec: float
    timestamp: str


@dataclass
class PhaseAudit:
    """Audit record for one pipeline phase."""
    phase: int
    name: str
    status: str             # RUNNING | COMPLETED | FAILED | SKIPPED
    started_at: str
    ended_at: Optional[str] = None
    duration_sec: float = 0.0
    tools: List[ToolEvidence] = field(default_factory=list)
    total_findings: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class ToolResult:
    """Return value from observer.record_tool() — tells caller if findings are accepted."""
    accepted: bool
    findings: List[Any]
    evidence: ToolEvidence


# ═══════════════════════════════════════════════════════════════════
# PipelineObserver
# ═══════════════════════════════════════════════════════════════════

class PipelineObserver:
    """
    Central observability hub for the ZeroKit pipeline.

    All tool calls MUST go through record_tool() to be part of the
    official evidence trail. Any finding not registered here is invalid.
    """

    AUDIT_DIR = os.path.join("storage", "audits")

    def __init__(self, repo_path: str, run_id: str = None):
        self.repo_path = repo_path
        self.run_id = run_id or f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._phases: List[PhaseAudit] = []
        self._current_phase: Optional[PhaseAudit] = None
        self._phase_start_ts: float = 0.0
        os.makedirs(self.AUDIT_DIR, exist_ok=True)

        self._print_header()

    # ─────────────────────────────────────────────────────────
    # Terminal display
    # ─────────────────────────────────────────────────────────

    def _print_header(self):
        width = 70
        print()
        print(BOLD(CYAN("═" * width)))
        print(BOLD(CYAN(f"  ZeroKit Pipeline Run: {self.run_id}")))
        print(BOLD(CYAN(f"  Repo: {self.repo_path}")))
        print(BOLD(CYAN("═" * width)))
        print()

    def _print_phase_banner(self, phase: int, name: str):
        label = f" Phase {phase}: {name} "
        pad = "─" * max(0, 68 - len(label))
        print(BOLD(BLUE(f"\n┌{'─' * 68}┐")))
        print(BOLD(BLUE(f"│{label:<68}│")))
        print(BOLD(BLUE(f"└{'─' * 68}┘")))

    def _print_tool_result(self, tool: str, command: str, exit_code: int,
                           accepted: bool, finding_count: int, duration: float):
        status_icon = GREEN("✅ PASS") if accepted else RED("❌ GATE FAIL")
        exit_str    = GREEN(f"exit:{exit_code}") if exit_code == 0 else RED(f"exit:{exit_code}")
        count_str   = YELLOW(f"{finding_count} findings") if finding_count > 0 else DIM("0 findings")
        dur_str     = DIM(f"{duration:.1f}s")

        print(f"  {status_icon}  {BOLD(tool):<20} {exit_str}  {count_str}  {dur_str}")
        print(f"  {DIM('cmd:')} {DIM(command[:100])}")

    def _print_phase_summary(self, phase: PhaseAudit):
        total = phase.total_findings
        status_str = GREEN("COMPLETED") if phase.status == "COMPLETED" else RED(phase.status)
        print(f"\n  {DIM('─' * 66)}")
        print(f"  Phase {phase.phase} {status_str} │ "
              f"Tools: {BOLD(str(len(phase.tools)))} │ "
              f"Findings accepted: {YELLOW(str(total))} │ "
              f"Duration: {DIM(f'{phase.duration_sec:.1f}s')}")
        print()

    # ─────────────────────────────────────────────────────────
    # Context manager: phase()
    # ─────────────────────────────────────────────────────────

    @contextmanager
    def phase(self, phase_num: int, phase_name: str):
        """
        Context manager for a pipeline phase.

        Usage:
            with observer.phase(4, "Detection"):
                result = observer.record_tool(...)
        """
        audit = PhaseAudit(
            phase=phase_num,
            name=phase_name,
            status="RUNNING",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._current_phase = audit
        self._phase_start_ts = time.monotonic()
        self._phases.append(audit)

        self._print_phase_banner(phase_num, phase_name)
        logger.info(f"[Observer] Phase {phase_num}: {phase_name} started")

        try:
            yield audit
            audit.status = "COMPLETED"
        except Exception as e:
            audit.status = "FAILED"
            audit.notes.append(f"Exception: {str(e)}")
            logger.error(f"[Observer] Phase {phase_num} FAILED: {e}")
            raise
        finally:
            elapsed = time.monotonic() - self._phase_start_ts
            audit.duration_sec = round(elapsed, 2)
            audit.ended_at = datetime.now(timezone.utc).isoformat()
            audit.total_findings = sum(t.finding_count for t in audit.tools if t.accepted)
            self._current_phase = None
            self._print_phase_summary(audit)

    # ─────────────────────────────────────────────────────────
    # Exit Code Gate: record_tool()
    # ─────────────────────────────────────────────────────────

    def record_tool(
        self,
        tool: str,
        command: str,
        exit_code: int,
        stdout: str = "",
        stderr: str = "",
        findings: List[Any] = None,
    ) -> ToolResult:
        """
        Register a tool invocation. ONLY accepts findings if exit_code == 0.

        >>> result = observer.record_tool("semgrep", cmd, proc.returncode, stdout, stderr, raw_findings)
        >>> if result.accepted:
        ...     context.static_findings.extend(result.findings)

        Returns ToolResult with:
          - accepted: True only if exit_code == 0
          - findings: the findings list (empty if not accepted)
          - evidence: the ToolEvidence record
        """
        findings = findings or []
        t_start = time.monotonic()

        # EXIT CODE GATE
        accepted = (exit_code == 0)
        accepted_findings = findings if accepted else []

        if not accepted:
            logger.warning(
                f"[EvidenceGate] Tool '{tool}' exited with code {exit_code} — "
                f"{len(findings)} raw finding(s) REJECTED. No findings admitted."
            )

        # Build evidence record
        stdout_hash = hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest()
        evidence = ToolEvidence(
            tool=tool,
            command=command,
            exit_code=exit_code,
            accepted=accepted,
            stdout_hash=f"sha256:{stdout_hash}",
            stderr_snippet=stderr[:500] if stderr else "",
            finding_count=len(accepted_findings),
            finding_ids=[getattr(f, "id", str(i)) for i, f in enumerate(accepted_findings)],
            duration_sec=round(time.monotonic() - t_start, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Attach to current phase
        if self._current_phase:
            self._current_phase.tools.append(evidence)
        else:
            logger.warning(f"[Observer] record_tool('{tool}') called outside a phase context!")

        # Display
        self._print_tool_result(
            tool=tool,
            command=command,
            exit_code=exit_code,
            accepted=accepted,
            finding_count=len(accepted_findings),
            duration=evidence.duration_sec,
        )

        return ToolResult(accepted=accepted, findings=accepted_findings, evidence=evidence)

    def note(self, message: str):
        """Add a note to the current phase audit (e.g. 'Skipped: no C files found')."""
        print(f"  {DIM('ℹ')}  {DIM(message)}")
        if self._current_phase:
            self._current_phase.notes.append(message)

    def skip_phase(self, phase_num: int, phase_name: str, reason: str):
        """Record a phase that was intentionally skipped."""
        audit = PhaseAudit(
            phase=phase_num,
            name=phase_name,
            status="SKIPPED",
            started_at=datetime.now(timezone.utc).isoformat(),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )
        audit.notes.append(f"Skipped: {reason}")
        self._phases.append(audit)
        print(f"  {DIM('⏭')}  {YELLOW(f'Phase {phase_num}: {phase_name}')} {DIM(f'skipped — {reason}')}")

    # ─────────────────────────────────────────────────────────
    # Audit file writer
    # ─────────────────────────────────────────────────────────

    def write_audit(self) -> str:
        """
        Write the full evidence trail to storage/audits/run_{timestamp}.json.
        Returns the audit file path.
        """
        ended_at = datetime.now(timezone.utc).isoformat()
        total_findings = sum(p.total_findings for p in self._phases)
        all_tools_ok = all(
            t.accepted
            for p in self._phases
            for t in p.tools
            if p.status != "SKIPPED"
        )

        audit_data = {
            "run_id": self.run_id,
            "repo_path": self.repo_path,
            "started_at": self.started_at,
            "ended_at": ended_at,
            "total_findings_accepted": total_findings,
            "all_exit_codes_clean": all_tools_ok,
            "phases": [
                {
                    "phase": p.phase,
                    "name": p.name,
                    "status": p.status,
                    "started_at": p.started_at,
                    "ended_at": p.ended_at,
                    "duration_sec": p.duration_sec,
                    "total_findings": p.total_findings,
                    "notes": p.notes,
                    "tools": [
                        {
                            "tool": t.tool,
                            "command": t.command,
                            "exit_code": t.exit_code,
                            "accepted": t.accepted,
                            "stdout_hash": t.stdout_hash,
                            "stderr_snippet": t.stderr_snippet,
                            "finding_count": t.finding_count,
                            "finding_ids": t.finding_ids,
                            "duration_sec": t.duration_sec,
                            "timestamp": t.timestamp,
                        }
                        for t in p.tools
                    ],
                }
                for p in self._phases
            ],
        }

        audit_path = os.path.join(self.AUDIT_DIR, f"{self.run_id}.json")
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2)

        self._print_final_summary(audit_data, audit_path)
        logger.info(f"[Observer] Audit written to: {audit_path}")
        return audit_path

    def _print_final_summary(self, data: dict, audit_path: str):
        width = 70
        clean = data["all_exit_codes_clean"]
        total = data["total_findings_accepted"]
        status = GREEN("✅ ALL GATES PASSED") if clean else RED("⚠️  SOME TOOLS FAILED — findings may be incomplete")

        print()
        print(BOLD(CYAN("═" * width)))
        print(BOLD(CYAN("  Pipeline Run Complete")))
        print(BOLD(CYAN("═" * width)))
        print(f"  Status      : {status}")
        print(f"  Total Accept: {YELLOW(str(total))} findings (exit_code=0 only)")
        print(f"  Audit File  : {BLUE(audit_path)}")

        print()
        print(f"  {'Phase':<5} {'Name':<22} {'Status':<12} {'Tools':<7} {'Findings'}")
        print(f"  {'─'*5} {'─'*22} {'─'*12} {'─'*7} {'─'*10}")
        for p in data["phases"]:
            s = p["status"]
            sc = GREEN(s) if s == "COMPLETED" else (YELLOW(s) if s == "SKIPPED" else RED(s))
            tc = str(len(p["tools"]))
            fc = str(p["total_findings"])
            print(f"  {p['phase']:<5} {p['name']:<22} {sc:<20} {tc:<7} {fc}")
        print()
        print(BOLD(CYAN("═" * width)))
        print()
