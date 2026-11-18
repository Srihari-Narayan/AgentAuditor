"""Tool registry for the analyst agent.

Each tool declares the permission it needs and whether it is *sensitive*
(externally observable / irreversible). The agent loop runs every call through
the guardrail broker (least privilege) and the HITL gate (sensitive actions).

Roles follow least privilege: the analyst role can read and assess, but cannot
e.g. email a report out without a human in the loop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# role -> granted permissions
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "analyst": {"findings:read", "controls:read", "report:write"},
    # note: NOT granted "report:send" -- sending is a sensitive, gated action.
    "operator": {"findings:read", "controls:read", "report:write", "report:send"},
}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    permission: str
    sensitive: bool
    description: str


TOOLS: dict[str, ToolSpec] = {
    "read_findings": ToolSpec("read_findings", "findings:read", False,
                              "Load findings from a source file."),
    "map_control": ToolSpec("map_control", "controls:read", False,
                            "Map a finding to NIST/CIS controls (deterministic)."),
    "score_risk": ToolSpec("score_risk", "controls:read", False,
                           "Compute inherent/residual risk (deterministic)."),
    "write_report": ToolSpec("write_report", "report:write", False,
                             "Write the governance report to disk."),
    "send_report": ToolSpec("send_report", "report:send", True,
                            "Email the report externally (SENSITIVE, HITL-gated)."),
}


def send_report(recipient: str, path: str) -> str:
    """Stub for the one sensitive tool. Never actually sends in this project --
    it exists so the least-privilege + HITL controls have something real to gate.
    """
    return f"[dry-run] would send {path} to {recipient}"
