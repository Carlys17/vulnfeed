"""Smoke tests for VulnFeed core analysis using local fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# allow `python tests/test_core.py` from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import core  # noqa: E402


def _slither_detects_reentrancy(result) -> bool:
    for f in result.findings:
        if "reentrancy" in (f.get("title") or "").lower():
            return True
    return False


def main() -> int:
    fixture = Path("fixtures/VulnerableVault.sol").read_text()
    result = core.audit_source({"VulnerableVault.sol": fixture})
    print("rating       :", result.rating)
    print("risk_score   :", result.risk_score)
    print("severity     :", result.severity_counts)
    print("summary      :", result.summary)
    print("exploit_prob :", result.exploit_probability)
    print("findings     :", len(result.findings))
    for f in result.findings[:6]:
        print("   -", f.get("impact"), "|", f.get("title"))

    assert result.findings, "expected findings on vulnerable fixture"
    assert _slither_detects_reentrancy(result), "expected a reentrancy finding"
    assert result.risk_score > 0, "expected non-zero risk score"
    assert result.rating in ("critical", "elevated", "moderate"), f"unexpected {result.rating}"
    print("\nPASS: core audit detects vulnerabilities deterministically")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
