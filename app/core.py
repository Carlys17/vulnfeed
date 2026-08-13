"""Core analysis: run Slither over verified source and synthesize a risk report.

Design goals for the Telegraph ONCHAIN_TX_LOOKUP intent:
- Deterministic output given the same input (stable ordering, stable score).
- Fast enough to serve as a live miner (< a few seconds warm).
- Graceful degradation: if full source is unavailable, fall back to a
  static bytecode heuristic scan so the miner can still answer.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
from pathlib import Path

from . import config
from .config import EngineResult

log = logging.getLogger("vulnfeed.core")

# Slither receivers are not fully thread-safe; serialize audits.
_audit_lock = threading.Lock()


def _patch_natspec() -> None:
    """crytic-compile 0.3.x expects userdoc/devdoc dicts, but solc 0.8.26+
    combined-json returns them as JSON strings. Patch to accept both."""
    import json as _json

    from crytic_compile.utils.natspec import UserDoc, DevDoc, Natspec

    def _coerce(v):
        if isinstance(v, str):
            try:
                return _json.loads(v)
            except Exception:  # noqa: BLE001
                return {}
        return v or {}

    _orig_ud = UserDoc.__init__
    _orig_dd = DevDoc.__init__
    _orig_ns = Natspec.__init__

    def _ud(self, userdoc, **kw):
        _orig_ud(self, _coerce(userdoc), **kw)

    def _dd(self, devdoc, **kw):
        _orig_dd(self, _coerce(devdoc), **kw)

    def _ns(self, userdoc, devdoc):
        _orig_ns(self, _coerce(userdoc), _coerce(devdoc))

    UserDoc.__init__ = _ud
    DevDoc.__init__ = _dd
    Natspec.__init__ = _ns


def _solcs_bin_map() -> dict:
    """Return {'0.8.26': '/path/solc-0.8.26', ...} for installed versions.

    Checks the env override, the venv prefix (where solc-select installs when
    run inside a venv), and the user home fallback.
    """
    import sys as _sys

    candidates = []
    env = os.environ.get("SOLC_ARTIFACTS")
    if env:
        candidates.append(env)
    # venv prefix: solc-select puts artifacts under sys.prefix/.solc-select
    candidates.append(os.path.join(_sys.prefix, ".solc-select", "artifacts"))
    candidates.append(os.path.expanduser("~/.solc-select/artifacts"))

    artifacts = next((c for c in candidates if os.path.isdir(c)), None)
    out: dict = {}
    if not artifacts:
        return out
    # Merge across ALL existing artifact dirs (not just the first one found),
    # so a solc version installed in another prefix (e.g. ~/.solc-select)
    # is still available to the miner.
    for c in candidates:
        if not os.path.isdir(c):
            continue
        for name in os.listdir(c):
            if not name.startswith("solc-"):
                continue
            ver = name[len("solc-"):]
            bin_path = os.path.join(c, name, name)
            if os.path.isfile(bin_path) and ver not in out:
                out[ver] = bin_path
    return out


def _register_all_detectors(sl) -> None:
    """Slither's library API does not auto-register detectors (the CLI does).

    Enumerate every concrete AbstractDetector subclass and register it so
    ``sl.detectors`` and ``sl.run_detectors()`` behave like the CLI.
    """
    import inspect

    from slither.detectors import all_detectors
    from slither.detectors.abstract_detector import AbstractDetector

    for name in dir(all_detectors):
        cls = getattr(all_detectors, name)
        if inspect.isclass(cls) and issubclass(cls, AbstractDetector):
            try:
                sl.register_detector(cls)
            except Exception:  # noqa: BLE001
                continue


# --------------------------------------------------------------------------
# Slither audit over a source tree
# --------------------------------------------------------------------------
def audit_source(source_files: dict[str, str], root_name: str = "Project") -> EngineResult:
    """Run Slither over an in-memory map of {relative_path: source}."""
    from slither.slither import Slither  # heavy import, lazy

    try:
        _patch_natspec()
        with _audit_lock:
            with tempfile.TemporaryDirectory(prefix="vulnfeed-") as td:
                base = Path(td)
                # Writable sources into a flat dir; Slither handles relative imports.
                entry = None
                for rel, code in source_files.items():
                    p = base / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(code)
                    if rel.endswith((".sol", ".vy")):
                        entry = entry or rel

                if entry is None:
                    raise ValueError("no Solidity/Vyper source file to analyze")

                # Build a version->binary map so crytic-compile tries each
                # installed solc and picks the one that satisfies the pragma.
                solcs_bin = _solcs_bin_map()

                # Solc resolves `@import` paths relative to CWD, so run from
                # the source root and pass a relative entry file.
                prev_cwd = os.getcwd()
                os.chdir(base)
                try:
                    sl = Slither(
                        entry,
                        solc_args=f"--allow-paths .,{base}",
                        solc_solcs_bin=solcs_bin,
                        disable_solc_warnings=True,
                        filter_paths="",
                    )
                    _register_all_detectors(sl)
                    findings = _findings_from_slither(sl)
                finally:
                    os.chdir(prev_cwd)
    except Exception as exc:  # noqa: BLE001
        log.warning("Slither run failed: %s", exc)
        return EngineResult(
            address="source-tree", error=f"audit failed: {exc}", tool="slither"
        )

    return synthesize(findings, address="source-tree", tool="slither")


def _findings_from_slither(sl) -> list[dict]:
    """Run all registered detectors and normalize their output.

    Detectors must be registered before calling this (see audit_source).
    ``run_detectors`` returns one list of issues per registered detector;
    we flatten and normalize into stable dicts.
    """
    findings: list[dict] = []
    results = sl.run_detectors()
    for det, issues in zip(sl.detectors, results):
        # Detector metadata: NAME-like fields live on the class; use
        # ARGUMENT (slug) + WIKI_TITLE (human name) which always exist.
        try:
            name = getattr(det, "WIKI_TITLE", None) or getattr(det, "ARGUMENT", None) or det.__class__.__name__
            impact = det.IMPACT
            confidence = det.CONFIDENCE
        except Exception:  # noqa: BLE001
            continue
        for issue in issues or []:
            if isinstance(issue, dict):
                # issue already carries impact/confidence from the detector run
                sev = str(issue.get("impact") or impact).lower()
                conf = str(issue.get("confidence") or confidence).lower()
                findings.append(
                    {
                        "title": name,
                        "impact": sev,
                        "confidence": conf,
                        "description": issue.get("description", ""),
                        "file": _issue_file(issue),
                        "line_start": _issue_line(issue),
                    }
                )
    return findings


def _issue_file(issue: dict) -> str | None:
    try:
        el = (issue.get("elements") or [{}])[0]
        sm = el.get("source_mapping") or {}
        return sm.get("filename_absolute") or sm.get("filename") or sm.get("filename_relative")
    except Exception:  # noqa: BLE001
        return None


def _issue_line(issue: dict) -> int | None:
    try:
        el = (issue.get("elements") or [{}])[0]
        sm = el.get("source_mapping") or {}
        if sm.get("lines"):
            return sm["lines"][0]
        return None
    except Exception:  # noqa: BLE001
        return None


def synthesize(findings: list[dict], address: str, tool: str = "slither") -> EngineResult:
    """Convert raw detector findings into a stable, weighted risk report."""
    counted: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    weighted = 0.0
    max_sev = "informational"
    order = ("high", "medium", "low", "informational")
    for f in findings:
        sev = f.get("impact", "informational")
        if sev not in counted:
            sev = "informational"
        counted[sev] += 1
        weighted += config.SEVERITY_WEIGHT[sev]
        if sev != "informational" and order.index(sev) < order.index(max_sev):
            max_sev = sev

    # Deterministic ordering: severity desc, then title asc.
    sev_rank = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    findings = sorted(
        findings,
        key=lambda f: (sev_rank.get(f.get("impact", "informational"), 3), str(f.get("title", ""))),
    )

    if findings and max_sev != "informational":
        # Scale so a single high finding lands around 60.
        risk_score = round(min(100.0, weighted * (100.0 / 16.0)), 1)
        rating = {
            "high": "critical",
            "medium": "elevated",
            "low": "moderate",
        }.get(max_sev, "unknown")
    else:
        risk_score = 0.0
        rating = "clean" if findings else "no_source"

    summary = (
        f"{counted['high']} high, {counted['medium']} medium, "
        f"{counted['low']} low, {counted['informational']} informational"
    )
    if rating == "clean":
        summary = "No high/medium/low severity issues detected."
    elif rating == "no_source":
        summary = "Source unavailable; no static analysis performed."

    return EngineResult(
        address=address,
        risk_score=risk_score,
        rating=rating,
        severity_counts=counted,
        findings=findings,
        summary=summary,
        tool=tool,
    )
