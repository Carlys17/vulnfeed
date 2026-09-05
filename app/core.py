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
import re
import tempfile
import threading
from pathlib import Path, PurePosixPath

from . import config
from .config import EngineResult

log = logging.getLogger("vulnfeed.core")

# Solidity import statements: `import "x";`, `import {A} from "x";`, `import * as y from "x";`
_IMPORT_RE = re.compile(r"""import\s+(?:[^"';]*?from\s*)?["']([^"']+)["']""")

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
def _safe_relpath(rel: str, base: Path) -> Path | None:
    """Resolve ``rel`` under ``base`` and refuse escapes (path traversal).

    Source maps come from external resolvers (Sourcify/Blockscout), so a
    malicious or malformed entry like ``../../etc/x`` must never write outside
    the temp dir. Returns None when the path is unsafe.
    """
    # Reject absolute paths and obvious traversal before joining.
    if rel.startswith(("/", "\\")) or ".." in Path(rel).parts:
        return None
    p = (base / rel).resolve()
    try:
        p.relative_to(base.resolve())
    except ValueError:
        return None
    return p


def _pick_entry(written: list[str]) -> str | None:
    """Pick the best Solidity entry file to pass to Slither.

    Prioritises short, root-level filenames (e.g. ``Contract.sol``,
    ``src/Foo.sol``) over deep library paths (``lib/foo/bar.sol``).
    Falls back to the first written file if nothing obvious matches.
    """
    root = [f for f in written if f.count("/") <= 1 and f.endswith(".sol")]
    if root:
        return sorted(root, key=lambda f: (f.count("/"), f))[0]
    non_lib = [f for f in written if not f.startswith("lib/")]
    return non_lib[0] if non_lib else (written[0] if written else None)


def _derive_remappings(source_files: dict[str, str]) -> list[str]:
    """Infer solc import remappings by matching imports against real paths.

    Verified sources keep their build-system layout (foundry ``lib/…``, hardhat
    ``node_modules/…``) while the code imports through aliases such as
    ``@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol``.
    For every import that has no matching file, find the file whose path shares
    the longest trailing segment run and emit ``alias_prefix=real_prefix``.
    """
    paths = set(source_files)
    imports: set[str] = set()
    for code in source_files.values():
        for m in _IMPORT_RE.finditer(code):
            target = m.group(1)
            if not target.startswith("."):  # relative imports resolve on disk
                imports.add(target)

    remaps: dict[str, str] = {}
    for imp in imports:
        if imp in paths:
            continue
        imp_parts = PurePosixPath(imp).parts
        best: tuple[int, tuple[str, ...]] | None = None
        for path in paths:
            p_parts = PurePosixPath(path).parts
            n = 0
            while (
                n < min(len(imp_parts), len(p_parts))
                and imp_parts[-1 - n] == p_parts[-1 - n]
            ):
                n += 1
            # Need at least the filename plus one directory to be confident.
            if n >= 2 and (best is None or n > best[0]):
                best = (n, p_parts)
        if not best:
            continue
        n, p_parts = best
        alias = "/".join(imp_parts[: len(imp_parts) - n])
        real = "/".join(p_parts[: len(p_parts) - n])
        if alias and real and remaps.get(alias) in (None, real):
            remaps[alias] = real

    return [f"{alias}/={real}/" for alias, real in sorted(remaps.items())]


def _slither_worker(source_files: dict[str, str], result_queue) -> None:
    """Run one Slither audit in an isolated child process.

    Runs in a fresh process so a hung or crashing Slither can be hard-killed by
    the parent (a stuck in-thread audit would hold ``_audit_lock`` forever and
    wedge every subsequent request). Puts a picklable dict on ``result_queue``.
    """
    try:
        from slither.slither import Slither  # heavy import, lazy

        _patch_natspec()
        with tempfile.TemporaryDirectory(prefix="vulnfeed-") as td:
            base = Path(td)
            written: list[str] = []
            for rel, code in source_files.items():
                p = _safe_relpath(rel, base)
                if p is None:
                    log.warning("skipping unsafe source path: %r", rel)
                    continue
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(code)
                if rel.endswith((".sol", ".vy")):
                    written.append(rel)

            entry = _pick_entry(written)
            if entry is None:
                result_queue.put({"ok": False, "error": "no Solidity/Vyper source file to analyze"})
                return

            # Verified sources keep their build-system layout (foundry lib/,
            # hardhat node_modules/) but import via aliases like
            # "@openzeppelin/contracts/...". Rebuild those remappings from the
            # file tree, otherwise every import fails to resolve.
            remaps = _derive_remappings(source_files)

            solcs_bin = _solcs_bin_map()

            prev_cwd = os.getcwd()
            os.chdir(base)
            try:
                sl = Slither(
                    entry,
                    solc_args=f"--allow-paths .,{base}",
                    solc_solcs_bin=solcs_bin,
                    disable_solc_warnings=True,
                    filter_paths="",
                    solc_remaps=remaps,
                )
                _register_all_detectors(sl)
                findings = _findings_from_slither(sl)
            finally:
                os.chdir(prev_cwd)
        result_queue.put({"ok": True, "findings": findings})
    except Exception as exc:  # noqa: BLE001
        try:
            result_queue.put({"ok": False, "error": str(exc)})
        except Exception:  # noqa: BLE001
            pass


def audit_source(source_files: dict[str, str], root_name: str = "Project") -> EngineResult:
    """Run Slither over an in-memory map of {relative_path: source}.

    The audit runs in a child process bounded by ``config.SLITHER_TIMEOUT``.
    ``_audit_lock`` serializes audits so only one heavy Slither process runs at
    a time (memory safety); the timeout bounds how long the lock can be held.
    """
    import multiprocessing as mp

    with _audit_lock:
        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        proc = ctx.Process(target=_slither_worker, args=(source_files, q))
        proc.start()
        proc.join(timeout=config.SLITHER_TIMEOUT)

        if proc.is_alive():
            proc.terminate()
            proc.join(5)
            if proc.is_alive():
                proc.kill()
                proc.join(2)
            log.warning("Slither audit timed out after %ss", config.SLITHER_TIMEOUT)
            return EngineResult(
                address="source-tree",
                error=f"audit timed out after {config.SLITHER_TIMEOUT}s",
                tool="slither",
            )

        try:
            res = q.get_nowait()
        except Exception:  # noqa: BLE001
            return EngineResult(
                address="source-tree", error="audit produced no result", tool="slither"
            )

    if not res.get("ok"):
        log.warning("Slither run failed: %s", res.get("error"))
        return EngineResult(
            address="source-tree", error=f"audit failed: {res.get('error')}", tool="slither"
        )

    return synthesize(res["findings"], address="source-tree", tool="slither")


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
