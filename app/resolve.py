"""External source resolvers: fetch verified Solidity source for an address.

Tries in order, free + no API key required:
1. Sourcify (server.v2)
2. Blockscout (Base) getsourcecode
Falls back to on-chain bytecode heuristics if neither produces source.
"""

from __future__ import annotations

import logging
import re

import requests

from . import config

log = logging.getLogger("vulnfeed.resolve")

SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{addr}?fields=sources"
BLOCKSCOUT = "https://{chain}.blockscout.com/api"  # subdomain per network


def _get(url: str, **kw) -> dict | None:
    try:
        r = requests.get(url, timeout=config.HTTP_TIMEOUT, **kw)
        if r.status_code == 200:
            return r.json()
    except Exception as exc:  # noqa: BLE001
        log.debug("resolve %s -> %s", url, exc)
    return None


def fetch_sources(addr: str, rpc: str | None = None) -> tuple[dict[str, str] | None, str | None]:
    """Return (source_files, warn). warn is set when only a fallback path is possible."""
    chain_id = _chain_id_from_rpc(rpc)

    # 1) Sourcify v2 (numeric chain id, sources as {path: {content}})
    try:
        j = _get(SOURCIFY.format(chain=chain_id, addr=addr))
        if j and j.get("match") and j.get("sources"):
            files = {
                path: meta.get("content", "")
                for path, meta in j["sources"].items()
                if isinstance(meta, dict)
            }
            if files:
                return files, None
    except Exception:  # noqa: BLE001
        pass

    # 2) Blockscout
    try:
        chain = "base" if chain_id in (8453, 84532) else "eth"
        j = _get(f"{BLOCKSCOUT.format(chain=chain)}?module=contract&action=getsourcecode&address={addr}")
        result = (j or {}).get("result") or [{}]
        if result and result[0].get("SourceCode"):
            files = _blockscout_files(result[0])
            if files:
                return files, None
    except Exception:  # noqa: BLE001
        pass

    return None, "verified source not found; using bytecode heuristics"


def _blockscout_files(entry: dict) -> dict[str, str] | None:
    src = entry.get("SourceCode", "")
    sources = {}
    try:
        # Standard JSON input wrapped by Blockscout
        import json as _json

        if src.startswith("{"):
            # sometimes double-encoded
            data = src
            if data.startswith("{{"):
                data = data[1:-1]
            spec = _json.loads(data)
            if spec.get("sources"):
                for path, meta in spec["sources"].items():
                    sources[path] = meta.get("content", "")
    except Exception:  # noqa: BLE001
        pass
    if not sources and src.strip():
        sources["Contract.sol"] = src
    return sources or None


def _chain_id_from_rpc(rpc: str | None) -> int:
    if rpc:
        try:
            j = _get(rpc, json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1})
            if j and "result" in j:
                return int(j["result"], 16)
        except Exception:  # noqa: BLE001
            pass
    return config.CHAIN_ID
