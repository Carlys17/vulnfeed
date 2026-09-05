"""External source resolvers: fetch verified Solidity source for an address.

Tries in order, free + no API key required:
1. Sourcify (server.v2) — multi-chain by numeric chain id
2. Chain-native Blockscout / explorer API (per-chain registry in chains.py)
3. On-chain bytecode heuristics if neither produces source.
"""

from __future__ import annotations

import logging
import re
import time

import requests

from . import chains, config

log = logging.getLogger("vulnfeed.resolve")

SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{addr}?fields=sources"

# EIP-1967 / legacy proxy storage slots, read straight off-chain via RPC.
# Reading storage needs no explorer and is not rate limited, unlike Blockscout.
IMPL_SLOTS = (
    # EIP-1967 implementation: keccak256("eip1967.proxy.implementation") - 1
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    # EIP-1967 beacon: keccak256("eip1967.proxy.beacon") - 1
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    # Legacy OpenZeppelin: keccak256("org.zeppelinos.proxy.implementation")
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
)
ZERO_WORD = "0x" + "0" * 64


def _get(url: str, **kw) -> dict | None:
    """GET JSON with retries on 429 (Blockscout rate-limits aggressively)."""
    backoff = 1.5
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=config.HTTP_TIMEOUT, **kw)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429 and attempt < 2:
                log.debug("429 on %s, retry %d after %.1fs", url, attempt + 1, backoff)
                time.sleep(backoff)
                backoff *= 2
                continue
            log.debug("resolve %s -> HTTP %s", url, r.status_code)
            return None
        except Exception as exc:  # noqa: BLE001
            log.debug("resolve %s -> %s", url, exc)
            return None
    return None


# Short-lived cache of Blockscout getsourcecode responses, keyed by
# (chain_id, address). One scan needs the entry for source, proxy detection and
# implementation lookup; without this each scan would burn 3 rate-limited calls.
_bs_cache: dict[tuple[int, str], tuple[float, dict | None]] = {}
_BS_TTL = 300.0


def _blockscout_entry(addr: str, chain_id: int) -> dict | None:
    """Fetch (and cache) the Blockscout getsourcecode entry for an address."""
    key = (chain_id, addr.lower())
    hit = _bs_cache.get(key)
    if hit and time.monotonic() - hit[0] < _BS_TTL:
        return hit[1]

    bs_url = chains.blockscout_url(chain_id)
    if not bs_url:
        return None
    j = _get(f"{bs_url}?module=contract&action=getsourcecode&address={addr}")
    entry = None
    result = (j or {}).get("result")
    if isinstance(result, list) and result and isinstance(result[0], dict):
        entry = result[0]

    # Cache misses too, so a rate-limited scan doesn't retry 3x in one request.
    if len(_bs_cache) > 256:
        _bs_cache.clear()
    _bs_cache[key] = (time.monotonic(), entry)
    return entry


def fetch_sources(addr: str, rpc: str | None = None, chain_id: int | None = None) -> tuple[dict[str, str] | None, str | None]:
    """Return (source_files, warn). warn is set when only a fallback path is possible.

    ``chain_id`` (if given) takes precedence; otherwise it is derived from the
    RPC endpoint, falling back to the configured default chain.

    Proxies (EIP-1967 and friends) are followed to their implementation: the
    proxy's own source is only boilerplate, the logic worth auditing lives in
    the implementation contract.
    """
    cid = chain_id or _chain_id_from_rpc(rpc)
    chain_id = cid

    files, warn = _fetch_for_address(addr, chain_id)

    impl_addr = _implementation_address(addr, rpc, chain_id)
    if impl_addr and impl_addr != addr.lower():
        impl_files, _ = _fetch_for_address(impl_addr, chain_id)
        if impl_files:
            note = f"proxy: audited implementation {impl_addr}"
            if files:
                # Implementation source wins on path collisions.
                merged = dict(files)
                merged.update(impl_files)
                files = merged
            else:
                files = impl_files
            warn = f"{warn}; {note}" if warn else note

    if not files:
        return None, f"verified source not found on {chains.chain_name(chain_id)}; using bytecode heuristics"
    return files, warn


def _fetch_for_address(addr: str, chain_id: int) -> tuple[dict[str, str] | None, str | None]:
    """Fetch source for a single address (no proxy resolution)."""
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

    # 2) Blockscout (cached — one API call, shared across all lookups)
    entry = _blockscout_entry(addr, chain_id)
    if entry and entry.get("SourceCode"):
        files = _blockscout_files(entry)
        if files:
            return files, None

    return None, f"source not found for {addr[:10]}"


def _is_proxy_contract(addr: str, chain_id: int) -> bool:
    """Return True if the contract at addr is a proxy (Blockscout, cached)."""
    entry = _blockscout_entry(addr, chain_id)
    if not entry:
        return False
    return str(entry.get("IsProxy", "")).lower() == "true"


def _implementation_address(
    addr: str, rpc: str | None = None, chain_id: int | None = None
) -> str | None:
    """Resolve a proxy's implementation address.

    Reads EIP-1967 storage slots over RPC first (free, never rate limited),
    then falls back to Blockscout's IsProxy/ImplementationAddress fields.
    """
    rpc_url = rpc or config.DEFAULT_RPC_URL

    for slot in IMPL_SLOTS:
        word = _storage_at(rpc_url, addr, slot)
        if word and word != ZERO_WORD and len(word) == 66:
            candidate = "0x" + word[-40:]
            if candidate != "0x" + "0" * 40:
                return candidate.lower()

    # Fallback: explorer metadata (rate-limited, so only if RPC found nothing).
    if chain_id is not None:
        entry = _blockscout_entry(addr, chain_id)
        if entry and str(entry.get("IsProxy", "")).lower() == "true":
            impl = entry.get("ImplementationAddress") or entry.get(
                "ImplementationAddresses"
            )
            if isinstance(impl, list):
                impl = impl[0] if impl else None
            if impl:
                return str(impl).lower()
    return None


def _storage_at(rpc_url: str | None, addr: str, slot: str) -> str | None:
    """eth_getStorageAt via plain JSON-RPC; None on any failure."""
    if not rpc_url:
        return None
    try:
        r = requests.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getStorageAt",
                "params": [addr, slot, "latest"],
            },
            timeout=config.HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            return (r.json() or {}).get("result")
    except Exception as exc:  # noqa: BLE001
        log.debug("eth_getStorageAt %s slot %s -> %s", addr, slot[:10], exc)
    return None


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

    # Merge AdditionalSources: Blockscout splits multi-file sources into this
    # separate field; include them so Slither can resolve imports.
    for extra in entry.get("AdditionalSources") or []:
        fn = extra.get("Filename") or extra.get("filename", "extra.sol")
        code = extra.get("SourceCode") or extra.get("source_code") or ""
        if code and fn:
            sources[fn] = code

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
