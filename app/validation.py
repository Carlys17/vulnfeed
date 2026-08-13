"""Address and request validation helpers."""

from __future__ import annotations

import re

_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")


def normalize_address(addr: str) -> str:
    """Return checksummed lowercase address or raise ValueError."""
    if not isinstance(addr, str):
        raise ValueError("address must be a string")
    a = addr.strip()
    if not _ADDR.match(a):
        raise ValueError("address must be a 0x-prefixed 40-hex EVM address")
    return a.lower()


def validate_rpc(rpc: str | None) -> str | None:
    """Basic sanity check on an optional user-supplied RPC URL."""
    if rpc is None:
        return None
    r = rpc.strip()
    if not r.startswith(("http://", "https://")):
        raise ValueError("rpc_url must be http(s) URL")
    return r
