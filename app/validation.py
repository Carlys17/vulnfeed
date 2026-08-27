"""Address and request validation helpers.

Security notes
--------------
``validate_rpc`` is SSRF-hardened: it only accepts https URLs whose host does
not resolve to a private / loopback / link-local / reserved address. This stops
callers from pointing the miner at cloud metadata (169.254.169.254), localhost
services, or RFC1918 hosts. Caveat: DNS is resolved here and again by the HTTP
client, so a determined DNS-rebinding attack is not fully ruled out; requiring
https + blocking internal ranges covers the practical cases.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")


def normalize_address(addr: str) -> str:
    """Return checksummed lowercase address or raise ValueError."""
    if not isinstance(addr, str):
        raise ValueError("address must be a string")
    a = addr.strip()
    if not _ADDR.match(a):
        raise ValueError("address must be a 0x-prefixed 40-hex EVM address")
    return a.lower()


def _is_blocked_ip(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    """True for any address that must never be fetched."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local      # covers 169.254.169.254 cloud metadata
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_rpc(rpc: str | None) -> str | None:
    """SSRF-safe check on an optional user-supplied RPC URL.

    Only https is allowed (matches the miner YAML limitation). The host must not
    be, or resolve to, a blocked (internal) address.
    """
    if rpc is None:
        return None
    r = rpc.strip()
    if len(r) > 2048:
        raise ValueError("rpc_url too long")

    u = urlparse(r)
    if u.scheme != "https":
        raise ValueError("rpc_url must be an https URL")
    host = u.hostname
    if not host:
        raise ValueError("rpc_url must include a host")

    # Literal IP host?
    literal = None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _is_blocked_ip(literal):
            raise ValueError("rpc_url host is not allowed")
        return r

    # Hostname: resolve and reject if ANY result is internal.
    try:
        infos = socket.getaddrinfo(host, u.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("rpc_url host does not resolve") from exc
    if not infos:
        raise ValueError("rpc_url host does not resolve")
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            raise ValueError("rpc_url host does not resolve")
        if _is_blocked_ip(ip):
            raise ValueError("rpc_url resolves to a blocked address")
    return r
