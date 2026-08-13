# VulnFeed miner - Telegraph Protocol Hackathon
# Deterministic on-chain smart contract security intelligence.

from __future__ import annotations

import os
from dataclasses import dataclass, field

# ---- RPC / network ----
DEFAULT_RPC_URL = os.environ.get(
    "VULNFEED_RPC_URL", "https://mainnet.base.org"
)
CHAIN_ID = int(os.environ.get("VULNFEED_CHAIN_ID", "8453"))  # Base mainnet

# ---- Timeouts (seconds) ----
SLITHER_TIMEOUT = int(os.environ.get("VULNFEED_SLITHER_TIMEOUT", "120"))
HTTP_TIMEOUT = int(os.environ.get("VULNFEED_HTTP_TIMEOUT", "20"))

# ---- Score weights ----
# Each maps to how strongly a finding class moves the composite risk score.
SEVERITY_WEIGHT = {
    "high": 10.0,
    "medium": 6.0,
    "low": 2.0,
    "informational": 0.5,
}

# ---- Output / service ----
HOST = os.environ.get("VULNFEED_HOST", "0.0.0.0")
PORT = int(os.environ.get("VULNFEED_PORT", "8081"))

# ---- Intent declaration (Telegraph YAML surface) ----
INTENT = "ONCHAIN_TX_LOOKUP"
# floor price in USDC (x10^6) - 0.01 USDC to stay competitive on the floor
MIN_PRICE_USDC = int(os.environ.get("VULNFEED_MIN_PRICE_USDC", "10000"))


@dataclass
class EngineResult:
    """Aggregated analysis result from one contract."""

    address: str
    risk_score: float = 0.0
    rating: str = "unknown"
    severity_counts: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    summary: str = ""
    warnings: list = field(default_factory=list)
    tool: str = "slither"
    error: str | None = None

    @property
    def exploit_probability(self) -> float:
        """0.0-1.0 estimate, monotonic in risk score."""
        return round(min(0.95, 0.02 + self.risk_score / 100.0), 3)
