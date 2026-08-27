"""EVM chain registry for VulnFeed.

VulnFeed supports any EVM chain that (a) has verified sources on Sourcify
(multi-chain by numeric chain id), or (b) exposes a Blockscout API we know
about, or (c) is reachable via a user-supplied rpc_url.

Adding a chain = add one entry here (blockscout base URL, or None if only
Sourcify/rpc is available). No other code changes needed.
"""

from __future__ import annotations

# chain_id -> human name (for logs / UI)
CHAIN_NAMES: dict[int, str] = {
    1: "ethereum",
    10: "optimism",
    56: "bnb-smart-chain",
    100: "gnosis",
    130: "unichain",
    137: "polygon",
    250: "fantom",
    8453: "base",
    84532: "base-sepolia",
    42161: "arbitrum-one",
    42170: "arbitrum-nova",
    43114: "avalanche-c",
    534352: "scroll",
    59144: "linea",
    7777777: "zora",
    81457: "blast",
    5000: "mantle",
    324: "zksync-era",
    1088: "metis",
    42220: "celo",
    1313161554: "aurora",
    1284: "moonbeam",
    1285: "moonriver",
    25: "cronos",
    204: "opbnb",
    11155111: "sepolia",
    57073: "ink",
    80094: "berachain",
    480: "worldchain",
    146: "sonic",
}

# chain_id -> Blockscout API base (no trailing slash). None = use Sourcify + rpc only.
# Sourcify covers all chains for verified-source, so this is a best-effort
# secondary resolver that adds chain-native explorers.
BLOCKSCOUT_API: dict[int, str] = {
    1: "https://eth.blockscout.com/api",
    10: "https://optimism.blockscout.com/api",
    56: "https://bscscan.com/api",  # bscscan-compatible
    100: "https://gnosis.blockscout.com/api",
    130: "https://unichain.blockscout.com/api",
    137: "https://polygon.blockscout.com/api",
    250: "https://ftm.blockscout.com/api",
    8453: "https://base.blockscout.com/api",
    84532: "https://base-sepolia.blockscout.com/api",
    42161: "https://arbitrum.blockscout.com/api",
    42170: "https://nova.blockscout.com/api",
    43114: "https://avalanche.blockscout.com/api",
    534352: "https://scroll.blockscout.com/api",
    59144: "https://linea.blockscout.com/api",
    7777777: "https://zora.blockscout.com/api",
    81457: "https://blast.blockscout.com/api",
    5000: "https://explorer.mantle.xyz/api",
    324: "https://explorer.zksync.io/api",
    1088: "https://andromeda-explorer.metis.io/api",
    42220: "https://celo.blockscout.com/api",
    1313161554: "https://aurora.blockscout.com/api",
    1284: "https://moonbeam.blockscout.com/api",
    1285: "https://moonriver.blockscout.com/api",
    25: "https://cronos.blockscout.com/api",
    204: "https://opbnb.blockscout.com/api",
    11155111: "https://eth-sepolia.blockscout.com/api",
    57073: "https://explorer.inkonchain.com/api",
    80094: "https://api.berascan.com/api",
    480: "https://worldchain.blockscout.com/api",
    146: "https://api.sonicscan.org/api",
}

# Chains where Blockscout is not available; Sourcify + rpc only.
# (All chains are implicitly supported via Sourcify by numeric id; this set
#  is informational — used by the UI to label "explorer: Sourcify".)
SOURCIFY_ONLY_CHAINS = {
    cid for cid in CHAIN_NAMES if cid not in BLOCKSCOUT_API
}


def chain_name(chain_id: int) -> str:
    return CHAIN_NAMES.get(chain_id, f"chain-{chain_id}")


def blockscout_url(chain_id: int) -> str | None:
    return BLOCKSCOUT_API.get(chain_id)


def is_known_chain(chain_id: int) -> bool:
    """True if we have an explorer OR Sourcify supports it.

    Sourcify supports ~100+ chains by numeric id, so we accept any positive
    integer as a valid chain id (defensive lower bound), but prefer known ones
    for better diagnostics.
    """
    return chain_id > 0
