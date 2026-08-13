#!/usr/bin/env bash
# VulnFeed miner registration on Base Sepolia (Telegraph)
# Usage:
#   1. cp .env.example .env  &&  edit .env (MINER_PRIVATE_KEY + FEE_ADDRESS)
#   2. ./scripts/register-miner.sh [--dry-run]
# Requires: cast (foundry), a Base Sepolia funded wallet
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

# Load .env if present (MINER_PRIVATE_KEY, FEE_ADDRESS, RPC_URL)
if [[ -f "$ROOT/.env" ]]; then
  set -a; source "$ROOT/.env"; set +a
fi

DIAMOND="0x5a2324aA18613FAD4e44bDF0d6c73Ec1f6D87ff8"
RPC="${RPC_URL:-https://sepolia.base.org}"
YAML_URL="${YAML_URL:-https://carly17.my.id/vulnfeed/vulnfeed.yaml}"
FEE_ADDRESS="${FEE_ADDRESS:-}"
MIN_PRICE=10000  # 0.01 USDC (6 decimals), network minimum

if [[ -z "${MINER_PRIVATE_KEY:-}" ]]; then
  echo "ERROR: MINER_PRIVATE_KEY not set. Create .env with MINER_PRIVATE_KEY=0x... (Base Sepolia funded)." >&2
  exit 1
fi

YAML_FILE="miner/vulnfeed.yaml"
YAML_HASH="0x$(sha256sum "$YAML_FILE" | awk '{print $1}')"
INTENTS='["ONCHAIN_TX_LOOKUP"]'

echo "=== VulnFeed Miner Registration (Base Sepolia) ==="
echo "Diamond:   $DIAMOND"
echo "YAML URL:  $YAML_URL"
echo "YAML hash: $YAML_HASH"
echo "Intents:   $INTENTS"
echo "Min price: $MIN_PRICE (0.01 USDC)"

# Verify the hosted YAML matches local bytes (node rejects on mismatch)
echo "--- verifying hosted YAML hash ---"
if command -v curl >/dev/null; then
  HOSTED_HASH=$(curl -s "$YAML_URL" | sha256sum | awk '{print $1}')
  LOCAL_HASH=$(sha256sum "$YAML_FILE" | awk '{print $1}')
  if [[ "$HOSTED_HASH" == "$LOCAL_HASH" ]]; then
    echo "OK: hosted YAML matches local file"
  else
    echo "WARN: hosted YAML differs from local file!" >&2
    echo "  hosted: $HOSTED_HASH" >&2
    echo "  local:  $LOCAL_HASH" >&2
    echo "  Update the hosted copy first (cp miner/vulnfeed.yaml /var/www/carly17.my.id/vulnfeed.yaml)" >&2
    exit 1
  fi
fi

WALLET_ADDR=$(cast wallet address "$MINER_PRIVATE_KEY" 2>/dev/null)
BAL=$(cast call "$RPC" balance "$WALLET_ADDR" 2>/dev/null || cast rpc eth_getBalance "$WALLET_ADDR" latest --rpc-url "$RPC" 2>/dev/null || echo "0x0")
echo "Wallet:    $WALLET_ADDR (balance: $BAL wei)"

if [[ "$BAL" == "0x0" || "$BAL" == "0" ]]; then
  echo "WARN: wallet has 0 balance on Base Sepolia. Need testnet ETH for gas." >&2
  echo "  Faucet: https://docs.base.org/tools/faucets/ or bridge from Base mainnet." >&2
fi

if [[ -z "$FEE_ADDRESS" ]]; then
  FEE_ADDRESS="$WALLET_ADDR"
  echo "Fee addr:  $FEE_ADDRESS (defaults to wallet)"
fi

if [[ "${1:-}" == "--dry-run" ]]; then
  echo ""
  echo "DRY RUN — no transaction sent. Command that WOULD run:"
  echo "  cast send \"$DIAMOND\" 'registerMiner(string,bytes32,address,uint256,string[])' \\"
  echo "    \"$YAML_URL\" \"$YAML_HASH\" \"$FEE_ADDRESS\" $MIN_PRICE '$INTENTS' \\"
  echo "    --rpc-url \"$RPC\" --private-key <REDACTED>"
  exit 0
fi

echo "--- submitting registration ---"
cast send "$DIAMOND" \
  "registerMiner(string,bytes32,address,uint256,string[])" \
  "$YAML_URL" \
  "$YAML_HASH" \
  "$FEE_ADDRESS" \
  "$MIN_PRICE" \
  "$INTENTS" \
  --rpc-url "$RPC" \
  --private-key "$MINER_PRIVATE_KEY"

echo "--- done. Check the node ingests at next epoch boundary ---"
