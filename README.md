# VulnFeed — On-Chain Security Intelligence Miner (Telegraph)

Deterministic smart-contract security miner for the **Telegraph Protocol Hackathon**.
Serves the **ONCHAIN_TX_LOOKUP** intent (Tier A · deterministic) — "Smart contract auditing agents".

Given an EVM contract address, VulnFeed fetches verified source (Sourcify → Blockscout)
and runs static analysis (Slither) to return a structured risk report:

- `rating`: clean / moderate / elevated / critical
- `risk_score`: 0–100 composite
- `exploit_probability`: 0–1
- `severity_counts`: high / medium / low / informational
- `findings`: per-detector detail (title, impact, confidence, file, line)
- deterministic & repeatable for the same input

## Intent

| Intent | Tier | Type | Deterministic |
|---|---|---|---|
| `ONCHAIN_TX_LOOKUP` | A | On-Chain Analytics | ✅ |

## Architecture

```
                  /v1/analyze
 Client ─────────────────────────────► FastAPI (uvicorn :8185)
                                   │
                  resolve.fetch_sources()   (Sourcify v2 → Blockscout → fallback)
                                   ▼
                                   core.audit_source()   (Slither static analysis)
                                   │
                                   ▼
                       structured risk report (JSON)
```

## Project structure

```
app/
  server.py      # FastAPI surface (health, intents, /v1/analyze)
  core.py        # Slither audit + risk synthesis
  resolve.py     # Sourcify/Blockscout verified-source resolver
  validation.py  # address + RPC normalization
  config.py      # env config + intent declaration
miner/
  vulnfeed.yaml  # Telegraph miner YAML integration manifest
eval/
  score_miner.py # Track 2 evaluation harness (determinism, accuracy, latency)
  ground_truth.jsonl
fixtures/
  VulnerableVault.sol
tests/
  test_core.py
deploy/
  systemd service + nginx notes
```

## Run locally

```bash
# create venv + install
python3 -m venv .venv-tg
.venv-tg/bin/pip install -r requirements.txt

# start API
.venv-tg/bin/python -m uvicorn app.server:app --host 127.0.0.1 --port 8185

# health
curl http://127.0.0.1:8185/health

# analyze a contract on Base
curl -s -X POST http://127.0.0.1:8185/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{"address":"0x2626664c2603336E57B271c5C0b26F421741e481"}'
```

## Track 2: evaluation harness

```bash
.venv-tg/bin/python eval/score_miner.py --truth eval/ground_truth.jsonl \
  --base-url http://127.0.0.1:8185 --out report.json
```

Metrics emitted: `rating_accuracy`, `rating_distance`, `high_f1`, `determinism`,
`latency_p50_s`, `latency_p95_s`.

## Deployment

- API: uvicorn on 127.0.0.1:8185
- Public proxy: `https://carly17.my.id/vulnfeed/` (nginx → 127.0.0.1:8185)
- Miner manifest: `https://carly17.my.id/collectors/vulnfeed.yaml`

## Miner YAML (Telegraph)

See `miner/vulnfeed.yaml`. Declares:
- intent `ONCHAIN_TX_LOOKUP`
- `label_field` = `rating`, `confidence_field` = `exploit_probability`
- `on_chain: transform direct, min_price_usdc 0.01`

## Security

- API binds loopback only (127.0.0.1), exposed via authenticated reverse proxy
- No API keys stored on-chain; `auth: none` for the public resolver path
- Deterministic output, rate limiting at proxy

## Judgment notes

- Track 1 Miners: 75% Normalized Performance (within intent) + 25% X engagement
- Guardrail: ≥3 active miners + ≥100 real requests per intent for cash prizes
- Tag `@Telegraphprotoc` in all update posts

## Links

- Hackathon: https://hackathon.telegraphprotocol.com/
- Docs: https://docs.telegraphprotocol.com/
- Boilerplate: https://github.com/telegraphprotocol/telegraph-usecases
