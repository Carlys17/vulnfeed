# VulnFeed

Deterministic EVM smart-contract security miner. Given a contract address on
Base, VulnFeed fetches verified source (Sourcify → Blockscout) and runs static
analysis (Slither) to produce a structured, reproducible risk report.

Built for the `ONCHAIN_TX_LOOKUP` intent in the Telegraph Protocol miner network.

## What it does

`POST /v1/analyze` with an EVM contract address returns a fixed-schema report:

| Field | Type | Description |
|---|---|---|
| `rating` | string | `clean` · `moderate` · `elevated` · `critical` · `no_source` |
| `risk_score` | number | 0–100 composite score |
| `exploit_probability` | number | 0–1 likelihood of a working exploit |
| `severity_counts` | object | high / medium / low / informational detector hits |
| `findings` | array | per-detector detail: title, impact, confidence, file, line |
| `summary` | string | human-readable explanation |

Output is **deterministic** — the same input always yields the same report
(stable detector ordering, stable scoring, no sampling or randomness).

## Architecture

```
Client
  │  POST /v1/analyze  { address }
  ▼
FastAPI  (uvicorn :8185)
  │
  ├─ resolve.fetch_sources()      Sourcify v2 → Blockscout → bytecode fallback
  ▼
core.audit_source()               Slither static analysis + risk synthesis
  ▼
structured risk report (JSON)
```

| Component | Responsibility |
|---|---|
| `app/server.py` | FastAPI surface: `/health`, `/intents`, `/v1/analyze` |
| `app/core.py` | Slither audit + composite risk-score synthesis |
| `app/resolve.py` | Verified-source resolver (Sourcify / Blockscout) |
| `app/validation.py` | Address + RPC normalization |
| `app/config.py` | Environment config + intent declaration |
| `miner/vulnfeed.yaml` | Telegraph miner integration manifest |
| `eval/score_miner.py` | Evaluation harness (determinism, accuracy, latency) |
| `fixtures/VulnerableVault.sol` | Sample contract for testing |

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# start the API (loopback only)
.venv/bin/python -m uvicorn app.server:app --host 127.0.0.1 --port 8185

# health check
curl http://127.0.0.1:8185/health

# analyze a contract on Base
curl -s -X POST http://127.0.0.1:8185/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{"address":"0x2626664c2603336E57B271c5C0b26F421741e481"}'
```

## Evaluation

`eval/score_miner.py` measures the miner against a ground-truth set
(`eval/ground_truth.jsonl`) and emits a machine-readable JSON report:

```bash
.venv/bin/python eval/score_miner.py \
  --truth eval/ground_truth.jsonl \
  --base-url http://127.0.0.1:8185 \
  --out report.json
```

Metrics: `rating_accuracy`, `rating_distance` (ordinal 0–3), `high_f1`,
`determinism`, `latency_p50_s`, `latency_p95_s`.

## Deployment

- API: `uvicorn` bound to `127.0.0.1:8185`
- Reverse proxy (nginx) → `https://carly17.my.id/vulnfeed/`
- Miner manifest served at `/vulnfeed.yaml` and `https://carly17.my.id/vulnfeed/vulnfeed.yaml`
- systemd unit: `deploy/vulnfeed.service`
- Container build: `Dockerfile`

## Security

- API binds loopback only; exposed through an authenticated reverse proxy.
- No API keys are stored on-chain; the public resolver path uses `auth: none`.
- Deterministic output with per-IP rate limiting at the proxy.

## License

MIT
