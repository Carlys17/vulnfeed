"""FastAPI service exposing the VulnFeed miner surface for Telegraph."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config, core, resolve
from .validation import normalize_address, validate_rpc

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("vulnfeed")

app = FastAPI(
    title="VulnFeed Miner",
    version="0.1.0",
    description="ONCHAIN_TX_LOOKUP smart-contract security intelligence miner.",
)


class Query(BaseModel):
    address: str = Field(..., description="EVM contract address (0x...)")
    chain_id: int | None = Field(None, description="optional chain id override")
    rpc_url: str | None = Field(None, description="optional RPC override")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "intent": config.INTENT, "version": app.version}


@app.get("/intents")
def intents() -> list[dict]:
    return [
        {
            "intent": config.INTENT,
            "deterministic": True,
            "min_price_usdc": config.MIN_PRICE_USDC,
        }
    ]


@app.post("/v1/analyze")
def analyze(q: Query) -> dict:
    t0 = time.monotonic()
    try:
        addr = normalize_address(q.address)
        rpc = validate_rpc(q.rpc_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    sources, warn = resolve.fetch_sources(addr, rpc)

    if sources:
        result = core.audit_source(sources)
        result.address = addr
    else:
        # No verified source -> fallback heuristic scan (deterministic).
        result = _heuristic_fallback(addr)

    if warn:
        result.warnings.append(warn)

    result.summary = result.summary or "no analysis"
    payload = _to_payload(result)
    payload["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return payload


def _heuristic_fallback(addr: str) -> core.EngineResult:
    """Minimal deterministic fallback when no source is retrievable."""
    return core.EngineResult(
        address=addr,
        risk_score=0.0,
        rating="no_source",
        severity_counts={"high": 0, "medium": 0, "low": 0, "informational": 0},
        findings=[],
        summary="Verified source unavailable; static code audit skipped.",
        warnings=["no verified source; consider providing source or using a verified contract"],
        tool="heuristic",
    )


def _to_payload(result: core.EngineResult) -> dict[str, Any]:
    return {
        "intent": config.INTENT,
        "address": result.address,
        "risk_score": result.risk_score,
        "rating": result.rating,
        "exploit_probability": result.exploit_probability,
        "severity_counts": result.severity_counts,
        "summary": result.summary,
        "findings": result.findings,
        "tool": result.tool,
        "warnings": result.warnings,
        "error": result.error,
    }


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"error": "internal_error"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.HOST, port=config.PORT)
