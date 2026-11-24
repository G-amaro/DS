"""Serviço HTTP da TSA (FastAPI). Recebe um hash e devolve o token.

Arranque (TLS mútuo, sem logs de acesso):

    FED_TSA_KEY=data/tsa/tsa.key FED_TSA_CERT=data/tsa/tsa.pem FED_TSA_STATE=data/tsa/state.json \\
    uvicorn --factory src.tsa.service:app_from_env --no-access-log \\
        --ssl-keyfile data/tsa/tsa.key --ssl-certfile data/tsa/tsa.pem \\
        --ssl-ca-certs data/ca/ca.cert.pem --ssl-cert-reqs 2

A TSA só vê um hash: nunca o conteúdo nem a identidade de quem reporta.
"""

from __future__ import annotations

import base64
import binascii
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.tsa.tsa import IMPRINT_LEN, MAX_NONCE_LEN, TimestampAuthority, TSAError


class StampRequest(BaseModel):
    imprint: str = Field(description="SHA-256 do envelope, em base64")
    nonce: str | None = Field(default=None, description="nonce opcional, em base64")


def _b64(value: str, name: str, max_len: int) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{name} não é base64 válido") from exc
    if len(raw) > max_len:
        raise HTTPException(status_code=400, detail=f"{name} demasiado longo")
    return raw


def create_app(tsa: TimestampAuthority) -> FastAPI:
    app = FastAPI(title="TSA da federação", docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/timestamp")
    def timestamp(req: StampRequest) -> dict:
        imprint = _b64(req.imprint, "imprint", IMPRINT_LEN)
        nonce = _b64(req.nonce, "nonce", MAX_NONCE_LEN) if req.nonce else None
        try:
            return tsa.stamp(imprint, nonce).to_dict()
        except TSAError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


def app_from_env() -> FastAPI:
    tsa = TimestampAuthority.load(
        os.environ["FED_TSA_KEY"], os.environ["FED_TSA_CERT"], os.environ["FED_TSA_STATE"],
        passphrase=os.environ.get("FED_TSA_KEY_PASSPHRASE"))
    return create_app(tsa)
