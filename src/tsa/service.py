"""Serviço HTTP da TSA (FastAPI), RFC 3161 sobre HTTP (RFC 3161, secção 3.4).

`POST /v1/timestamp` com corpo `application/timestamp-query` (TimeStampReq DER) devolve
`application/timestamp-reply` (TimeStampResp DER).

Arranque (TLS mútuo, sem logs de acesso, um único processo por causa do ficheiro de serial).
O certificado TLS é um certificado de servidor próprio: o da TSA tem só a EKU timeStamping
e não serve para TLS.

    FED_TSA_KEY=data/tsa/tsa.key FED_TSA_CERT=data/tsa/tsa.pem FED_TSA_STATE=data/tsa/state \\
    FED_TSA_KEY_PASSPHRASE=... \\
    uvicorn --factory src.tsa.service:app_from_env --no-access-log \\
        --ssl-keyfile data/tsa/tls.key --ssl-certfile data/tsa/tls.pem \\
        --ssl-ca-certs data/ca/ca.cert.pem --ssl-cert-reqs 2

A TSA só vê um hash: nunca o conteúdo nem a identidade de quem reporta.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from src.tsa.tsa import MAX_REQUEST_LEN, TimestampAuthority, TSAError, load_from_env

QUERY_TYPE = "application/timestamp-query"
REPLY_TYPE = "application/timestamp-reply"


def create_app(tsa: TimestampAuthority) -> FastAPI:
    app = FastAPI(title="TSA da federação", docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/timestamp")
    async def timestamp(request: Request) -> Response:
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != QUERY_TYPE:
            raise HTTPException(status_code=415, detail=f"Content-Type tem de ser {QUERY_TYPE}")
        body = await request.body()
        if len(body) > MAX_REQUEST_LEN:
            raise HTTPException(status_code=413, detail="Pedido demasiado longo")
        try:
            reply = await run_in_threadpool(tsa.stamp, body)  # o openssl bloqueia
        except TSAError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return Response(content=reply, media_type=REPLY_TYPE)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


def app_from_env() -> FastAPI:
    return create_app(load_from_env())
