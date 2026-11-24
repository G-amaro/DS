"""TSA própria da federação: token de timestamp simplificado, assinado com Ed25519.

Decisão (a declarar no relatório): em vez de RFC 3161 completo (ASN.1/CMS, que a biblioteca
`cryptography` não gera), a TSA assina um token próprio com o hash, a hora e um número de série.
Mantém as propriedades de que a federação precisa: a hora vem de uma entidade independente de
quem reporta, o token é verificável por qualquer membro com a raiz da CA, e não revela conteúdo
nem identidade (a TSA só vê um hash). O que se perde face ao RFC 3161: interoperabilidade com
ferramentas padrão (openssl ts, Adobe, etc.) e campos como a política e a precisão.

O token liga-se a:
- o hash (message imprint, SHA-256) do envelope, calculado por quem pede;
- um número de série estritamente crescente, persistido antes de o token sair;
- a hora de geração (ms desde 1970, UTC), nunca a recuar;
- um nonce opcional do requerente (frescura da resposta);
- a impressão digital do certificado da TSA (impede trocar o certificado por outro válido).

O certificado da TSA é emitido pela CA com EKU `timeStamping` crítica e vai dentro do token,
por isso um verificador só precisa da raiz da CA.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import struct
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID

from src.ca import ca as ca_mod

DOMAIN_TSA = b"FED-TSA-v1"
TOKEN_VERSION = 1
HASH_ALG = "sha256"
IMPRINT_LEN = 32
MAX_NONCE_LEN = 64
CLOCK_SKEW = timedelta(minutes=5)


class TSAError(Exception):
    """Erro do serviço de timestamp (configuração, estado, pedido inválido)."""


class TokenError(TSAError):
    """Token malformado ou que não passa a verificação."""


def _lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _signed_message(version: int, hash_alg: str, imprint: bytes, serial: int,
                    gen_time_ms: int, nonce: bytes, cert_der: bytes) -> bytes:
    """Mensagem assinada: todos os campos com prefixo de comprimento e separação de domínio."""
    return (
        DOMAIN_TSA
        + _lp(struct.pack(">I", version))
        + _lp(hash_alg.encode("ascii"))
        + _lp(imprint)
        + _lp(struct.pack(">Q", serial))
        + _lp(struct.pack(">Q", gen_time_ms))
        + _lp(nonce)
        + _lp(hashlib.sha256(cert_der).digest())
    )


@dataclass(frozen=True)
class TimestampToken:
    serial: int
    gen_time_ms: int
    imprint: bytes
    nonce: bytes
    tsa_cert_der: bytes
    signature: bytes
    hash_alg: str = HASH_ALG
    version: int = TOKEN_VERSION

    @property
    def gen_time(self) -> datetime:
        return datetime.fromtimestamp(self.gen_time_ms / 1000, tz=timezone.utc)

    @property
    def gen_time_iso(self) -> str:
        """Hora em ISO 8601 UTC com milissegundos."""
        return self.gen_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.gen_time_ms % 1000:03d}Z"

    def to_dict(self) -> dict:
        b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
        return {
            "version": self.version, "hash_alg": self.hash_alg, "serial": self.serial,
            "gen_time_ms": self.gen_time_ms, "gen_time": self.gen_time_iso,
            "imprint": b64(self.imprint), "nonce": b64(self.nonce),
            "tsa_cert": b64(self.tsa_cert_der), "signature": b64(self.signature),
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_dict(cls, d: dict) -> "TimestampToken":
        try:
            def raw(name: str) -> bytes:
                return base64.b64decode(d[name], validate=True)

            def integer(name: str) -> int:
                v = d[name]
                if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                    raise ValueError(name)
                return v

            alg = d["hash_alg"]
            if not isinstance(alg, str):
                raise ValueError("hash_alg")
            return cls(
                serial=integer("serial"), gen_time_ms=integer("gen_time_ms"),
                imprint=raw("imprint"), nonce=raw("nonce"), tsa_cert_der=raw("tsa_cert"),
                signature=raw("signature"), hash_alg=alg, version=integer("version"),
            )
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise TokenError(f"Token malformado: {exc!r}") from exc

    @classmethod
    def from_bytes(cls, data: bytes) -> "TimestampToken":
        try:
            d = json.loads(data)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TokenError("Token não é JSON válido.") from exc
        if not isinstance(d, dict):
            raise TokenError("Token malformado: esperado um objeto JSON.")
        return cls.from_dict(d)


# --- Verificação (membros, Gateway, Arbiter) ---

def verify_token(token: TimestampToken, ca_cert: x509.Certificate, imprint: bytes, *,
                 nonce: Optional[bytes] = None, now: Optional[datetime] = None,
                 max_age: Optional[timedelta] = None) -> datetime:
    """Verifica um token e devolve a hora de geração (datetime UTC).

    Confirma: versão e algoritmo, hash pedido, nonce (se dado), certificado da TSA emitido pela CA
    e válido à hora do token com EKU timeStamping, assinatura, hora não futura e idade máxima.
    O certificado só tem de ser válido quando o token foi emitido, não agora.
    """
    now = now or _utcnow()
    if token.version != TOKEN_VERSION or token.hash_alg != HASH_ALG:
        raise TokenError("Versão ou algoritmo de hash do token não suportados.")
    if not hmac.compare_digest(token.imprint, imprint):
        raise TokenError("O token não corresponde ao hash pedido.")
    if nonce is not None and not hmac.compare_digest(token.nonce, nonce):
        raise TokenError("Nonce do token não corresponde.")

    try:
        cert = x509.load_der_x509_certificate(token.tsa_cert_der)
    except ValueError as exc:
        raise TokenError("Certificado da TSA ilegível.") from exc
    try:
        ca_mod.verify_certificate(cert, ca_cert, now=token.gen_time)
    except ca_mod.CAError as exc:
        raise TokenError(f"Certificado da TSA não aceite: {exc}") from exc
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as exc:
        raise TokenError("Certificado sem EKU: não é um certificado de TSA.") from exc
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku.value:
        raise TokenError("Certificado sem EKU timeStamping.")
    pub = cert.public_key()
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise TokenError("A chave da TSA não é Ed25519.")

    message = _signed_message(token.version, token.hash_alg, token.imprint, token.serial,
                              token.gen_time_ms, token.nonce, token.tsa_cert_der)
    try:
        pub.verify(token.signature, message)
    except InvalidSignature as exc:
        raise TokenError("Assinatura do token inválida.") from exc

    if token.gen_time > now + CLOCK_SKEW:
        raise TokenError("Token com hora no futuro.")
    if max_age is not None and now - token.gen_time > max_age:
        raise TokenError("Token mais antigo do que o permitido.")
    return token.gen_time


# --- A TSA ---

class TimestampAuthority:
    """Emissor de tokens. O estado (último serial e hora) é persistido antes de cada token sair."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey, cert: x509.Certificate,
                 state_path, clock: Callable[[], datetime] = _utcnow):
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TSAError("A chave da TSA tem de ser Ed25519.")
        pub_raw = lambda k: k.public_bytes(  # noqa: E731
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if pub_raw(private_key.public_key()) != pub_raw(cert.public_key()):
            raise TSAError("A chave privada não corresponde ao certificado da TSA.")
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            eku = []
        if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
            raise TSAError("O certificado não tem EKU timeStamping.")
        self._key = private_key
        self._cert = cert
        self._cert_der = cert.public_bytes(serialization.Encoding.DER)
        self._state_path = Path(state_path)
        self._clock = clock
        self._lock = threading.Lock()
        self._last_serial, self._last_time_ms = self._load_state()

    @classmethod
    def load(cls, key_path, cert_path, state_path, passphrase: Optional[str] = None,
             clock: Callable[[], datetime] = _utcnow) -> "TimestampAuthority":
        try:
            key = serialization.load_pem_private_key(
                Path(key_path).read_bytes(),
                password=passphrase.encode("utf-8") if passphrase else None)
            cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        except (OSError, ValueError, TypeError) as exc:
            raise TSAError(f"Não foi possível carregar a chave ou o certificado da TSA: {exc}") from exc
        return cls(key, cert, state_path, clock)

    def _load_state(self) -> tuple[int, int]:
        if not self._state_path.exists():
            return 0, 0
        try:
            d = json.loads(self._state_path.read_text())
            serial, last_ms = d["last_serial"], d["last_time_ms"]
            if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (serial, last_ms)):
                raise ValueError("valores inválidos")
            return serial, last_ms
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # Falhar fechado: reiniciar a 0 reutilizaria números de série.
            raise TSAError(f"Estado da TSA ilegível ({exc}); recusa arrancar para não repetir seriais.") from exc

    def _persist(self, serial: int, time_ms: int) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._state_path.parent, prefix=".tsa-state-")
        with os.fdopen(fd, "w") as f:
            json.dump({"last_serial": serial, "last_time_ms": time_ms}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_path)

    def stamp(self, imprint: bytes, nonce: Optional[bytes] = None) -> TimestampToken:
        """Emite um token para um hash SHA-256 (32 bytes)."""
        if len(imprint) != IMPRINT_LEN:
            raise TSAError(f"O hash tem de ter {IMPRINT_LEN} bytes (SHA-256).")
        nonce = nonce or b""
        if len(nonce) > MAX_NONCE_LEN:
            raise TSAError(f"Nonce demasiado longo (máximo {MAX_NONCE_LEN} bytes).")
        with self._lock:
            now = self._clock()
            if not (self._cert.not_valid_before_utc <= now <= self._cert.not_valid_after_utc):
                raise TSAError("O certificado da TSA não é válido neste momento.")
            now_ms = int(now.timestamp() * 1000)
            gen_ms = max(now_ms, self._last_time_ms)  # a hora nunca recua
            serial = self._last_serial + 1
            self._persist(serial, gen_ms)  # antes de assinar: um crash nunca repete o serial
            self._last_serial, self._last_time_ms = serial, gen_ms
            signature = self._key.sign(_signed_message(
                TOKEN_VERSION, HASH_ALG, imprint, serial, gen_ms, nonce, self._cert_der))
        return TimestampToken(serial=serial, gen_time_ms=gen_ms, imprint=imprint, nonce=nonce,
                              tsa_cert_der=self._cert_der, signature=signature)
