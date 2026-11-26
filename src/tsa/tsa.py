"""TSA da federação segundo o RFC 3161, com `openssl ts`.

A biblioteca `cryptography` não gera nem verifica tokens RFC 3161 (CMS/ASN.1), por isso:
- a TSA responde com `openssl ts -reply` (chave RSA-3072, SHA-256, política fixa, serial
  persistido num ficheiro que o próprio openssl incrementa antes de assinar);
- o Gateway cria o pedido (TimeStampReq) com um nonce de 64 bits tirado de `secrets`;
- membros, Gateway e Arbiter verificam o token com `openssl ts -verify` contra a raiz da CA,
  e este módulo lê os campos do TSTInfo (serial, hora, hash, nonce, política) com um leitor
  DER mínimo, só para os conferir e expor.

O token liga-se ao hash (message imprint SHA-256) do envelope, calculado por quem pede; a TSA
nunca vê mais do que esse hash. O certificado da TSA é emitido pela CA com EKU `timeStamping`
crítica e vai dentro do token (o pedido leva certReq = TRUE), por isso o verificador só precisa
da raiz da CA. O `openssl ts -verify` recusa signatários sem essa EKU crítica.

Requer OpenSSL >= 3 (o LibreSSL do macOS não serve; usar FED_OPENSSL para indicar o binário).
"""

from __future__ import annotations

import hmac
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

OPENSSL = os.environ.get("FED_OPENSSL", "openssl")
OPENSSL_TIMEOUT = 30  # segundos

IMPRINT_LEN = 32
NONCE_BITS = 64
MAX_REQUEST_LEN = 1024
TSA_KEY_BITS = 3072
CLOCK_SKEW = timedelta(minutes=5)

# OID de exemplo (o mesmo do openssl.cnf de referência). Trocar por um OID da organização.
DEFAULT_POLICY_OID = "1.2.3.4.1"

SERIAL_FILE = "tsa_serial"
CONFIG_FILE = "tsa.cnf"

# Conteúdos DER (sem tag nem comprimento) dos OIDs usados
_OID_SHA256 = bytes.fromhex("608648016503040201")            # 2.16.840.1.101.3.4.2.1
_OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")       # 1.2.840.113549.1.7.2
_OID_TST_INFO = bytes.fromhex("2a864886f70d0109100104")      # 1.2.840.113549.1.9.16.1.4

# Tags DER
_INTEGER, _BOOLEAN, _OCTET_STRING, _NULL, _OID = 0x02, 0x01, 0x04, 0x05, 0x06
_GENERALIZED_TIME, _SEQUENCE, _SET = 0x18, 0x30, 0x31
_CTX0, _CTX1 = 0xA0, 0xA1

# PKIStatus (RFC 3161, secção 2.4.2)
_STATUS_GRANTED = (0, 1)  # granted, grantedWithMods


class TSAError(Exception):
    """Erro do serviço de timestamp (configuração, estado, pedido inválido, openssl)."""


class TokenError(TSAError):
    """Token ou resposta malformados, ou que não passam a verificação."""


class _DERError(ValueError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- Leitor e escritor DER mínimos ---

def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Lê um TLV em `pos`. Devolve (tag, início do conteúdo, fim do conteúdo)."""
    if pos + 2 > len(data):
        raise _DERError("TLV truncado")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise _DERError("tags de número alto não suportadas")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise _DERError("comprimento inválido (DER não admite comprimento indefinido)")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise _DERError("conteúdo truncado")
    return tag, pos, end


def _single(data: bytes, expected_tag: int) -> bytes:
    """Lê exatamente um TLV com a tag esperada e devolve o conteúdo."""
    tag, start, end = _read_tlv(data, 0)
    if tag != expected_tag or end != len(data):
        raise _DERError(f"esperado um único elemento com tag {expected_tag:#x}")
    return data[start:end]


def _children(content: bytes) -> list[tuple[int, bytes]]:
    """Elementos de um SEQUENCE/SET (ou de uma tag explícita): lista de (tag, conteúdo)."""
    out, pos = [], 0
    while pos < len(content):
        tag, start, end = _read_tlv(content, pos)
        out.append((tag, content[start:end]))
        pos = end
    return out


def _expect(item: tuple[int, bytes], tag: int) -> bytes:
    if item[0] != tag:
        raise _DERError(f"esperada tag {tag:#x}, encontrada {item[0]:#x}")
    return item[1]


def _uint(content: bytes) -> int:
    if not content:
        raise _DERError("INTEGER vazio")
    value = int.from_bytes(content, "big", signed=True)
    if value < 0:
        raise _DERError("INTEGER negativo")
    return value


def _oid_to_str(content: bytes) -> str:
    if not content:
        raise _DERError("OID vazio")
    arcs, value = [], 0
    for byte in content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if content[-1] & 0x80:
        raise _DERError("OID truncado")
    first = arcs[0]
    head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    return ".".join(str(a) for a in head + arcs[1:])


def _generalized_time(content: bytes) -> datetime:
    """GeneralizedTime em UTC: AAAAMMDDhhmmss[.fff]Z."""
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _DERError("GeneralizedTime não é ASCII") from exc
    if not text.endswith("Z") or len(text) < 15:
        raise _DERError("GeneralizedTime tem de estar em UTC (sufixo Z)")
    base, frac = text[:14], text[14:-1]
    try:
        moment = datetime.strptime(base, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise _DERError("GeneralizedTime inválido") from exc
    if frac:
        digits = frac[1:]
        if frac[0] != "." or not digits.isdigit() or len(digits) > 6:
            raise _DERError("fração de segundo inválida")
        moment += timedelta(microseconds=int(digits.ljust(6, "0")))
    return moment


def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _der_uint(value: int) -> bytes:
    if value < 0:
        raise ValueError("só inteiros não negativos")
    return _tlv(_INTEGER, value.to_bytes(value.bit_length() // 8 + 1, "big"))


# --- Pedido (Gateway) ---

@dataclass(frozen=True)
class TimestampRequest:
    der: bytes      # TimeStampReq, corpo application/timestamp-query
    imprint: bytes
    nonce: int


def create_request(imprint: bytes, nonce: Optional[int] = None) -> TimestampRequest:
    """Cria um TimeStampReq (RFC 3161) para um hash SHA-256 de 32 bytes.

    O nonce (64 bits, `secrets`) permite ao Gateway confirmar que a resposta é a este pedido.
    certReq = TRUE para o certificado da TSA ir dentro do token.
    """
    if len(imprint) != IMPRINT_LEN:
        raise TSAError(f"O hash tem de ter {IMPRINT_LEN} bytes (SHA-256).")
    if nonce is None:
        nonce = secrets.randbits(NONCE_BITS)
    if nonce < 0:
        raise TSAError("O nonce não pode ser negativo.")
    message_imprint = _tlv(_SEQUENCE, _tlv(_SEQUENCE, _tlv(_OID, _OID_SHA256))
                           + _tlv(_OCTET_STRING, imprint))
    der = _tlv(_SEQUENCE, _der_uint(1) + message_imprint + _der_uint(nonce)
               + _tlv(_BOOLEAN, b"\xff"))
    return TimestampRequest(der=der, imprint=imprint, nonce=nonce)


def parse_request(der: bytes) -> TimestampRequest:
    """Lê um TimeStampReq e confirma versão 1, SHA-256 e hash de 32 bytes (lado da TSA)."""
    if len(der) > MAX_REQUEST_LEN:
        raise TSAError("Pedido demasiado longo.")
    try:
        fields = _children(_single(der, _SEQUENCE))
        if len(fields) < 2 or _uint(_expect(fields[0], _INTEGER)) != 1:
            raise _DERError("versão do pedido não suportada")
        imprint_fields = _children(_expect(fields[1], _SEQUENCE))
        if len(imprint_fields) != 2:
            raise _DERError("messageImprint malformado")
        alg = _children(_expect(imprint_fields[0], _SEQUENCE))
        if not alg or _expect(alg[0], _OID) != _OID_SHA256:
            raise _DERError("só SHA-256 é aceite")
        if len(alg) > 2 or (len(alg) == 2 and alg[1] != (_NULL, b"")):
            raise _DERError("parâmetros do algoritmo de hash inválidos")
        imprint = _expect(imprint_fields[1], _OCTET_STRING)
        if len(imprint) != IMPRINT_LEN:
            raise _DERError("o hash tem de ter 32 bytes")
        nonce = 0
        for tag, content in fields[2:]:
            if tag == _INTEGER:
                nonce = _uint(content)
            elif tag not in (_OID, _BOOLEAN, _CTX0):
                raise _DERError(f"campo inesperado {tag:#x}")
    except _DERError as exc:
        raise TSAError(f"Pedido de timestamp inválido: {exc}") from exc
    return TimestampRequest(der=der, imprint=imprint, nonce=nonce)


# --- Resposta e token ---

@dataclass(frozen=True)
class TimestampToken:
    """Campos lidos do TSTInfo. `der` é o TimeStampToken (ContentInfo CMS) que vai no envelope."""
    der: bytes
    serial: int
    gen_time: datetime
    imprint: bytes
    nonce: Optional[int]
    policy: str

    @property
    def gen_time_iso(self) -> str:
        """Hora em ISO 8601 UTC com milissegundos (para "quem reportou primeiro")."""
        t = self.gen_time
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def token_from_response(response_der: bytes) -> bytes:
    """Extrai o TimeStampToken de um TimeStampResp. Lança TokenError se a TSA recusou."""
    try:
        fields = _children(_single(response_der, _SEQUENCE))
        if not fields:
            raise _DERError("resposta vazia")
        status_info = _children(_expect(fields[0], _SEQUENCE))
        status = _uint(_expect(status_info[0], _INTEGER)) if status_info else -1
        if status not in _STATUS_GRANTED:
            raise TokenError(f"A TSA recusou o pedido (PKIStatus {status}).")
        if len(fields) != 2:
            raise _DERError("resposta sem token")
        tag, content = fields[1]
        token = _tlv(tag, content)
        _expect(fields[1], _SEQUENCE)
    except _DERError as exc:
        raise TokenError(f"Resposta de timestamp malformada: {exc}") from exc
    return token


def parse_token(token_der: bytes) -> TimestampToken:
    """Lê os campos do TSTInfo dentro de um TimeStampToken. Não verifica a assinatura."""
    try:
        content_info = _children(_single(token_der, _SEQUENCE))
        if len(content_info) != 2 or _expect(content_info[0], _OID) != _OID_SIGNED_DATA:
            raise _DERError("não é um SignedData CMS")
        signed_data = _children(_single(_expect(content_info[1], _CTX0), _SEQUENCE))
        if len(signed_data) < 4:
            raise _DERError("SignedData incompleto")
        encap = _children(_expect(signed_data[2], _SEQUENCE))
        if len(encap) != 2 or _expect(encap[0], _OID) != _OID_TST_INFO:
            raise _DERError("o conteúdo não é um TSTInfo")
        tst_der = _single(_expect(encap[1], _CTX0), _OCTET_STRING)

        tst = _children(_single(tst_der, _SEQUENCE))
        if len(tst) < 5 or _uint(_expect(tst[0], _INTEGER)) != 1:
            raise _DERError("versão do TSTInfo não suportada")
        policy = _oid_to_str(_expect(tst[1], _OID))
        mi = _children(_expect(tst[2], _SEQUENCE))
        if len(mi) != 2:
            raise _DERError("messageImprint malformado")
        alg = _children(_expect(mi[0], _SEQUENCE))
        if not alg or _expect(alg[0], _OID) != _OID_SHA256:
            raise _DERError("o token não usa SHA-256")
        imprint = _expect(mi[1], _OCTET_STRING)
        serial = _uint(_expect(tst[3], _INTEGER))
        gen_time = _generalized_time(_expect(tst[4], _GENERALIZED_TIME))
        nonce = None
        for tag, value in tst[5:]:
            if tag == _INTEGER:
                nonce = _uint(value)
            elif tag not in (_SEQUENCE, _BOOLEAN, _CTX0, _CTX1):
                raise _DERError(f"campo inesperado no TSTInfo {tag:#x}")
    except _DERError as exc:
        raise TokenError(f"Token malformado: {exc}") from exc
    return TimestampToken(der=token_der, serial=serial, gen_time=gen_time, imprint=imprint,
                          nonce=nonce, policy=policy)


# --- openssl ---

def _run_openssl(args: list[str], *, openssl: str = OPENSSL,
                 env_extra: Optional[dict] = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(env_extra or {})
    try:
        return subprocess.run([openssl, *args], capture_output=True, timeout=OPENSSL_TIMEOUT,
                              env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TSAError(f"Não foi possível correr o openssl: {exc}") from exc


def openssl_available(openssl: str = OPENSSL) -> bool:
    """True se `openssl` existe e é OpenSSL (não LibreSSL) com versão >= 3."""
    if shutil.which(openssl) is None:
        return False
    try:
        out = _run_openssl(["version"], openssl=openssl).stdout.decode()
    except TSAError:
        return False
    parts = out.split()
    if len(parts) < 2 or parts[0] != "OpenSSL":
        return False
    try:
        return int(parts[1].split(".")[0]) >= 3
    except ValueError:
        return False


# --- Verificação (membros, Gateway, Arbiter) ---

def verify_token(token_der: bytes, ca_cert: x509.Certificate, imprint: bytes, *,
                 nonce: Optional[int] = None, policy: Optional[str] = None,
                 now: Optional[datetime] = None, max_age: Optional[timedelta] = None,
                 openssl: str = OPENSSL) -> TimestampToken:
    """Verifica um TimeStampToken e devolve os seus campos.

    1. Lê o TSTInfo e confere o hash, o nonce (se dado: o Gateway) e a política (se dada).
    2. `openssl ts -verify -token_in -digest ... -CAfile raiz -attime <hora do token>`:
       assinatura CMS, cadeia até à raiz, EKU timeStamping crítica, atributo ESS que liga
       o certificado do signatário, e hash. O certificado só tem de ser válido à hora do token,
       para que um token continue verificável depois de o certificado da TSA expirar.
    3. Hora não futura e, se pedido, idade máxima (ex.: 30 dias para disputas).
    """
    now = now or _utcnow()
    token = parse_token(token_der)
    if not hmac.compare_digest(token.imprint, imprint):
        raise TokenError("O token não corresponde ao hash pedido.")
    if nonce is not None and token.nonce != nonce:
        raise TokenError("Nonce do token não corresponde ao do pedido.")
    if policy is not None and token.policy != policy:
        raise TokenError("Política do token não é a esperada.")

    with tempfile.TemporaryDirectory(prefix="fed-tsv-") as tmp:
        token_path = Path(tmp) / "token.der"
        ca_path = Path(tmp) / "ca.pem"
        token_path.write_bytes(token_der)
        ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        proc = _run_openssl([
            "ts", "-verify", "-token_in", "-in", str(token_path),
            "-digest", imprint.hex(), "-CAfile", str(ca_path),
            "-attime", str(int(token.gen_time.timestamp())),
        ], openssl=openssl)
    if proc.returncode != 0 or b"Verification: OK" not in proc.stdout:
        detail = (proc.stderr or proc.stdout).decode(errors="replace").strip().splitlines()
        raise TokenError("Token recusado pelo openssl ts -verify"
                         + (f": {detail[-1]}" if detail else "."))

    if token.gen_time > now + CLOCK_SKEW:
        raise TokenError("Token com hora no futuro.")
    if max_age is not None and now - token.gen_time > max_age:
        raise TokenError("Token mais antigo do que o permitido.")
    return token


# --- A TSA ---

def _config_text(serial_path: Path, cert_path: Path, key_path: Path, policy: str) -> str:
    for p in (serial_path, cert_path, key_path):
        if any(ch in str(p) for ch in "$\\\"'\n"):
            raise TSAError(f"Caminho com caracteres não suportados pela configuração do openssl: {p}")
    return f"""# Gerado por src/tsa/tsa.py; não editar à mão.
[ tsa ]
default_tsa = fed_tsa

[ fed_tsa ]
serial = {serial_path}
crypto_device = builtin
signer_cert = {cert_path}
signer_key = {key_path}
signer_digest = sha256
default_policy = {policy}
digests = sha256
accuracy = secs:1
clock_precision_digits = 3
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


class TimestampAuthority:
    """Emissor de respostas RFC 3161 via `openssl ts -reply`.

    O serial fica em `state_dir/tsa_serial` (hexadecimal). O openssl lê-o, incrementa-o e
    grava-o antes de assinar, por isso um crash nunca repete um serial. Se o ficheiro
    desaparecer ou ficar ilegível, a TSA recusa emitir (o openssl recomeçaria em 1).
    Um único processo por ficheiro de serial (uvicorn sem --workers); o lock serializa os pedidos.
    """

    def __init__(self, key_path, cert_path, state_dir, *, passphrase: Optional[str] = None,
                 policy: str = DEFAULT_POLICY_OID, openssl: str = OPENSSL):
        self._key_path = Path(key_path).resolve()
        self._cert_path = Path(cert_path).resolve()
        self._state_dir = Path(state_dir).resolve()
        self._passphrase = passphrase
        self._openssl = openssl
        self.policy = policy
        if passphrase == "":
            raise TSAError("Passphrase vazia: use None para uma chave sem cifra.")
        if not openssl_available(openssl):
            raise TSAError(f"'{openssl}' não é OpenSSL >= 3 (defina FED_OPENSSL).")

        try:
            key = serialization.load_pem_private_key(
                self._key_path.read_bytes(),
                password=passphrase.encode("utf-8") if passphrase else None)
            self.cert = x509.load_pem_x509_certificate(self._cert_path.read_bytes())
        except (OSError, ValueError, TypeError) as exc:
            raise TSAError(f"Não foi possível carregar a chave ou o certificado da TSA: {exc}") from exc
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < TSA_KEY_BITS:
            raise TSAError(f"A chave da TSA tem de ser RSA com pelo menos {TSA_KEY_BITS} bits.")
        der = lambda k: k.public_bytes(  # noqa: E731
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if der(key.public_key()) != der(self.cert.public_key()):
            raise TSAError("A chave privada não corresponde ao certificado da TSA.")
        try:
            eku = self.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        except x509.ExtensionNotFound as exc:
            raise TSAError("O certificado não tem EKU timeStamping.") from exc
        if not eku.critical or list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
            raise TSAError("O certificado tem de ter EKU timeStamping, crítica e única.")

        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._serial_path = self._state_dir / SERIAL_FILE
        if not self._serial_path.exists():
            self._serial_path.write_text("00\n")
        self.last_serial()  # falha já se o ficheiro estiver corrompido
        self._config_path = self._state_dir / CONFIG_FILE
        self._config_path.write_text(
            _config_text(self._serial_path, self._cert_path, self._key_path, policy))
        self._lock = threading.Lock()

    def last_serial(self) -> int:
        """Último serial emitido (lido do ficheiro). Lança TSAError se o estado estiver mau."""
        try:
            text = self._serial_path.read_text().strip()
            if not text:
                raise ValueError("vazio")
            return int(text, 16)
        except (OSError, ValueError) as exc:
            raise TSAError(f"Serial da TSA ilegível ({exc}); recusa emitir para não repetir seriais.") from exc

    def stamp(self, request_der: bytes) -> bytes:
        """Recebe um TimeStampReq (DER) e devolve o TimeStampResp (DER) assinado."""
        parse_request(request_der)
        now = _utcnow()
        if not (self.cert.not_valid_before_utc <= now <= self.cert.not_valid_after_utc):
            raise TSAError("O certificado da TSA não é válido neste momento.")
        args = ["ts", "-reply", "-config", str(self._config_path), "-section", "fed_tsa"]
        env = {}
        if self._passphrase is not None:
            env["FED_TSA_PASSIN"] = self._passphrase
            args += ["-passin", "env:FED_TSA_PASSIN"]
        with self._lock, tempfile.TemporaryDirectory(prefix="fed-tsa-") as tmp:
            self.last_serial()  # o openssl recomeçaria em 1 sem o ficheiro
            req_path, resp_path = Path(tmp) / "req.tsq", Path(tmp) / "resp.tsr"
            req_path.write_bytes(request_der)
            proc = _run_openssl(args + ["-queryfile", str(req_path), "-out", str(resp_path)],
                                openssl=self._openssl, env_extra=env)
            if proc.returncode != 0 or not resp_path.exists():
                raise TSAError("openssl ts -reply falhou: "
                               + proc.stderr.decode(errors="replace").strip()[-300:])
            return resp_path.read_bytes()


def load_from_env() -> TimestampAuthority:
    """Configuração por variáveis de ambiente (usada pelo serviço)."""
    try:
        return TimestampAuthority(
            os.environ["FED_TSA_KEY"], os.environ["FED_TSA_CERT"], os.environ["FED_TSA_STATE"],
            passphrase=os.environ.get("FED_TSA_KEY_PASSPHRASE"),
            policy=os.environ.get("FED_TSA_POLICY", DEFAULT_POLICY_OID))
    except KeyError as exc:
        raise TSAError(f"Variável de ambiente em falta: {exc}") from exc
