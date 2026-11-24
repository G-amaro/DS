"""CA privada da federação (módulo offline).

Responsabilidades (ver plano, secção 4 e passo 2):
- gerar a raiz autoassinada;
- assinar CSRs de servidores (Kafka, Coordinator, Arbiter, Gateway), da TSA
  (extensão timeStamping) e certificados de login de membros (clientAuth);
- assinar CRLs (RFC 5280) com cRLNumber crescente e nextUpdate;
- oferecer verificação de certificados e de CRLs para os restantes serviços;
- exportar keystore/truststore PKCS12 para o Kafka.

A CA nunca emite credenciais de publicação: esse papel é do Coordinator.
O assunto (subject) e as extensões dos certificados são decididos pela CA,
nunca copiados do CSR; do CSR só se aproveita a chave pública, depois de
verificada a prova de posse (assinatura do CSR).

Requer cryptography >= 42.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_VALIDITY_DAYS = 3650
LEAF_VALIDITY_DAYS = 365
CRL_VALIDITY_DAYS = 30
CLOCK_SKEW = timedelta(minutes=5)

KEY_FILE = "ca.key.pem"
CERT_FILE = "ca.cert.pem"
STATE_FILE = "ca_state.json"

REVOCATION_REASONS = {
    "unspecified": None,  # RFC 5280: omitir a extensão
    "key_compromise": x509.ReasonFlags.key_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
}


class CAError(Exception):
    """Erro genérico da CA (certificados, estado, ficheiros)."""


class CSRError(CAError):
    """CSR inválido ou com chave não aceite."""


class CRLError(CAError):
    """CRL inválida, expirada ou antiga."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sign_hash(key) -> Optional[hashes.HashAlgorithm]:
    """Ed25519 assina sem hash externo; as restantes usam SHA-256."""
    return None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()


def _write_private(path: Path, data: bytes) -> None:
    """Escreve um ficheiro com chave privada com permissões 0600."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def fingerprint(cert: x509.Certificate) -> str:
    """Impressão digital SHA-256 (hex minúsculo) do certificado, para confirmar fora de banda."""
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def serial_to_hex(serial: int) -> str:
    return format(serial, "x")


# --- CSR ---

def generate_csr(common_name: str, private_key=None):
    """Gera (chave privada, CSR). Por omissão usa ECDSA P-256; aceita Ed25519 ou outra chave.

    Auxiliar para os serviços e para os membros (que usam Ed25519 para o login).
    """
    if private_key is None:
        private_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, _sign_hash(private_key))
    )
    return private_key, csr


def _validate_csr(csr: x509.CertificateSigningRequest):
    """Verifica a prova de posse do CSR e a robustez da chave. Devolve a chave pública."""
    if not csr.is_signature_valid:
        raise CSRError("Assinatura do CSR inválida (sem prova de posse da chave privada).")
    pub = csr.public_key()
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return pub
    if isinstance(pub, ec.EllipticCurvePublicKey):
        if pub.curve.name not in ("secp256r1", "secp384r1"):
            raise CSRError(f"Curva elíptica não aceite: {pub.curve.name}.")
        return pub
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            raise CSRError("Chave RSA com menos de 2048 bits.")
        return pub
    raise CSRError("Tipo de chave não suportado (aceites: Ed25519, ECDSA P-256/P-384, RSA >= 2048).")


# --- Verificação (usada pelos outros serviços) ---

def verify_certificate(cert: x509.Certificate, ca_cert: x509.Certificate,
                       now: Optional[datetime] = None) -> None:
    """Confirma que `cert` foi emitido diretamente por `ca_cert` e está dentro da validade."""
    now = now or _now()
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise CAError(f"Certificado não emitido por esta CA: {exc}") from exc
    if now < cert.not_valid_before_utc:
        raise CAError("Certificado ainda não é válido.")
    if now > cert.not_valid_after_utc:
        raise CAError("Certificado expirado.")


def verify_crl(crl: x509.CertificateRevocationList, ca_cert: x509.Certificate,
               now: Optional[datetime] = None, previous_number: Optional[int] = None
               ) -> x509.CertificateRevocationList:
    """Valida uma CRL: assinatura da CA, emissor, nextUpdate e cRLNumber.

    `previous_number` é o cRLNumber da última CRL aceite; uma CRL com número igual ou
    inferior é recusada (antiga ou repetida). Os servidores devem guardar o último número.
    """
    now = now or _now()
    if crl.issuer != ca_cert.subject:
        raise CRLError("CRL de outro emissor.")
    if not crl.is_signature_valid(ca_cert.public_key()):
        raise CRLError("Assinatura da CRL inválida.")
    if crl.last_update_utc > now + CLOCK_SKEW:
        raise CRLError("CRL com data de emissão no futuro.")
    if crl.next_update_utc is None or crl.next_update_utc <= now:
        raise CRLError("CRL expirada (nextUpdate ultrapassado).")
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound as exc:
        raise CRLError("CRL sem cRLNumber.") from exc
    if previous_number is not None and number <= previous_number:
        raise CRLError(f"CRL antiga ou repetida (número {number} <= {previous_number}).")
    return crl


def crl_number(crl: x509.CertificateRevocationList) -> int:
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def crl_contains(crl: x509.CertificateRevocationList, serial: int) -> bool:
    """True se o serial consta da CRL."""
    return crl.get_revoked_certificate_by_serial_number(serial) is not None


# --- PKCS12 (Kafka) ---

def to_pkcs12(private_key, cert: x509.Certificate, ca_cert: x509.Certificate,
              password: str, name: str) -> bytes:
    """Keystore PKCS12 (chave, certificado e cadeia) para o broker Kafka."""
    return pkcs12.serialize_key_and_certificates(
        name.encode("utf-8"), private_key, cert, [ca_cert],
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def to_truststore(ca_cert: x509.Certificate, password: str, name: str = "federation-ca") -> bytes:
    """Truststore PKCS12 só com a raiz da CA (formato lido pelo Java)."""
    entry = pkcs12.PKCS12Certificate(ca_cert, name.encode("utf-8"))
    return pkcs12.serialize_java_truststore(
        [entry], serialization.BestAvailableEncryption(password.encode("utf-8"))
    )


# --- A CA ---

class CertificateAuthority:
    """CA privada com estado persistido (certificados emitidos, revogados, cRLNumber)."""

    def __init__(self, directory: Path, key, cert: x509.Certificate, state: dict):
        self.directory = Path(directory)
        self.key = key
        self.cert = cert
        self._state = state

    # criação e carregamento

    @classmethod
    def init(cls, directory, passphrase: str, common_name: str = "Federation Root CA",
             organization: str = "Federation", validity_days: int = ROOT_VALIDITY_DAYS,
             now: Optional[datetime] = None) -> "CertificateAuthority":
        """Gera a raiz autoassinada. A chave fica cifrada em disco com a passphrase."""
        if not passphrase:
            raise CAError("A chave da CA tem de ser protegida por uma passphrase.")
        directory = Path(directory)
        if (directory / KEY_FILE).exists() or (directory / CERT_FILE).exists():
            raise CAError(f"Já existe uma CA em {directory}; não é sobrescrita.")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)

        now = now or _now()
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        _write_private(directory / KEY_FILE, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8"))))
        (directory / CERT_FILE).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        ca = cls(directory, key, cert, {"version": 1, "crl_number": 0, "issued": {}, "revoked": {}})
        ca._save()
        return ca

    @classmethod
    def load(cls, directory, passphrase: str) -> "CertificateAuthority":
        directory = Path(directory)
        try:
            key = serialization.load_pem_private_key(
                (directory / KEY_FILE).read_bytes(), password=passphrase.encode("utf-8"))
            cert = x509.load_pem_x509_certificate((directory / CERT_FILE).read_bytes())
            state = json.loads((directory / STATE_FILE).read_text())
        except FileNotFoundError as exc:
            raise CAError(f"CA incompleta ou inexistente em {directory}: {exc.filename}") from exc
        except (ValueError, TypeError) as exc:
            raise CAError("Não foi possível abrir a chave da CA (passphrase errada ou ficheiro corrompido).") from exc
        return cls(directory, key, cert, state)

    def _save(self) -> None:
        """Escrita atómica do estado."""
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".state-")
        with os.fdopen(fd, "w") as f:
            json.dump(self._state, f, indent=2, sort_keys=True)
        os.replace(tmp, self.directory / STATE_FILE)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.cert)

    @property
    def organization(self) -> str:
        attrs = self.cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return attrs[0].value if attrs else "Federation"

    # emissão

    def _issue(self, csr: x509.CertificateSigningRequest, common_name: str, kind: str,
               unit: str, usage: x509.KeyUsage, extensions: list, days: int,
               now: Optional[datetime]) -> x509.Certificate:
        pub = _validate_csr(csr)
        now = now or _now()
        not_after = min(now + timedelta(days=days), self.cert.not_valid_after_utc)
        if not_after <= now:
            raise CAError("A raiz da CA expirou; não pode emitir novos certificados.")
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(self.cert.subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(usage, critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.cert.public_key()),
                           critical=False)
        )
        for ext, critical in extensions:
            builder = builder.add_extension(ext, critical=critical)
        cert = builder.sign(self.key, hashes.SHA256())
        self._state["issued"][serial_to_hex(cert.serial_number)] = {
            "kind": kind, "subject": common_name, "issued_at": _iso(now),
            "not_after": _iso(not_after),
        }
        self._save()
        return cert

    @staticmethod
    def _signature_only_usage() -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False)

    def issue_server_cert(self, csr: x509.CertificateSigningRequest, common_name: str,
                          dns_names: list[str] | None = None, ip_addresses: list[str] | None = None,
                          days: int = LEAF_VALIDITY_DAYS, now: Optional[datetime] = None
                          ) -> x509.Certificate:
        """Certificado TLS de servidor (Kafka, Coordinator, Arbiter, Gateway). SAN decidido pela CA."""
        sans: list[x509.GeneralName] = [x509.DNSName(n) for n in (dns_names or [])]
        try:
            sans += [x509.IPAddress(ipaddress.ip_address(i)) for i in (ip_addresses or [])]
        except ValueError as exc:
            raise CAError(f"Endereço IP inválido: {exc}") from exc
        if not sans:
            raise CAError("Um certificado de servidor precisa de pelo menos um DNS ou IP no SAN.")
        return self._issue(
            csr, common_name, "server", "servers", self._signature_only_usage(),
            [(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
             (x509.SubjectAlternativeName(sans), False)],
            days, now)

    def issue_tsa_cert(self, csr: x509.CertificateSigningRequest, common_name: str,
                       days: int = LEAF_VALIDITY_DAYS, now: Optional[datetime] = None
                       ) -> x509.Certificate:
        """Certificado da TSA: EKU timeStamping, crítica e única (RFC 3161)."""
        return self._issue(
            csr, common_name, "tsa", "timestamping",
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False),
            [(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True)],
            days, now)

    def issue_member_cert(self, csr: x509.CertificateSigningRequest, member_id: str,
                          days: int = LEAF_VALIDITY_DAYS, now: Optional[datetime] = None
                          ) -> x509.Certificate:
        """Certificado de login de um membro (mTLS com o Coordinator, o Arbiter e o Kafka).

        O CN é o member_id escolhido pelo Coordinator, nunca o do CSR. Serve só para login:
        não é usado para publicar (a publicação usa pk_E e credenciais de lote).
        """
        if not member_id or member_id != member_id.strip() or len(member_id) > 64 or not member_id.isprintable():
            raise CAError("member_id inválido (vazio, com espaços nas pontas, não imprimível ou > 64).")
        return self._issue(
            csr, member_id, "member", "members", self._signature_only_usage(),
            [(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)],
            days, now)

    # revogação e CRL

    def is_revoked(self, serial: int) -> bool:
        return serial_to_hex(serial) in self._state["revoked"]

    def revoke(self, serial: int, reason: str = "unspecified", now: Optional[datetime] = None) -> bool:
        """Marca um certificado emitido por esta CA como revogado. Devolve False se já estava."""
        if reason not in REVOCATION_REASONS:
            raise CAError(f"Motivo desconhecido: {reason}. Válidos: {', '.join(REVOCATION_REASONS)}.")
        key = serial_to_hex(serial)
        if key not in self._state["issued"]:
            raise CAError(f"Serial {key} não foi emitido por esta CA.")
        if key in self._state["revoked"]:
            return False
        self._state["revoked"][key] = {"revoked_at": _iso(now or _now()), "reason": reason}
        self._save()
        return True

    def issue_crl(self, days: int = CRL_VALIDITY_DAYS, now: Optional[datetime] = None
                  ) -> x509.CertificateRevocationList:
        """Assina uma nova CRL com todos os revogados e cRLNumber seguinte."""
        now = now or _now()
        number = self._state["crl_number"] + 1
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(now - CLOCK_SKEW).next_update(now + timedelta(days=days))
            .add_extension(x509.CRLNumber(number), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.cert.public_key()),
                           critical=False)
        )
        for serial_hex, info in sorted(self._state["revoked"].items()):
            entry = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(serial_hex, 16))
                .revocation_date(datetime.strptime(info["revoked_at"], "%Y-%m-%dT%H:%M:%SZ"))
            )
            flag = REVOCATION_REASONS[info["reason"]]
            if flag is not None:
                entry = entry.add_extension(x509.CRLReason(flag), critical=False)
            builder = builder.add_revoked_certificate(entry.build())
        crl = builder.sign(self.key, hashes.SHA256())
        self._state["crl_number"] = number
        self._save()
        return crl


# --- Interface de linha de comandos ---

def _passphrase(confirm: bool = False) -> str:
    env = os.environ.get("FED_CA_PASSPHRASE")
    if env:
        return env
    pw = getpass.getpass("Passphrase da CA: ")
    if confirm and getpass.getpass("Repetir passphrase: ") != pw:
        raise CAError("As passphrases não coincidem.")
    return pw


def _load_csr(path: str) -> x509.CertificateSigningRequest:
    try:
        return x509.load_pem_x509_csr(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise CSRError(f"Não foi possível ler o CSR {path}: {exc}") from exc


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ca", description="CA privada da federação (offline).")
    p.add_argument("--dir", default="data/ca", help="pasta da CA (por omissão data/ca)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="gera a raiz autoassinada")
    s.add_argument("--name", default="Federation Root CA")
    s.add_argument("--org", default="Federation")
    s.add_argument("--days", type=int, default=ROOT_VALIDITY_DAYS)

    s = sub.add_parser("gen-csr", help="gera chave privada (0600) e CSR para um serviço")
    s.add_argument("--cn", required=True)
    s.add_argument("--key-out", required=True)
    s.add_argument("--csr-out", required=True)
    s.add_argument("--ed25519", action="store_true", help="usa Ed25519 em vez de ECDSA P-256")

    s = sub.add_parser("issue-server", help="assina um CSR de servidor")
    s.add_argument("--csr", required=True)
    s.add_argument("--cn", required=True)
    s.add_argument("--dns", action="append", default=[])
    s.add_argument("--ip", action="append", default=[])
    s.add_argument("--out", required=True)
    s.add_argument("--days", type=int, default=LEAF_VALIDITY_DAYS)

    s = sub.add_parser("issue-tsa", help="assina um CSR da TSA")
    s.add_argument("--csr", required=True)
    s.add_argument("--cn", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--days", type=int, default=LEAF_VALIDITY_DAYS)

    s = sub.add_parser("issue-member", help="assina o CSR de login de um membro")
    s.add_argument("--csr", required=True)
    s.add_argument("--member-id", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--days", type=int, default=LEAF_VALIDITY_DAYS)

    s = sub.add_parser("revoke", help="revoga um certificado pelo serial (hex)")
    s.add_argument("--serial", required=True)
    s.add_argument("--reason", default="unspecified", choices=list(REVOCATION_REASONS))

    s = sub.add_parser("crl", help="assina uma nova CRL")
    s.add_argument("--out", required=True)
    s.add_argument("--days", type=int, default=CRL_VALIDITY_DAYS)

    sub.add_parser("fingerprint", help="mostra a impressão digital SHA-256 da raiz")

    s = sub.add_parser("export-pkcs12", help="keystore e truststore PKCS12 para o Kafka")
    s.add_argument("--key", required=True, help="chave privada do serviço (PEM, sem passphrase)")
    s.add_argument("--cert", required=True, help="certificado do serviço (PEM)")
    s.add_argument("--keystore-out", required=True)
    s.add_argument("--truststore-out", required=True)
    s.add_argument("--name", default="service")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.cmd == "init":
            ca = CertificateAuthority.init(args.dir, _passphrase(confirm=True), args.name,
                                           args.org, args.days)
            print(f"CA criada em {args.dir}\nImpressão digital SHA-256: {ca.fingerprint}")
            return 0

        if args.cmd == "gen-csr":
            key = ed25519.Ed25519PrivateKey.generate() if args.ed25519 else None
            key, csr = generate_csr(args.cn, key)
            _write_private(Path(args.key_out), key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            Path(args.csr_out).write_bytes(csr.public_bytes(serialization.Encoding.PEM))
            return 0

        ca = CertificateAuthority.load(args.dir, _passphrase())

        if args.cmd == "issue-server":
            cert = ca.issue_server_cert(_load_csr(args.csr), args.cn, args.dns, args.ip, args.days)
        elif args.cmd == "issue-tsa":
            cert = ca.issue_tsa_cert(_load_csr(args.csr), args.cn, args.days)
        elif args.cmd == "issue-member":
            cert = ca.issue_member_cert(_load_csr(args.csr), args.member_id, args.days)
        elif args.cmd == "revoke":
            try:
                serial = int(args.serial, 16)
            except ValueError as exc:
                raise CAError("Serial inválido (esperado hexadecimal).") from exc
            changed = ca.revoke(serial, args.reason)
            print("Revogado. Gere uma CRL nova com o comando 'crl'." if changed else "Já estava revogado.")
            return 0
        elif args.cmd == "crl":
            crl = ca.issue_crl(args.days)
            Path(args.out).write_bytes(crl.public_bytes(serialization.Encoding.PEM))
            print(f"CRL número {crl_number(crl)} escrita em {args.out}")
            return 0
        elif args.cmd == "fingerprint":
            print(ca.fingerprint)
            return 0
        elif args.cmd == "export-pkcs12":
            password = os.environ.get("FED_P12_PASSWORD") or getpass.getpass("Password do PKCS12: ")
            key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(Path(args.cert).read_bytes())
            verify_certificate(cert, ca.cert)
            Path(args.keystore_out).write_bytes(to_pkcs12(key, cert, ca.cert, password, args.name))
            Path(args.truststore_out).write_bytes(to_truststore(ca.cert, password))
            return 0

        Path(args.out).write_bytes(_pem(cert))
        print(f"Certificado escrito em {args.out} (serial {serial_to_hex(cert.serial_number)})")
        return 0
    except CAError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
