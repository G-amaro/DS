"""Testes da TSA RFC 3161 (openssl ts). Correr a partir da raiz: python -m pytest.

Precisam de OpenSSL >= 3 no PATH (ou em FED_OPENSSL); sem ele são ignorados.
"""

import hashlib
import subprocess
import threading
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from src.ca import ca as ca_mod
from src.ca.ca import CertificateAuthority
from src.tsa import tsa as tsa_mod
from src.tsa.service import create_app
from src.tsa.tsa import TimestampAuthority, TokenError, TSAError

pytestmark = pytest.mark.skipif(not tsa_mod.openssl_available(),
                                reason="requer OpenSSL >= 3 (defina FED_OPENSSL)")

PW = "pw"
H = hashlib.sha256(b"envelope").digest()


@pytest.fixture(scope="module")
def tsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    return CertificateAuthority.init(tmp_path_factory.mktemp("ca") / "ca", PW)


def _write(tmp_path, key, cert, passphrase=None, name="tsa"):
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    key_path, cert_path = tmp_path / f"{name}.key", tmp_path / f"{name}.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8, enc))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _make_tsa(ca, tmp_path, key, passphrase="segredo", state="state", **kw):
    _, csr = ca_mod.generate_csr("tsa", key)
    cert = ca.issue_tsa_cert(csr, "tsa")
    key_path, cert_path = _write(tmp_path, key, cert, passphrase)
    return TimestampAuthority(key_path, cert_path, tmp_path / state, passphrase=passphrase, **kw)


@pytest.fixture
def tsa(ca, tmp_path, tsa_key):
    return _make_tsa(ca, tmp_path, tsa_key)


def _stamp(tsa, imprint=H):
    req = tsa_mod.create_request(imprint)
    return req, tsa_mod.token_from_response(tsa.stamp(req.der))


# --- Emissão e verificação ---

def test_stamp_and_verify(tsa, ca):
    req, token = _stamp(tsa)
    info = tsa_mod.verify_token(token, ca.cert, H, nonce=req.nonce, policy=tsa_mod.DEFAULT_POLICY_OID)
    assert info.serial == 1 and info.imprint == H and info.nonce == req.nonce
    assert info.policy == tsa_mod.DEFAULT_POLICY_OID
    assert abs(info.gen_time - tsa_mod._utcnow()) < timedelta(minutes=1)
    assert info.gen_time_iso.endswith("Z") and len(info.gen_time_iso) == 24


def test_members_verify_without_nonce(tsa, ca):
    """Membros e Arbiter não conhecem o nonce do Gateway: basta o hash e a raiz da CA."""
    _, token = _stamp(tsa)
    assert tsa_mod.verify_token(token, ca.cert, H).serial == 1


def test_serials_strictly_increase(tsa):
    assert [tsa_mod.parse_token(_stamp(tsa)[1]).serial for _ in range(4)] == [1, 2, 3, 4]
    assert tsa.last_serial() == 4


def test_serial_persists_across_restart(ca, tmp_path, tsa_key):
    tsa1 = _make_tsa(ca, tmp_path, tsa_key)
    _stamp(tsa1)
    _stamp(tsa1)
    tsa2 = _make_tsa(ca, tmp_path, tsa_key)
    assert tsa_mod.parse_token(_stamp(tsa2)[1]).serial == 3


def test_corrupt_serial_fails_closed(ca, tmp_path, tsa_key):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / tsa_mod.SERIAL_FILE).write_text("isto não é hex")
    with pytest.raises(TSAError):
        _make_tsa(ca, tmp_path, tsa_key)


def test_deleted_serial_fails_closed(tsa):
    _stamp(tsa)
    tsa._serial_path.unlink()
    with pytest.raises(TSAError):
        _stamp(tsa)


def test_concurrent_stamps_have_unique_serials(tsa):
    serials, errors = [], []

    def work():
        try:
            serials.append(tsa_mod.parse_token(_stamp(tsa)[1]).serial)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and sorted(serials) == list(range(1, 7))


def test_unencrypted_key_supported(ca, tmp_path, tsa_key):
    tsa = _make_tsa(ca, tmp_path, tsa_key, passphrase=None)
    assert tsa_mod.parse_token(_stamp(tsa)[1]).serial == 1


# --- Pedido ---

def test_request_is_valid_rfc3161_for_openssl(tmp_path):
    req = tsa_mod.create_request(H, nonce=0x1234)
    path = tmp_path / "req.tsq"
    path.write_bytes(req.der)
    out = subprocess.run([tsa_mod.OPENSSL, "ts", "-query", "-in", str(path), "-text"],
                         capture_output=True, check=True).stdout.decode()
    assert "sha256" in out and "0x1234" in out and "Certificate required: yes" in out
    assert tsa_mod.parse_request(req.der).nonce == 0x1234


def test_request_nonce_is_random():
    assert tsa_mod.create_request(H).nonce != tsa_mod.create_request(H).nonce


def test_request_validation(tsa):
    with pytest.raises(TSAError):
        tsa_mod.create_request(b"curto")
    for bad in (b"", b"lixo", b"\x30\x00", b"\x30" + b"\x82\xff\xff", b"x" * 5000):
        with pytest.raises(TSAError):
            tsa.stamp(bad)


def test_non_sha256_request_rejected(tsa):
    sha1_oid = bytes.fromhex("2b0e03021a")
    der = tsa_mod.create_request(H).der.replace(
        tsa_mod._tlv(0x06, tsa_mod._OID_SHA256), tsa_mod._tlv(0x06, sha1_oid))
    with pytest.raises(TSAError):
        tsa.stamp(der)


# --- Configuração da TSA ---

def test_constructor_rejects_bad_setup(ca, tmp_path, tsa_key):
    # Chave que não corresponde ao certificado
    _, csr = ca_mod.generate_csr("tsa", tsa_key)
    cert = ca.issue_tsa_cert(csr, "tsa")
    other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    k, c = _write(tmp_path, other, cert, name="mismatch")
    with pytest.raises(TSAError):
        TimestampAuthority(k, c, tmp_path / "s1")

    # Certificado de servidor (sem EKU timeStamping)
    _, csr = ca_mod.generate_csr("srv", tsa_key)
    srv = ca.issue_server_cert(csr, "srv", dns_names=["srv"])
    k, c = _write(tmp_path, tsa_key, srv, name="srv")
    with pytest.raises(TSAError):
        TimestampAuthority(k, c, tmp_path / "s2")

    # Chave não RSA
    eck, csr = ca_mod.generate_csr("tsa-ec")
    cert = ca.issue_tsa_cert(csr, "tsa-ec")
    k, c = _write(tmp_path, eck, cert, name="ec")
    with pytest.raises(TSAError):
        TimestampAuthority(k, c, tmp_path / "s3")

    # Passphrase errada, vazia, binário que não é OpenSSL
    k, c = _write(tmp_path, tsa_key, ca.issue_tsa_cert(ca_mod.generate_csr("t", tsa_key)[1], "t"),
                  passphrase="certa", name="pw")
    with pytest.raises(TSAError):
        TimestampAuthority(k, c, tmp_path / "s4", passphrase="errada")
    with pytest.raises(TSAError):
        TimestampAuthority(k, c, tmp_path / "s4", passphrase="")
    with pytest.raises(TSAError):
        TimestampAuthority(k, c, tmp_path / "s4", passphrase="certa", openssl="/nao/existe")


def test_weak_rsa_key_rejected(ca, tmp_path):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _, csr = ca_mod.generate_csr("tsa", weak)
    k, c = _write(tmp_path, weak, ca.issue_tsa_cert(csr, "tsa"))
    with pytest.raises(TSAError):
        TimestampAuthority(k, c, tmp_path / "s")


# --- Rejeição de tokens ---

def test_wrong_imprint_rejected(tsa, ca):
    _, token = _stamp(tsa)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(token, ca.cert, hashlib.sha256(b"outro").digest())


def test_wrong_nonce_and_policy_rejected(tsa, ca):
    req, token = _stamp(tsa)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(token, ca.cert, H, nonce=req.nonce + 1)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(token, ca.cert, H, policy="1.2.3.4.2")


def test_bad_signature_rejected(tsa, ca):
    _, token = _stamp(tsa)
    bad = bytearray(token)
    bad[-1] ^= 1  # último byte da assinatura RSA no SignerInfo
    with pytest.raises(TokenError):
        tsa_mod.verify_token(bytes(bad), ca.cert, H)


def test_tampered_tstinfo_rejected(tsa, ca):
    """Mudar o hash dentro do TSTInfo (e pedir esse hash) quebra a assinatura."""
    _, token = _stamp(tsa)
    forged_h = bytes([H[0] ^ 1]) + H[1:]
    forged = token.replace(H, forged_h)
    assert forged != token
    with pytest.raises(TokenError):
        tsa_mod.verify_token(forged, ca.cert, forged_h)


def test_token_from_other_ca_rejected(tsa, tmp_path):
    _, token = _stamp(tsa)
    other = CertificateAuthority.init(tmp_path / "other", PW)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(token, other.cert, H)


def test_token_from_tsa_of_other_ca_rejected(tsa, ca, tmp_path, tsa_key):
    """Uma TSA válida mas certificada por outra CA não é aceite pela raiz da federação."""
    other_ca = CertificateAuthority.init(tmp_path / "other", PW)
    rogue = _make_tsa(other_ca, tmp_path, tsa_key, state="rogue")
    _, token = _stamp(rogue)
    assert tsa_mod.verify_token(token, other_ca.cert, H)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(token, ca.cert, H)


def test_future_token_rejected(tsa, ca):
    _, token = _stamp(tsa)
    gen = tsa_mod.parse_token(token).gen_time
    with pytest.raises(TokenError):
        tsa_mod.verify_token(token, ca.cert, H, now=gen - timedelta(hours=1))


def test_max_age(tsa, ca):
    """Prazo de disputas: 30 dias pela hora do token."""
    _, token = _stamp(tsa)
    gen = tsa_mod.parse_token(token).gen_time
    assert tsa_mod.verify_token(token, ca.cert, H, now=gen + timedelta(days=29),
                                max_age=timedelta(days=30))
    with pytest.raises(TokenError):
        tsa_mod.verify_token(token, ca.cert, H, now=gen + timedelta(days=31),
                             max_age=timedelta(days=30))


def test_rejection_response_raises():
    rejection = tsa_mod._tlv(0x30, tsa_mod._tlv(0x30, tsa_mod._der_uint(2)))
    with pytest.raises(TokenError):
        tsa_mod.token_from_response(rejection)


@pytest.mark.parametrize("bad", [b"", b"lixo", b"\x30\x00", b"\x30\x80\x00\x00", b"\x30\x05\x02\x01"])
def test_malformed_tokens_rejected(bad, ca):
    with pytest.raises(TokenError):
        tsa_mod.parse_token(bad)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(bad, ca.cert, H)
    with pytest.raises(TokenError):
        tsa_mod.token_from_response(bad)


def test_openssl_cli_accepts_reply(tsa, ca, tmp_path):
    """Interoperabilidade: o próprio openssl verifica a resposta contra o pedido (com nonce)."""
    req = tsa_mod.create_request(H)
    (tmp_path / "q.tsq").write_bytes(req.der)
    (tmp_path / "r.tsr").write_bytes(tsa.stamp(req.der))
    (tmp_path / "ca.pem").write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))
    out = subprocess.run([tsa_mod.OPENSSL, "ts", "-verify", "-queryfile", str(tmp_path / "q.tsq"),
                          "-in", str(tmp_path / "r.tsr"), "-CAfile", str(tmp_path / "ca.pem")],
                         capture_output=True)
    assert out.returncode == 0 and b"Verification: OK" in out.stdout


# --- Serviço HTTP ---

def test_service(tsa, ca):
    client = TestClient(create_app(tsa))
    assert client.get("/health").json() == {"status": "ok"}

    req = tsa_mod.create_request(H)
    r = client.post("/v1/timestamp", content=req.der,
                    headers={"Content-Type": "application/timestamp-query"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/timestamp-reply"
    token = tsa_mod.token_from_response(r.content)
    assert tsa_mod.verify_token(token, ca.cert, H, nonce=req.nonce).serial == 1

    assert client.post("/v1/timestamp", content=req.der,
                       headers={"Content-Type": "application/json"}).status_code == 415
    assert client.post("/v1/timestamp", content=b"lixo",
                       headers={"Content-Type": "application/timestamp-query"}).status_code == 400
    assert client.post("/v1/timestamp", content=b"x" * 5000,
                       headers={"Content-Type": "application/timestamp-query"}).status_code == 413

