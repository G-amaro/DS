"""Testes da TSA (token simplificado Ed25519). Correr a partir da raiz: python -m pytest."""

import base64
import hashlib
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from src.ca import ca as ca_mod
from src.ca.ca import CertificateAuthority
from src.tsa import tsa as tsa_mod
from src.tsa.service import create_app
from src.tsa.tsa import TimestampAuthority, TimestampToken, TokenError, TSAError

PW = "pw"
T0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
H = hashlib.sha256(b"envelope").digest()


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority.init(tmp_path / "ca", PW, now=T0)


def _make_tsa(ca, tmp_path, clock, name="tsa", days=365, state="state.json"):
    key = ed25519.Ed25519PrivateKey.generate()
    _, csr = ca_mod.generate_csr(name, key)
    cert = ca.issue_tsa_cert(csr, name, days=days, now=T0)
    return TimestampAuthority(key, cert, tmp_path / state, clock), key, cert


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def tsa(ca, tmp_path, clock):
    return _make_tsa(ca, tmp_path, clock)[0]


# --- Emissão e verificação ---

def test_stamp_and_verify(tsa, ca, clock):
    tok = tsa.stamp(H)
    assert tok.serial == 1 and tok.imprint == H and tok.nonce == b""
    assert tsa_mod.verify_token(tok, ca.cert, H, now=clock.t) == T0
    assert tok.gen_time_iso == "2026-11-24T12:00:00.000Z"


def test_serials_strictly_increase(tsa):
    assert [tsa.stamp(H).serial for _ in range(5)] == [1, 2, 3, 4, 5]


def test_time_never_goes_backwards(tsa, clock):
    first = tsa.stamp(H)
    clock.t = T0 - timedelta(minutes=1)  # ainda dentro da validade do certificado
    second = tsa.stamp(H)
    assert second.gen_time_ms == first.gen_time_ms and second.serial == first.serial + 1


def test_serial_persists_across_restart(ca, tmp_path, clock):
    tsa1, key, cert = _make_tsa(ca, tmp_path, clock)
    tsa1.stamp(H)
    tsa1.stamp(H)
    tsa2 = TimestampAuthority(key, cert, tmp_path / "state.json", clock)
    assert tsa2.stamp(H).serial == 3


def test_corrupt_state_fails_closed(ca, tmp_path, clock):
    tsa1, key, cert = _make_tsa(ca, tmp_path, clock)
    tsa1.stamp(H)
    (tmp_path / "state.json").write_text("{lixo")
    with pytest.raises(TSAError):
        TimestampAuthority(key, cert, tmp_path / "state.json", clock)
    (tmp_path / "state.json").write_text('{"last_serial": -1, "last_time_ms": 0}')
    with pytest.raises(TSAError):
        TimestampAuthority(key, cert, tmp_path / "state.json", clock)


def test_concurrent_stamps_have_unique_serials(tsa):
    serials, lock = [], threading.Lock()

    def work():
        for _ in range(10):
            s = tsa.stamp(H).serial
            with lock:
                serials.append(s)

    threads = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(serials) == list(range(1, 81))


def test_input_validation(tsa):
    with pytest.raises(TSAError):
        tsa.stamp(b"curto")
    with pytest.raises(TSAError):
        tsa.stamp(H, nonce=b"x" * 65)


def test_tsa_refuses_to_stamp_outside_cert_validity(ca, tmp_path, clock):
    tsa, _, cert = _make_tsa(ca, tmp_path, clock, days=1)
    clock.t = T0 + timedelta(days=2)
    with pytest.raises(TSAError):
        tsa.stamp(H)


# --- Configuração ---

def test_constructor_rejects_bad_setup(ca, tmp_path, clock):
    key = ed25519.Ed25519PrivateKey.generate()
    _, csr = ca_mod.generate_csr("m", key)
    member_cert = ca.issue_member_cert(csr, "m1", now=T0)
    with pytest.raises(TSAError):  # certificado sem EKU timeStamping
        TimestampAuthority(key, member_cert, tmp_path / "s.json", clock)
    _, _, tsa_cert = _make_tsa(ca, tmp_path, clock, state="x.json")
    with pytest.raises(TSAError):  # chave não corresponde ao certificado
        TimestampAuthority(ed25519.Ed25519PrivateKey.generate(), tsa_cert, tmp_path / "s.json", clock)


def test_load_from_pem_files(ca, tmp_path, clock):
    key = ed25519.Ed25519PrivateKey.generate()
    _, csr = ca_mod.generate_csr("tsa", key)
    cert = ca.issue_tsa_cert(csr, "tsa", now=T0)
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw")))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    tsa = TimestampAuthority.load(tmp_path / "k.pem", tmp_path / "c.pem", tmp_path / "s.json", "pw", clock)
    assert tsa_mod.verify_token(tsa.stamp(H), ca.cert, H, now=clock.t) == T0
    with pytest.raises(TSAError):
        TimestampAuthority.load(tmp_path / "k.pem", tmp_path / "c.pem", tmp_path / "s2.json", "errada", clock)


# --- Verificação: adulteração ---

def test_wrong_imprint_rejected(tsa, ca, clock):
    tok = tsa.stamp(H)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, hashlib.sha256(b"outro").digest(), now=clock.t)


@pytest.mark.parametrize("change", [
    {"serial": 99}, {"gen_time_ms": 1}, {"nonce": b"x"}, {"hash_alg": "sha512"}, {"version": 2},
])
def test_tampered_fields_rejected(tsa, ca, clock, change):
    tok = replace(tsa.stamp(H), **change)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, H, now=clock.t)


def test_tampered_imprint_with_matching_request_rejected(tsa, ca, clock):
    """Atacante troca o hash no token e pede verificação com o hash novo: a assinatura falha."""
    other = hashlib.sha256(b"outro").digest()
    tok = replace(tsa.stamp(H), imprint=other)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, other, now=clock.t)


def test_bad_signature_rejected(tsa, ca, clock):
    tok = tsa.stamp(H)
    sig = bytearray(tok.signature)
    sig[0] ^= 1
    with pytest.raises(TokenError):
        tsa_mod.verify_token(replace(tok, signature=bytes(sig)), ca.cert, H, now=clock.t)


def test_nonce_checked_when_given(tsa, ca, clock):
    tok = tsa.stamp(H, nonce=b"abc")
    tsa_mod.verify_token(tok, ca.cert, H, nonce=b"abc", now=clock.t)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, H, nonce=b"xyz", now=clock.t)


def test_token_from_other_ca_rejected(tsa, tmp_path, clock):
    other = CertificateAuthority.init(tmp_path / "other", PW, now=T0)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tsa.stamp(H), other.cert, H, now=clock.t)


def test_certificate_substitution_rejected(ca, tmp_path, clock):
    """Trocar o certificado por outro TSA válido da mesma CA não pode passar."""
    tsa_a, _, _ = _make_tsa(ca, tmp_path, clock, name="a", state="a.json")
    _, _, cert_b = _make_tsa(ca, tmp_path, clock, name="b", state="b.json")
    tok = replace(tsa_a.stamp(H), tsa_cert_der=cert_b.public_bytes(serialization.Encoding.DER))
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, H, now=clock.t)


def test_forged_token_with_real_cert_but_other_key_rejected(tsa, ca, clock):
    real = tsa.stamp(H)
    attacker = ed25519.Ed25519PrivateKey.generate()
    msg = tsa_mod._signed_message(1, "sha256", H, 7, real.gen_time_ms, b"", real.tsa_cert_der)
    forged = replace(real, serial=7, signature=attacker.sign(msg))
    with pytest.raises(TokenError):
        tsa_mod.verify_token(forged, ca.cert, H, now=clock.t)


def test_forged_token_with_selfsigned_cert_rejected(tsa, ca, clock, tmp_path):
    rogue = CertificateAuthority.init(tmp_path / "rogue", PW, now=T0)
    rogue_tsa, _, _ = _make_tsa(rogue, tmp_path, clock, state="r.json")
    with pytest.raises(TokenError):
        tsa_mod.verify_token(rogue_tsa.stamp(H), ca.cert, H, now=clock.t)


def test_non_tsa_cert_cannot_sign_tokens(ca, clock):
    """Um membro com certificado de login assina à mão um token: rejeitado por EKU."""
    key = ed25519.Ed25519PrivateKey.generate()
    _, csr = ca_mod.generate_csr("m", key)
    cert = ca.issue_member_cert(csr, "m1", now=T0)
    der = cert.public_bytes(serialization.Encoding.DER)
    sig = key.sign(tsa_mod._signed_message(1, "sha256", H, 1, int(T0.timestamp() * 1000), b"", der))
    tok = TimestampToken(1, int(T0.timestamp() * 1000), H, b"", der, sig)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, H, now=clock.t)


# --- Verificação: tempo ---

def test_token_stays_valid_after_tsa_cert_expires(ca, tmp_path, clock):
    tsa, _, cert = _make_tsa(ca, tmp_path, clock, days=2)
    tok = tsa.stamp(H)
    later = cert.not_valid_after_utc + timedelta(days=30)
    assert tsa_mod.verify_token(tok, ca.cert, H, now=later) == T0


def test_token_issued_outside_cert_validity_rejected(ca, tmp_path, clock):
    tsa, key, cert = _make_tsa(ca, tmp_path, clock)
    tok = tsa.stamp(H)
    early = T0 - timedelta(days=10)
    forged_ms = int(early.timestamp() * 1000)
    msg = tsa_mod._signed_message(1, "sha256", H, 1, forged_ms, b"", tok.tsa_cert_der)
    forged = replace(tok, gen_time_ms=forged_ms, signature=key.sign(msg))  # só possível com a chave real
    with pytest.raises(TokenError):
        tsa_mod.verify_token(forged, ca.cert, H, now=T0)


def test_future_token_rejected(tsa, ca, clock):
    tok = tsa.stamp(H)
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, H, now=T0 - timedelta(hours=1))
    tsa_mod.verify_token(tok, ca.cert, H, now=T0 - timedelta(minutes=1))  # dentro da tolerância


def test_max_age(tsa, ca, clock):
    tok = tsa.stamp(H)
    now = T0 + timedelta(days=29)
    tsa_mod.verify_token(tok, ca.cert, H, now=now, max_age=timedelta(days=30))
    with pytest.raises(TokenError):
        tsa_mod.verify_token(tok, ca.cert, H, now=T0 + timedelta(days=31), max_age=timedelta(days=30))


# --- Serialização ---

def test_serialization_roundtrip(tsa, ca, clock):
    tok = tsa.stamp(H, nonce=b"n")
    again = TimestampToken.from_bytes(tok.to_bytes())
    assert again == tok
    tsa_mod.verify_token(again, ca.cert, H, nonce=b"n", now=clock.t)


@pytest.mark.parametrize("bad", [
    b"", b"nao json", b"[]", b'{"serial": 1}', b'"x"',
])
def test_malformed_tokens_rejected(bad):
    with pytest.raises(TokenError):
        TimestampToken.from_bytes(bad)


def test_malformed_field_types_rejected(tsa):
    d = tsa.stamp(H).to_dict()
    for field, value in [("serial", "1"), ("serial", -1), ("serial", True), ("imprint", "@@@"),
                         ("imprint", 5), ("hash_alg", 3), ("gen_time_ms", 1.5)]:
        with pytest.raises(TokenError):
            TimestampToken.from_dict({**d, field: value})


# --- Serviço HTTP ---

def test_service(tsa, ca, clock):
    client = TestClient(create_app(tsa))
    assert client.get("/health").json() == {"status": "ok"}
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731

    r = client.post("/v1/timestamp", json={"imprint": b64(H), "nonce": b64(b"n1")})
    assert r.status_code == 200
    tok = TimestampToken.from_dict(r.json())
    assert tsa_mod.verify_token(tok, ca.cert, H, nonce=b"n1", now=clock.t) == T0

    assert client.post("/v1/timestamp", json={"imprint": "@@@"}).status_code == 400
    assert client.post("/v1/timestamp", json={"imprint": b64(b"curto")}).status_code == 400
    assert client.post("/v1/timestamp", json={"imprint": b64(H), "nonce": b64(b"x" * 65)}).status_code == 400
    assert client.post("/v1/timestamp", json={}).status_code == 422
    assert client.get("/docs").status_code == 404
