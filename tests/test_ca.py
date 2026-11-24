"""Testes da CA privada (passo 2 do plano). Correr a partir da raiz do projeto: python -m pytest."""

from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.ca import ca as ca_mod
from src.ca.ca import CAError, CertificateAuthority, CRLError, CSRError

PW = "passphrase-de-teste"


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority.init(tmp_path / "ca", PW)


def _cn(cert):
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _ext(cert, cls):
    return cert.extensions.get_extension_for_class(cls)


# --- Raiz ---

def test_init_creates_valid_root(ca, tmp_path):
    cert = ca.cert
    assert cert.subject == cert.issuer
    bc = _ext(cert, x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = _ext(cert, x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign and not ku.digital_signature
    cert.verify_directly_issued_by(cert)
    assert len(ca.fingerprint) == 64
    assert (tmp_path / "ca" / "ca.key.pem").stat().st_mode & 0o777 == 0o600


def test_root_key_is_encrypted_and_reload_works(ca, tmp_path):
    pem = (tmp_path / "ca" / "ca.key.pem").read_bytes()
    assert b"ENCRYPTED" in pem
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(pem, password=None)
    again = CertificateAuthority.load(tmp_path / "ca", PW)
    assert again.fingerprint == ca.fingerprint
    with pytest.raises(CAError):
        CertificateAuthority.load(tmp_path / "ca", "errada")


def test_init_refuses_empty_passphrase_and_overwrite(ca, tmp_path):
    with pytest.raises(CAError):
        CertificateAuthority.init(tmp_path / "outra", "")
    with pytest.raises(CAError):
        CertificateAuthority.init(tmp_path / "ca", PW)


def test_load_missing_ca(tmp_path):
    with pytest.raises(CAError):
        CertificateAuthority.load(tmp_path / "nada", PW)


# --- Certificados de servidor ---

def test_server_cert(ca):
    _, csr = ca_mod.generate_csr("evil-cn-from-csr")
    cert = ca.issue_server_cert(csr, "kafka", dns_names=["kafka", "localhost"], ip_addresses=["127.0.0.1"])
    assert _cn(cert) == "kafka"  # o subject vem da CA, não do CSR
    ca_mod.verify_certificate(cert, ca.cert)
    assert not _ext(cert, x509.BasicConstraints).value.ca
    assert _ext(cert, x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    san = _ext(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["kafka", "localhost"]
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]
    assert cert.not_valid_after_utc <= ca.cert.not_valid_after_utc


def test_server_cert_requires_san_and_valid_ip(ca):
    _, csr = ca_mod.generate_csr("x")
    with pytest.raises(CAError):
        ca.issue_server_cert(csr, "x")
    with pytest.raises(CAError):
        ca.issue_server_cert(csr, "x", ip_addresses=["não-é-ip"])


def test_leaf_validity_capped_by_root(tmp_path):
    ca = CertificateAuthority.init(tmp_path / "ca", PW, validity_days=30)
    _, csr = ca_mod.generate_csr("x")
    cert = ca.issue_server_cert(csr, "x", dns_names=["x"], days=365)
    assert cert.not_valid_after_utc == ca.cert.not_valid_after_utc


def test_cannot_issue_after_root_expiry(tmp_path):
    ca = CertificateAuthority.init(tmp_path / "ca", PW, validity_days=1)
    _, csr = ca_mod.generate_csr("x")
    late = ca.cert.not_valid_after_utc + timedelta(days=1)
    with pytest.raises(CAError):
        ca.issue_server_cert(csr, "x", dns_names=["x"], now=late)


# --- TSA ---

def test_tsa_cert_has_critical_timestamping_eku_only(ca):
    _, csr = ca_mod.generate_csr("tsa")
    cert = ca.issue_tsa_cert(csr, "tsa")
    eku = _ext(cert, x509.ExtendedKeyUsage)
    assert eku.critical
    assert list(eku.value) == [ExtendedKeyUsageOID.TIME_STAMPING]
    ca_mod.verify_certificate(cert, ca.cert)


# --- Membros ---

def test_member_cert(ca):
    sk = ed25519.Ed25519PrivateKey.generate()
    _, csr = ca_mod.generate_csr("o-que-o-membro-escreveu", sk)
    cert = ca.issue_member_cert(csr, "membro-001")
    assert _cn(cert) == "membro-001"
    assert list(_ext(cert, x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    with pytest.raises(x509.ExtensionNotFound):
        _ext(cert, x509.SubjectAlternativeName)
    assert cert.public_key().public_bytes_raw() == sk.public_key().public_bytes_raw()
    ca_mod.verify_certificate(cert, ca.cert)


def test_member_serials_unique_and_recorded(ca):
    serials = set()
    for i in range(5):
        _, csr = ca_mod.generate_csr("m")
        serials.add(ca.issue_member_cert(csr, f"m{i}").serial_number)
    assert len(serials) == 5
    assert all(ca_mod.serial_to_hex(s) in ca._state["issued"] for s in serials)


@pytest.mark.parametrize("bad", ["", " x", "x ", "a" * 65, "a\nb"])
def test_member_id_validation(ca, bad):
    _, csr = ca_mod.generate_csr("m")
    with pytest.raises(CAError):
        ca.issue_member_cert(csr, bad)


# --- Validação de CSR ---

def test_csr_with_bad_signature_rejected(ca):
    _, csr = ca_mod.generate_csr("x")
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF
    bad = x509.load_der_x509_csr(bytes(der))
    with pytest.raises(CSRError):
        ca.issue_member_cert(bad, "m1")


def test_csr_key_policy(ca):
    weak_rsa = rsa.generate_private_key(65537, 1024)
    _, csr = ca_mod.generate_csr("x", weak_rsa)
    with pytest.raises(CSRError):
        ca.issue_member_cert(csr, "m1")
    _, csr = ca_mod.generate_csr("x", ec.generate_private_key(ec.SECP256K1()))
    with pytest.raises(CSRError):
        ca.issue_member_cert(csr, "m2")
    # aceites
    for key in (rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP384R1())):
        _, csr = ca_mod.generate_csr("x", key)
        ca.issue_member_cert(csr, "ok")


# --- verify_certificate ---

def test_verify_certificate_failures(ca, tmp_path):
    _, csr = ca_mod.generate_csr("x")
    cert = ca.issue_member_cert(csr, "m1")
    other = CertificateAuthority.init(tmp_path / "other", PW)
    with pytest.raises(CAError):
        ca_mod.verify_certificate(cert, other.cert)
    with pytest.raises(CAError):
        ca_mod.verify_certificate(cert, ca.cert, now=cert.not_valid_after_utc + timedelta(seconds=1))
    with pytest.raises(CAError):
        ca_mod.verify_certificate(cert, ca.cert, now=cert.not_valid_before_utc - timedelta(minutes=1))


# --- Revogação e CRL ---

def test_empty_crl_is_valid(ca):
    crl = ca.issue_crl()
    ca_mod.verify_crl(crl, ca.cert)
    assert len(list(crl)) == 0
    assert ca_mod.crl_number(crl) == 1


def test_revoke_and_crl(ca):
    _, csr = ca_mod.generate_csr("x")
    a = ca.issue_member_cert(csr, "a")
    b = ca.issue_member_cert(csr, "b")
    assert ca.revoke(a.serial_number, "key_compromise") is True
    assert ca.revoke(a.serial_number) is False  # idempotente
    crl = ca_mod.verify_crl(ca.issue_crl(), ca.cert)
    assert ca_mod.crl_contains(crl, a.serial_number)
    assert not ca_mod.crl_contains(crl, b.serial_number)
    entry = crl.get_revoked_certificate_by_serial_number(a.serial_number)
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.key_compromise


def test_revoke_unknown_serial_or_reason(ca):
    with pytest.raises(CAError):
        ca.revoke(12345)
    _, csr = ca_mod.generate_csr("x")
    cert = ca.issue_member_cert(csr, "a")
    with pytest.raises(CAError):
        ca.revoke(cert.serial_number, "porque-sim")


def test_crl_number_increases_and_stale_rejected(ca):
    first = ca.issue_crl()
    second = ca.issue_crl()
    assert ca_mod.crl_number(second) == ca_mod.crl_number(first) + 1
    ca_mod.verify_crl(second, ca.cert, previous_number=ca_mod.crl_number(first))
    with pytest.raises(CRLError):
        ca_mod.verify_crl(first, ca.cert, previous_number=ca_mod.crl_number(second))
    with pytest.raises(CRLError):
        ca_mod.verify_crl(second, ca.cert, previous_number=ca_mod.crl_number(second))


def test_expired_and_future_crl_rejected(ca):
    crl = ca.issue_crl(days=7)
    with pytest.raises(CRLError):
        ca_mod.verify_crl(crl, ca.cert, now=crl.next_update_utc + timedelta(seconds=1))
    with pytest.raises(CRLError):
        ca_mod.verify_crl(crl, ca.cert, now=crl.last_update_utc - timedelta(hours=1))


def test_crl_from_other_ca_rejected(ca, tmp_path):
    other = CertificateAuthority.init(tmp_path / "other", PW)
    with pytest.raises(CRLError):
        ca_mod.verify_crl(other.issue_crl(), ca.cert)


def test_crl_signed_by_impostor_with_same_name_rejected(ca, tmp_path):
    """Mesmo emissor (nome) mas outra chave: a assinatura tem de falhar."""
    impostor = CertificateAuthority.init(tmp_path / "imp", PW)
    crl = impostor.issue_crl()
    forged_ca_cert = ca.cert
    assert crl.issuer == forged_ca_cert.subject  # mesmo nome por omissão
    with pytest.raises(CRLError):
        ca_mod.verify_crl(crl, forged_ca_cert)


def test_state_persists_across_reload(ca, tmp_path):
    _, csr = ca_mod.generate_csr("x")
    cert = ca.issue_member_cert(csr, "a")
    ca.revoke(cert.serial_number)
    ca.issue_crl()
    again = CertificateAuthority.load(tmp_path / "ca", PW)
    assert again.is_revoked(cert.serial_number)
    crl = again.issue_crl()
    assert ca_mod.crl_number(crl) == 2
    assert ca_mod.crl_contains(crl, cert.serial_number)


# --- PKCS12 ---

def test_pkcs12_keystore_and_truststore(ca):
    key, csr = ca_mod.generate_csr("kafka")
    cert = ca.issue_server_cert(csr, "kafka", dns_names=["kafka"])
    data = ca_mod.to_pkcs12(key, cert, ca.cert, "pw", "kafka")
    loaded_key, loaded_cert, extra = pkcs12.load_key_and_certificates(data, b"pw")
    assert loaded_cert == cert and extra == [ca.cert]
    assert loaded_key.private_numbers() == key.private_numbers()
    trust = pkcs12.load_pkcs12(ca_mod.to_truststore(ca.cert, "pw"), b"pw")
    assert [c.certificate for c in trust.additional_certs] == [ca.cert]
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(data, b"errada")


# --- CLI ---

def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FED_CA_PASSPHRASE", PW)
    monkeypatch.setenv("FED_P12_PASSWORD", "pw")
    d = str(tmp_path / "ca")
    run = lambda *a: ca_mod.main(["--dir", d, *a])  # noqa: E731

    assert run("init", "--name", "Test CA") == 0
    assert run("init") == 1  # não sobrescreve
    assert run("fingerprint") == 0
    assert capsys.readouterr().out.strip().splitlines()[-1] == CertificateAuthority.load(d, PW).fingerprint

    key, csr = tmp_path / "m.key", tmp_path / "m.csr"
    assert run("gen-csr", "--cn", "x", "--key-out", str(key), "--csr-out", str(csr), "--ed25519") == 0
    assert key.stat().st_mode & 0o777 == 0o600
    out = tmp_path / "m.pem"
    assert run("issue-member", "--csr", str(csr), "--member-id", "membro-9", "--out", str(out)) == 0
    cert = x509.load_pem_x509_certificate(out.read_bytes())
    assert _cn(cert) == "membro-9"

    assert run("revoke", "--serial", ca_mod.serial_to_hex(cert.serial_number), "--reason", "key_compromise") == 0
    assert run("revoke", "--serial", "zz") == 1
    assert run("revoke", "--serial", "1234") == 1
    crl_path = tmp_path / "crl.pem"
    assert run("crl", "--out", str(crl_path)) == 0
    crl = x509.load_pem_x509_crl(crl_path.read_bytes())
    ca_mod.verify_crl(crl, CertificateAuthority.load(d, PW).cert)
    assert ca_mod.crl_contains(crl, cert.serial_number)

    skey, scsr, scert = tmp_path / "s.key", tmp_path / "s.csr", tmp_path / "s.pem"
    assert run("gen-csr", "--cn", "kafka", "--key-out", str(skey), "--csr-out", str(scsr)) == 0
    assert run("issue-server", "--csr", str(scsr), "--cn", "kafka", "--dns", "kafka", "--out", str(scert)) == 0
    assert run("issue-server", "--csr", str(scsr), "--cn", "kafka", "--out", str(scert)) == 1  # sem SAN
    assert run("issue-tsa", "--csr", str(scsr), "--cn", "tsa", "--out", str(tmp_path / "t.pem")) == 0
    assert run("export-pkcs12", "--key", str(skey), "--cert", str(scert),
               "--keystore-out", str(tmp_path / "ks.p12"), "--truststore-out", str(tmp_path / "ts.p12")) == 0
    assert (tmp_path / "ks.p12").stat().st_size > 0


def test_cli_wrong_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv("FED_CA_PASSPHRASE", PW)
    d = str(tmp_path / "ca")
    assert ca_mod.main(["--dir", d, "init"]) == 0
    monkeypatch.setenv("FED_CA_PASSPHRASE", "errada")
    assert ca_mod.main(["--dir", d, "fingerprint"]) == 1
