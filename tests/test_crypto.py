"""Testes unitários das primitivas de crypto.py (passo 1 do plano)."""

import pytest

from src.common import crypto as c


# --- AES-GCM ---

def test_aes_gcm_roundtrip():
    key = c.generate_symmetric_key()
    ct = c.aes_gcm_encrypt(key, b"relatorio", b"ad")
    assert c.aes_gcm_decrypt(key, ct, b"ad") == b"relatorio"


def test_aes_gcm_nonce_is_random():
    key = c.generate_symmetric_key()
    assert c.aes_gcm_encrypt(key, b"x") != c.aes_gcm_encrypt(key, b"x")


def test_aes_gcm_wrong_ad_fails():
    key = c.generate_symmetric_key()
    ct = c.aes_gcm_encrypt(key, b"x", b"ad1")
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(key, ct, b"ad2")


def test_aes_gcm_tampered_fails():
    key = c.generate_symmetric_key()
    ct = bytearray(c.aes_gcm_encrypt(key, b"x", b"ad"))
    ct[-1] ^= 1
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(key, bytes(ct), b"ad")


def test_aes_gcm_wrong_key_and_bad_sizes():
    ct = c.aes_gcm_encrypt(c.generate_symmetric_key(), b"x")
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(c.generate_symmetric_key(), ct)
    with pytest.raises(ValueError):
        c.aes_gcm_encrypt(b"curta", b"x")
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(c.generate_symmetric_key(), b"curto")


# --- ECIES ---

def test_ecies_roundtrip():
    sk, pk = c.generate_x25519_keypair()
    ct = c.ecies_encrypt(pk, b"K_c", info=b"A", associated_data=b"ctx")
    assert c.ecies_decrypt(sk, ct, info=b"A", associated_data=b"ctx") == b"K_c"


def test_ecies_defaults_roundtrip():
    sk, pk = c.generate_x25519_keypair()
    assert c.ecies_decrypt(sk, c.ecies_encrypt(pk, b"m")) == b"m"


def test_ecies_wrong_associated_data_fails():
    sk, pk = c.generate_x25519_keypair()
    ct = c.ecies_encrypt(pk, b"m", associated_data=b"ctx1")
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, ct, associated_data=b"ctx2")
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, ct, associated_data=None)


def test_ecies_wrong_info_fails():
    sk, pk = c.generate_x25519_keypair()
    ct = c.ecies_encrypt(pk, b"m", info=b"cofre-interior")
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, ct, info=b"cofre-exterior")


def test_ecies_wrong_recipient_fails():
    _, pk = c.generate_x25519_keypair()
    other_sk, _ = c.generate_x25519_keypair()
    with pytest.raises(ValueError):
        c.ecies_decrypt(other_sk, c.ecies_encrypt(pk, b"m"))


def test_ecies_tampered_and_short_fail():
    sk, pk = c.generate_x25519_keypair()
    ct = bytearray(c.ecies_encrypt(pk, b"m"))
    ct[40] ^= 1  # nonce
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, bytes(ct))
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, b"curto")


def test_ecies_is_randomized():
    _, pk = c.generate_x25519_keypair()
    assert c.ecies_encrypt(pk, b"m") != c.ecies_encrypt(pk, b"m")


# --- Serialização de chaves ---

def test_pem_roundtrips_with_and_without_passphrase():
    sk, pk = c.generate_ed25519_keypair()
    for pw in (None, "segredo"):
        pem = c.ed25519_private_to_pem(sk, pw)
        assert c.ed25519_private_from_pem(pem, pw).sign(b"m") == sk.sign(b"m")
    assert c.ed25519_public_to_raw(c.ed25519_public_from_pem(c.ed25519_public_to_pem(pk))) == c.ed25519_public_to_raw(pk)

    xsk, xpk = c.generate_x25519_keypair()
    pem = c.x25519_private_to_pem(xsk, "segredo")
    assert c.x25519_public_to_raw(c.x25519_private_from_pem(pem, "segredo").public_key()) == c.x25519_public_to_raw(xpk)
    assert c.x25519_public_to_raw(c.x25519_public_from_pem(c.x25519_public_to_pem(xpk))) == c.x25519_public_to_raw(xpk)


def test_encrypted_pem_needs_passphrase():
    sk, _ = c.generate_ed25519_keypair()
    pem = c.ed25519_private_to_pem(sk, "segredo")
    with pytest.raises(Exception):
        c.ed25519_private_from_pem(pem, "errada")


def test_wrong_key_type_pem_rejected():
    xsk, xpk = c.generate_x25519_keypair()
    with pytest.raises(ValueError):
        c.ed25519_private_from_pem(c.x25519_private_to_pem(xsk))
    with pytest.raises(ValueError):
        c.ed25519_public_from_pem(c.x25519_public_to_pem(xpk))


# --- Prova de posse ---

def test_pop_roundtrip_and_failures():
    sk, pk = c.generate_ed25519_keypair()
    sig = c.sign_pop(sk, 7, b"desafio")
    assert c.verify_pop(pk, 7, b"desafio", sig)
    assert not c.verify_pop(pk, 8, b"desafio", sig)
    assert not c.verify_pop(pk, 7, b"outro", sig)
    _, other_pk = c.generate_ed25519_keypair()
    assert not c.verify_pop(other_pk, 7, b"desafio", sig)


# --- Credencial ---

def test_credential_roundtrip_and_failures():
    csk, cpk = c.generate_ed25519_keypair()
    _, pk_e = c.generate_ed25519_keypair()
    pk_raw = c.ed25519_public_to_raw(pk_e)
    vault = b"cofre"
    sig = c.sign_credential(csk, 5, pk_raw, vault)
    assert c.verify_credential(cpk, 5, pk_raw, vault, sig)
    assert not c.verify_credential(cpk, 6, pk_raw, vault, sig)
    assert not c.verify_credential(cpk, 5, pk_raw, b"outro cofre", sig)
    other_raw = c.ed25519_public_to_raw(c.generate_ed25519_keypair()[1])
    assert not c.verify_credential(cpk, 5, other_raw, vault, sig)


# --- Cofre ---

def test_vault_payload_roundtrip():
    payload = c.build_vault_payload("membro-1", b"\x01" * 32, 42)
    assert c.parse_vault_payload(payload) == ("membro-1", b"\x01" * 32, 42)


def test_vault_payload_truncated_fails():
    payload = c.build_vault_payload("membro-1", b"\x01" * 32, 42)
    with pytest.raises(ValueError):
        c.parse_vault_payload(payload[:-3])
    with pytest.raises(ValueError):
        c.parse_vault_payload(b"\x00\x00")


# --- rid e lista de chaves ---

def test_rid_is_deterministic_and_32_bytes():
    rid = c.compute_rid("3f1c2a9e-7b4d-4e8a-9c21-5d6f0a1b2c3d")
    assert len(rid) == 32
    assert rid == c.compute_rid("3f1c2a9e-7b4d-4e8a-9c21-5d6f0a1b2c3d")
    assert rid != c.compute_rid("outro")


def test_key_list_roundtrip_and_malformed():
    entries = [(c.recipient_key_id(b"a" * 32), b"w1"), (c.recipient_key_id(b"b" * 32), b"w2" * 40)]
    data = c.serialize_key_list(entries)
    assert c.parse_key_list(data) == entries
    assert c.parse_key_list(c.serialize_key_list([])) == []
    with pytest.raises(ValueError):
        c.parse_key_list(data[:-1])
    with pytest.raises(ValueError):
        c.parse_key_list(data + b"x")
    with pytest.raises(ValueError):
        c.parse_key_list(b"\x00")


# --- Assinaturas de relatório e corroboração ---

def _envelope():
    sk, pk = c.generate_ed25519_keypair()
    rid = c.compute_rid("id")
    ct = b"ciphertext"
    kl = c.serialize_key_list([(b"k" * 32, b"w")])
    return sk, pk, rid, ct, kl


def test_report_roundtrip():
    sk, pk, rid, ct, kl = _envelope()
    sig = c.sign_report(sk, 3, 9, rid, ct, kl)
    assert c.verify_report(pk, 3, 9, rid, ct, kl, sig)


@pytest.mark.parametrize("field", ["epoch", "version", "rid", "ct", "kl"])
def test_report_signature_binds_every_field(field):
    sk, pk, rid, ct, kl = _envelope()
    sig = c.sign_report(sk, 3, 9, rid, ct, kl)
    args = {"epoch": 3, "version": 9, "rid": rid, "ct": ct, "kl": kl}
    args[field] = {
        "epoch": 4, "version": 10, "rid": c.compute_rid("x"),
        "ct": b"outro", "kl": c.serialize_key_list([]),
    }[field]
    assert not c.verify_report(pk, args["epoch"], args["version"], args["rid"], args["ct"], args["kl"], sig)


def test_report_and_corroboration_domains_are_separated():
    sk, pk, rid, ct, kl = _envelope()
    rep = c.sign_report(sk, 3, 9, rid, ct, kl)
    cor = c.sign_corroboration(sk, 3, 9, rid, ct, kl)
    assert c.verify_corroboration(pk, 3, 9, rid, ct, kl, cor)
    assert not c.verify_corroboration(pk, 3, 9, rid, ct, kl, rep)
    assert not c.verify_report(pk, 3, 9, rid, ct, kl, cor)


def test_report_signature_wrong_key_fails():
    sk, pk, rid, ct, kl = _envelope()
    sig = c.sign_report(sk, 3, 9, rid, ct, kl)
    _, other_pk = c.generate_ed25519_keypair()
    assert not c.verify_report(other_pk, 3, 9, rid, ct, kl, sig)


def test_report_aad_depends_on_all_fields():
    rid = c.compute_rid("id")
    base = c.report_aad(1, rid, 1)
    assert base != c.report_aad(2, rid, 1)
    assert base != c.report_aad(1, c.compute_rid("x"), 1)
    assert base != c.report_aad(1, rid, 2)


# --- Diretório ---

def test_directory_roundtrip_and_failures():
    sk, pk = c.generate_ed25519_keypair()
    pubs = [b"a" * 32, b"b" * 32]
    sig = c.sign_directory(sk, 4, pubs)
    assert c.verify_directory(pk, 4, pubs, sig)
    assert not c.verify_directory(pk, 5, pubs, sig)
    assert not c.verify_directory(pk, 4, pubs[:1], sig)
    assert not c.verify_directory(pk, 4, list(reversed(pubs)), sig)
    assert not c.verify_directory(pk, 4, pubs + [b"c" * 32], sig)


def test_directory_boundary_not_ambiguous():
    sk, pk = c.generate_ed25519_keypair()
    sig = c.sign_directory(sk, 1, [b"ab", b"c"])
    assert not c.verify_directory(pk, 1, [b"a", b"bc"], sig)


# --- Veredito ---

def test_verdict_roundtrip_and_failures():
    sk, pk = c.generate_ed25519_keypair()
    rid = c.compute_rid("id")
    sig = c.sign_verdict(sk, rid, "procedente")
    assert c.verify_verdict(pk, rid, "procedente", sig)
    assert not c.verify_verdict(pk, rid, "improcedente", sig)
    assert not c.verify_verdict(pk, c.compute_rid("x"), "procedente", sig)


def test_cross_domain_signature_not_accepted():
    """Uma assinatura de veredito não pode passar por diretório, e vice-versa."""
    sk, pk = c.generate_ed25519_keypair()
    sig = c.sign_verdict(sk, b"rid", "ok")
    assert not c.verify_directory(pk, 1, [], sig)


# --- Cadeia HKDF ---

def test_chain_is_deterministic():
    ck = b"\x07" * 32
    sk1, n1 = c.derive_epoch_key(ck)
    sk2, n2 = c.derive_epoch_key(ck)
    assert n1 == n2
    assert c.ed25519_public_to_raw(sk1.public_key()) == c.ed25519_public_to_raw(sk2.public_key())


def test_chain_key_and_next_are_independent():
    ck = b"\x07" * 32
    sk, nxt = c.derive_epoch_key(ck)
    sk_raw = sk.private_bytes_raw()
    assert sk_raw != nxt and sk_raw != ck and nxt != ck


def test_chain_epochs_have_distinct_keys():
    keys, _ = c.derive_epoch_batch(b"\x01" * 32, 6)
    pubs = {c.ed25519_public_to_raw(k.public_key()) for k in keys}
    assert len(pubs) == 6


def test_chain_batch_matches_stepwise_and_returns_next_ck():
    ck = b"\x09" * 32
    keys, after = c.derive_epoch_batch(ck, 3)
    step = ck
    for k in keys:
        sk, step = c.derive_epoch_key(step)
        assert sk.private_bytes_raw() == k.private_bytes_raw()
    assert step == after


def test_chain_different_seeds_diverge():
    a, _ = c.derive_epoch_key(b"\x01" * 32)
    b, _ = c.derive_epoch_key(b"\x02" * 32)
    assert a.private_bytes_raw() != b.private_bytes_raw()


def test_chain_input_validation():
    with pytest.raises(ValueError):
        c.derive_epoch_key(b"curta")
    with pytest.raises(ValueError):
        c.derive_epoch_batch(b"\x01" * 32, 0)


def test_derived_key_signs_and_verifies():
    sk, _ = c.derive_epoch_key(b"\x05" * 32)
    pk = sk.public_key()
    assert c.verify_pop(pk, 1, b"d", c.sign_pop(sk, 1, b"d"))


# --- HMAC de admissão ---

def test_admission_hmac_roundtrip_and_failures():
    k = c.generate_symmetric_key()
    rid = c.compute_rid("id")
    tag = c.compute_admission_hmac(k, 3, 9, rid, b"ct", b"kl")
    assert c.verify_admission_hmac(k, 3, 9, rid, b"ct", b"kl", tag)
    assert not c.verify_admission_hmac(c.generate_symmetric_key(), 3, 9, rid, b"ct", b"kl", tag)
    assert not c.verify_admission_hmac(k, 4, 9, rid, b"ct", b"kl", tag)
    assert not c.verify_admission_hmac(k, 3, 10, rid, b"ct", b"kl", tag)
    assert not c.verify_admission_hmac(k, 3, 9, c.compute_rid("x"), b"ct", b"kl", tag)
    assert not c.verify_admission_hmac(k, 3, 9, rid, b"ct2", b"kl", tag)
    assert not c.verify_admission_hmac(k, 3, 9, rid, b"ct", b"kl2", tag)
    assert not c.verify_admission_hmac(k, 3, 9, rid, b"ct", b"kl", tag[:-1] + bytes([tag[-1] ^ 1]))


def test_admission_hmac_boundary_not_ambiguous():
    k = c.generate_symmetric_key()
    rid = c.compute_rid("id")
    tag = c.compute_admission_hmac(k, 1, 1, rid, b"ab", b"c")
    assert not c.verify_admission_hmac(k, 1, 1, rid, b"a", b"bc", tag)


# --- Fluxo completo: envelope de relatório ---

def test_full_report_envelope_flow():
    members = [c.generate_x25519_keypair() for _ in range(3)]
    sk_e, pk_e = c.generate_ed25519_keypair()
    k_adm = c.generate_symmetric_key()
    epoch, version = 10, 2
    rid = c.compute_rid("uuid-do-relatorio")

    k_c = c.generate_symmetric_key()
    ct = c.aes_gcm_encrypt(k_c, b'{"severity":"high"}', c.report_aad(epoch, rid, version))
    entries = []
    for _, pub in members:
        raw = c.x25519_public_to_raw(pub)
        entries.append((c.recipient_key_id(raw), c.ecies_encrypt(pub, k_c, associated_data=rid)))
    kl = c.serialize_key_list(entries)
    sig = c.sign_report(sk_e, epoch, version, rid, ct, kl)
    tag = c.compute_admission_hmac(k_adm, epoch, version, rid, ct, kl)

    # Gateway
    assert c.verify_admission_hmac(k_adm, epoch, version, rid, ct, kl, tag)
    assert c.verify_report(pk_e, epoch, version, rid, ct, kl, sig)

    # Cada membro encontra a sua entrada e decifra
    parsed = c.parse_key_list(kl)
    for sk, pub in members:
        kid = c.recipient_key_id(c.x25519_public_to_raw(pub))
        wrapped = dict(parsed)[kid]
        got_kc = c.ecies_decrypt(sk, wrapped, associated_data=rid)
        assert c.aes_gcm_decrypt(got_kc, ct, c.report_aad(epoch, rid, version)) == b'{"severity":"high"}'

    # Um não-membro (revogado) não decifra
    outsider_sk, _ = c.generate_x25519_keypair()
    with pytest.raises(ValueError):
        c.ecies_decrypt(outsider_sk, parsed[0][1], associated_data=rid)
