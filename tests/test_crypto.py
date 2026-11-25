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
    assert c.aes_gcm_encrypt(key, b"x", b"ad") != c.aes_gcm_encrypt(key, b"x", b"ad")


def test_aes_gcm_wrong_ad_fails():
    key = c.generate_symmetric_key()
    ct = c.aes_gcm_encrypt(key, b"x", b"ad1")
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(key, ct, b"ad2")


def test_aes_gcm_requires_associated_data():
    key = c.generate_symmetric_key()
    with pytest.raises(ValueError):
        c.aes_gcm_encrypt(key, b"x", None)
    ct = c.aes_gcm_encrypt(key, b"x", b"ad")
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(key, ct, None)
    with pytest.raises(TypeError):
        c.aes_gcm_encrypt(key, b"x")


def test_aes_gcm_tampered_fails():
    key = c.generate_symmetric_key()
    ct = bytearray(c.aes_gcm_encrypt(key, b"x", b"ad"))
    ct[-1] ^= 1
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(key, bytes(ct), b"ad")


def test_aes_gcm_wrong_key_and_bad_sizes():
    ct = c.aes_gcm_encrypt(c.generate_symmetric_key(), b"x", b"ad")
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(c.generate_symmetric_key(), ct, b"ad")
    with pytest.raises(ValueError):
        c.aes_gcm_encrypt(b"curta", b"x", b"ad")
    with pytest.raises(ValueError):
        c.aes_gcm_decrypt(c.generate_symmetric_key(), b"curto", b"ad")


# --- ECIES ---

def _enc(pk, m=b"m", info=b"A", ad=b"ctx"):
    return c.ecies_encrypt(pk, m, info=info, associated_data=ad)


def test_ecies_roundtrip():
    sk, pk = c.generate_x25519_keypair()
    ct = _enc(pk, b"K_c")
    assert c.ecies_decrypt(sk, ct, info=b"A", associated_data=b"ctx") == b"K_c"


def test_ecies_requires_info_and_associated_data():
    sk, pk = c.generate_x25519_keypair()
    with pytest.raises(TypeError):
        c.ecies_encrypt(pk, b"m")
    with pytest.raises(TypeError):
        c.ecies_encrypt(pk, b"m", b"A", b"ctx")  # só por nome
    with pytest.raises(ValueError):
        c.ecies_encrypt(pk, b"m", info=b"", associated_data=b"ctx")
    with pytest.raises(ValueError):
        c.ecies_encrypt(pk, b"m", info=b"A", associated_data=None)
    ct = _enc(pk)
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, ct, info=b"A", associated_data=None)


def test_ecies_wrong_associated_data_fails():
    sk, pk = c.generate_x25519_keypair()
    ct = _enc(pk, ad=b"ctx1")
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, ct, info=b"A", associated_data=b"ctx2")


def test_ecies_wrong_info_fails():
    sk, pk = c.generate_x25519_keypair()
    ct = _enc(pk, info=c.INFO_VAULT_INNER)
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, ct, info=c.INFO_VAULT_OUTER, associated_data=b"ctx")


def test_ecies_info_constants_are_distinct():
    infos = [c.INFO_KC, c.INFO_DIRKEY, c.INFO_VAULT_INNER, c.INFO_VAULT_OUTER,
             c.INFO_CHAIN_KEY, c.INFO_CHAIN_NEXT]
    assert len(set(infos)) == len(infos)


def test_ecies_wrong_recipient_fails():
    _, pk = c.generate_x25519_keypair()
    other_sk, _ = c.generate_x25519_keypair()
    with pytest.raises(ValueError):
        c.ecies_decrypt(other_sk, _enc(pk), info=b"A", associated_data=b"ctx")


def test_ecies_tampered_and_short_fail():
    sk, pk = c.generate_x25519_keypair()
    ct = bytearray(_enc(pk))
    ct[40] ^= 1  # nonce
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, bytes(ct), info=b"A", associated_data=b"ctx")
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, b"curto", info=b"A", associated_data=b"ctx")


def test_ecies_is_randomized():
    _, pk = c.generate_x25519_keypair()
    assert _enc(pk) != _enc(pk)


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


def test_empty_passphrase_rejected():
    sk, _ = c.generate_ed25519_keypair()
    xsk, _ = c.generate_x25519_keypair()
    with pytest.raises(ValueError):
        c.ed25519_private_to_pem(sk, "")
    with pytest.raises(ValueError):
        c.x25519_private_to_pem(xsk, "")
    pem = c.ed25519_private_to_pem(sk, None)
    with pytest.raises(ValueError):
        c.ed25519_private_from_pem(pem, "")


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
    _, pk_E = c.generate_ed25519_keypair()
    pk_raw = c.ed25519_public_to_raw(pk_E)
    vault = b"cofre"
    sig = c.sign_credential(csk, 5, pk_raw, vault, 1)
    assert c.verify_credential(cpk, 5, pk_raw, vault, 1, sig)
    assert not c.verify_credential(cpk, 6, pk_raw, vault, 1, sig)
    assert not c.verify_credential(cpk, 5, pk_raw, b"outro cofre", 1, sig)
    assert not c.verify_credential(cpk, 5, pk_raw, vault, 2, sig)
    other_raw = c.ed25519_public_to_raw(c.generate_ed25519_keypair()[1])
    assert not c.verify_credential(cpk, 5, other_raw, vault, 1, sig)
    _, other_cpk = c.generate_ed25519_keypair()
    assert not c.verify_credential(other_cpk, 5, pk_raw, vault, 1, sig)


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
    with pytest.raises(ValueError):
        c.parse_vault_payload(payload + b"x")


def _vault_setup():
    arb_sk, arb_pk = c.generate_x25519_keypair()
    coord_sk, coord_pk = c.generate_x25519_keypair()
    _, pk_E = c.generate_ed25519_keypair()
    pk_raw = c.ed25519_public_to_raw(pk_E)
    vault = c.seal_vault(arb_pk, coord_pk, 3, "membro-7", pk_raw, 100)
    return arb_sk, coord_sk, pk_raw, vault


def test_two_layer_vault_roundtrip():
    arb_sk, coord_sk, pk_raw, vault = _vault_setup()
    inner = c.open_vault_outer(coord_sk, vault, 100, 3)
    assert c.open_vault_inner(arb_sk, inner, 100, pk_raw) == "membro-7"


def test_arbiter_alone_cannot_open_vault():
    arb_sk, _, pk_raw, vault = _vault_setup()
    with pytest.raises(ValueError):
        c.open_vault_inner(arb_sk, vault, 100, pk_raw)
    with pytest.raises(ValueError):
        c.open_vault_outer(arb_sk, vault, 100, 3)


def test_coordinator_alone_cannot_read_vault():
    _, coord_sk, pk_raw, vault = _vault_setup()
    inner = c.open_vault_outer(coord_sk, vault, 100, 3)
    with pytest.raises(ValueError):
        c.open_vault_inner(coord_sk, inner, 100, pk_raw)


def test_vault_outer_bound_to_epoch_and_key_gen():
    _, coord_sk, _, vault = _vault_setup()
    with pytest.raises(ValueError):
        c.open_vault_outer(coord_sk, vault, 101, 3)
    with pytest.raises(ValueError):
        c.open_vault_outer(coord_sk, vault, 100, 4)


def test_vault_inner_bound_to_pk_E_and_epoch():
    arb_sk, coord_sk, pk_raw, vault = _vault_setup()
    inner = c.open_vault_outer(coord_sk, vault, 100, 3)
    other_raw = c.ed25519_public_to_raw(c.generate_ed25519_keypair()[1])
    with pytest.raises(ValueError):
        c.open_vault_inner(arb_sk, inner, 100, other_raw)
    with pytest.raises(ValueError):
        c.open_vault_inner(arb_sk, inner, 101, pk_raw)


def test_vault_inner_rejects_mismatched_content():
    """Um cofre construído à mão com pk_E diferente da dos dados associados é recusado."""
    arb_sk, arb_pk = c.generate_x25519_keypair()
    pk_raw = b"\x01" * 32
    payload = c.build_vault_payload("m", b"\x02" * 32, 100)
    inner = c.ecies_encrypt(arb_pk, payload, info=c.INFO_VAULT_INNER,
                            associated_data=c._vault_inner_aad(100, pk_raw))
    with pytest.raises(ValueError):
        c.open_vault_inner(arb_sk, inner, 100, pk_raw)


def test_vault_in_credential_flow():
    csk, cpk = c.generate_ed25519_keypair()
    arb_sk, coord_sk, pk_raw, vault = _vault_setup()
    sig = c.sign_credential(csk, 100, pk_raw, vault, 3)
    assert c.verify_credential(cpk, 100, pk_raw, vault, 3, sig)
    _, other_vault = _vault_setup()[2:]
    assert not c.verify_credential(cpk, 100, pk_raw, other_vault, 3, sig)


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


# --- Entrega de K_c e K_adm ---

def test_content_key_bound_to_context():
    sk, pk = c.generate_x25519_keypair()
    k_c = c.generate_symmetric_key()
    rid = c.compute_rid("id")
    w = c.wrap_content_key(pk, k_c, 10, rid, 2)
    assert c.unwrap_content_key(sk, w, 10, rid, 2) == k_c
    for e, r, v in [(11, rid, 2), (10, c.compute_rid("x"), 2), (10, rid, 3)]:
        with pytest.raises(ValueError):
            c.unwrap_content_key(sk, w, e, r, v)


def test_k_adm_bound_to_version_and_usage():
    sk, pk = c.generate_x25519_keypair()
    k_adm = c.generate_symmetric_key()
    w = c.wrap_k_adm(pk, k_adm, 5)
    assert c.unwrap_k_adm(sk, w, 5) == k_adm
    with pytest.raises(ValueError):
        c.unwrap_k_adm(sk, w, 6)
    # Um criptograma de K_adm não passa por K_c (info diferente), e vice-versa
    with pytest.raises(ValueError):
        c.ecies_decrypt(sk, w, info=c.INFO_KC, associated_data=c._u32(5))
    wk = c.wrap_content_key(pk, k_adm, 0, b"", 5)
    with pytest.raises(ValueError):
        c.unwrap_k_adm(sk, wk, 5)


def test_unwrap_from_key_list_not_member():
    members = [c.generate_x25519_keypair() for _ in range(2)]
    raws = [c.x25519_public_to_raw(pk) for _, pk in members]
    rid = c.compute_rid("id")
    k_c = c.generate_symmetric_key()
    kl = c.build_key_list(raws, k_c, 1, rid, 1)
    for sk, _ in members:
        assert c.unwrap_from_key_list(sk, kl, 1, rid, 1) == k_c
    outsider_sk, _ = c.generate_x25519_keypair()
    with pytest.raises(ValueError):
        c.unwrap_from_key_list(outsider_sk, kl, 1, rid, 1)


# --- Épocas ---

def test_epoch_boundaries_at_00_and_12_utc():
    from datetime import datetime, timedelta, timezone
    utc = timezone.utc
    noon = datetime(2026, 11, 25, 12, 0, tzinfo=utc)
    e = c.epoch_id_for(noon)
    assert c.epoch_id_for(noon - timedelta(microseconds=1)) == e - 1
    assert c.epoch_id_for(datetime(2026, 11, 25, 23, 59, 59, tzinfo=utc)) == e
    assert c.epoch_id_for(datetime(2026, 11, 26, 0, 0, tzinfo=utc)) == e + 1
    start, end = c.epoch_bounds(e)
    assert start == noon and end == noon + timedelta(hours=12)


def test_epoch_respects_timezone_and_rejects_naive():
    from datetime import datetime, timedelta, timezone
    lisbon_summer = timezone(timedelta(hours=1))
    assert c.epoch_id_for(datetime(2026, 7, 1, 13, 0, tzinfo=lisbon_summer)) == \
        c.epoch_id_for(datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc))
    with pytest.raises(ValueError):
        c.epoch_id_for(datetime(2026, 7, 1, 12, 0))
    with pytest.raises(ValueError):
        c.epoch_bounds(-1)
    assert isinstance(c.current_epoch(), int)


# --- Fluxo completo: envelope de relatório ---

def test_full_report_envelope_flow():
    members = [c.generate_x25519_keypair() for _ in range(3)]
    raws = [c.x25519_public_to_raw(pub) for _, pub in members]
    sk_E, pk_E = c.generate_ed25519_keypair()
    k_adm = c.generate_symmetric_key()
    epoch, version = 10, 2
    rid = c.compute_rid("uuid-do-relatorio")

    k_c = c.generate_symmetric_key()
    ct = c.aes_gcm_encrypt(k_c, b'{"severity":"high"}', c.report_aad(epoch, rid, version))
    kl = c.build_key_list(raws, k_c, epoch, rid, version)
    sig = c.sign_report(sk_E, epoch, version, rid, ct, kl)
    tag = c.compute_admission_hmac(k_adm, epoch, version, rid, ct, kl)

    # Gateway
    assert c.verify_admission_hmac(k_adm, epoch, version, rid, ct, kl, tag)
    assert c.verify_report(pk_E, epoch, version, rid, ct, kl, sig)

    # Cada membro encontra a sua entrada e decifra
    for sk, _ in members:
        got_kc = c.unwrap_from_key_list(sk, kl, epoch, rid, version)
        assert c.aes_gcm_decrypt(got_kc, ct, c.report_aad(epoch, rid, version)) == b'{"severity":"high"}'

    # Um não-membro (revogado) não decifra nenhuma entrada
    outsider_sk, _ = c.generate_x25519_keypair()
    for _, wrapped in c.parse_key_list(kl):
        with pytest.raises(ValueError):
            c.unwrap_content_key(outsider_sk, wrapped, epoch, rid, version)
