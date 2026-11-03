"""Testes unitários das primitivas criptográficas em src/common/crypto.py."""

import unittest

from src.common.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    build_vault_payload,
    ecies_decrypt,
    ecies_encrypt,
    ed25519_private_from_pem,
    ed25519_private_to_pem,
    ed25519_public_from_pem,
    ed25519_public_to_pem,
    ed25519_public_to_raw,
    generate_ed25519_keypair,
    generate_symmetric_key,
    generate_x25519_keypair,
    parse_vault_payload,
    sign_credential,
    sign_pop,
    verify_credential,
    verify_pop,
    x25519_private_from_pem,
    x25519_private_to_pem,
    x25519_public_from_pem,
    x25519_public_to_pem,
)


class TestCrypto(unittest.TestCase):
    def test_ed25519_keygen_and_pem(self):
        sk, pk = generate_ed25519_keypair()
        pem_sk = ed25519_private_to_pem(sk, passphrase="segredo_forte")
        pem_pk = ed25519_public_to_pem(pk)

        sk_loaded = ed25519_private_from_pem(pem_sk, passphrase="segredo_forte")
        pk_loaded = ed25519_public_from_pem(pem_pk)

        # Assinar com a carregada e verificar com a original
        sig = sk_loaded.sign(b"teste")
        pk.verify(sig, b"teste")

    def test_x25519_keygen_and_pem(self):
        sk, pk = generate_x25519_keypair()
        pem_sk = x25519_private_to_pem(sk)
        pem_pk = x25519_public_to_pem(pk)

        sk_loaded = x25519_private_from_pem(pem_sk)
        pk_loaded = x25519_public_from_pem(pem_pk)
        self.assertEqual(pem_pk, x25519_public_to_pem(pk_loaded))

    def test_aes_gcm(self):
        key = generate_symmetric_key(32)
        plaintext = b"Dados ultra-secretos do relatorio de incidente"
        aad = b"associated_data_epoch_1"

        encrypted = aes_gcm_encrypt(key, plaintext, associated_data=aad)
        decrypted = aes_gcm_decrypt(key, encrypted, associated_data=aad)
        self.assertEqual(decrypted, plaintext)

        # Adulteração de dados associados deve falhar
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(key, encrypted, associated_data=b"outro_aad")

        # Adulteração do ciphertext deve falhar
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(key, bytes(tampered), associated_data=aad)

    def test_ecies(self):
        recipient_sk, recipient_pk = generate_x25519_keypair()
        msg = b"Chave simetrica de epoca K_ep"

        encrypted = ecies_encrypt(recipient_pk, msg)
        decrypted = ecies_decrypt(recipient_sk, encrypted)
        self.assertEqual(decrypted, msg)

        # Chave errada deve falhar
        other_sk, _ = generate_x25519_keypair()
        with self.assertRaises(ValueError):
            ecies_decrypt(other_sk, encrypted)

    def test_proof_of_possession(self):
        sk_ep, pk_ep = generate_ed25519_keypair()
        epoch_id = 1
        challenge = b"desafio_aleatorio_32_bytes_12345"

        sig = sign_pop(sk_ep, epoch_id, challenge)
        self.assertTrue(verify_pop(pk_ep, epoch_id, challenge, sig))

        # Época incorreta ou desafio alterado deve falhar
        self.assertFalse(verify_pop(pk_ep, 2, challenge, sig))
        self.assertFalse(verify_pop(pk_ep, epoch_id, b"outro_desafio", sig))

    def test_credential_and_vault(self):
        coord_sk, coord_pk = generate_ed25519_keypair()
        arbiter_sk, arbiter_pk = generate_x25519_keypair()
        member_sk_ep, member_pk_ep = generate_ed25519_keypair()

        member_id = "ISP-Alpha-99"
        epoch_id = 42
        pk_ep_raw = ed25519_public_to_raw(member_pk_ep)

        # Criar e cifrar cofre para o Arbiter
        vault_payload = build_vault_payload(member_id, pk_ep_raw, epoch_id)
        vault_ciphertext = ecies_encrypt(arbiter_pk, vault_payload)

        # Coordinator assina credencial
        cred_sig = sign_credential(coord_sk, epoch_id, pk_ep_raw, vault_ciphertext)

        # Verificar credencial
        self.assertTrue(verify_credential(coord_pk, epoch_id, pk_ep_raw, vault_ciphertext, cred_sig))

        # Arbiter decifra cofre e recupera identidade
        decrypted_vault = ecies_decrypt(arbiter_sk, vault_ciphertext)
        dec_member_id, dec_pk_ep, dec_epoch = parse_vault_payload(decrypted_vault)

        self.assertEqual(dec_member_id, member_id)
        self.assertEqual(dec_pk_ep, pk_ep_raw)
        self.assertEqual(dec_epoch, epoch_id)


if __name__ == "__main__":
    unittest.main()
