"""Testes de integração do Federation Coordinator e do servidor de atendimento a membros."""

import base64
import json
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from src.common.crypto import (
    ecies_decrypt,
    ed25519_private_to_pem,
    ed25519_public_from_raw,
    ed25519_public_to_pem,
    ed25519_public_to_raw,
    generate_ed25519_keypair,
    generate_symmetric_key,
    generate_x25519_keypair,
    parse_vault_payload,
    sign_pop,
    verify_credential,
    x25519_private_to_pem,
    x25519_public_to_pem,
)
from src.coordinator.database import CoordinatorDatabase
from src.coordinator.logger import COORDINATOR_LOG_FILE, read_recent_logs
from src.coordinator.server import CoordinatorServer


class TestCoordinator(unittest.TestCase):
    def setUp(self):
        # Base de dados temporária para testes isolados
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_coordinator.db"
        self.db = CoordinatorDatabase(self.db_path)

        # Chaves de teste
        self.coord_sk, self.coord_pk = generate_ed25519_keypair()
        self.arbiter_sk, self.arbiter_pk = generate_x25519_keypair()

        # Iniciar servidor em porta dinâmica (0) para evitar conflitos
        self.server = CoordinatorServer(
            host="127.0.0.1",
            port=0,
            db=self.db,
            coordinator_sk=self.coord_sk,
            arbiter_pk=self.arbiter_pk,
        )
        self.server.start()
        self.port = self.server.port
        self.base_url = f"http://127.0.0.1:{self.port}"
        time.sleep(0.05)  # Pequena pausa para garantir arranque

    def tearDown(self):
        self.server.stop()
        self.temp_dir.cleanup()

    def _http_request(self, method: str, path: str, data: dict = None) -> tuple[int, dict]:
        url = f"{self.base_url}{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                return resp.status, resp_data
        except urllib.error.HTTPError as e:
            try:
                resp_data = json.loads(e.read().decode("utf-8")) if e.fp else {}
            finally:
                e.close()
            return e.code, resp_data

    def test_health_check(self):
        status, data = self._http_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(data.get("status"), "ok")

    def test_complete_member_flow(self):
        # 1. Criar época inicial
        epoch_key = generate_symmetric_key(32)
        epoch = self.db.advance_epoch(epoch_key)
        epoch_id = epoch["epoch_id"]

        # 2. Inscrever um membro
        member_id = "ISP-Test-PT"
        member_name = "ISP de Teste Portugal"
        member_login_sk, member_login_pk = generate_ed25519_keypair()
        member_enc_sk, member_enc_pk = generate_x25519_keypair()

        self.db.enroll_member(
            member_id=member_id,
            name=member_name,
            login_pubkey_pem=ed25519_public_to_pem(member_login_pk).decode("utf-8"),
            enc_pubkey_pem=x25519_public_to_pem(member_enc_pk).decode("utf-8"),
        )

        # 3. Membro gera par de chaves efêmeras para a época
        sk_ep, pk_ep = generate_ed25519_keypair()
        pk_ep_raw = ed25519_public_to_raw(pk_ep)
        pk_ep_b64 = base64.b64encode(pk_ep_raw).decode("utf-8")

        # 4. Pedir desafio de prova de posse (PoP)
        status, challenge_resp = self._http_request("POST", "/api/v1/auth/challenge", {
            "member_id": member_id,
            "epoch_id": epoch_id,
            "pk_ep_raw": pk_ep_b64,
        })
        self.assertEqual(status, 200)
        challenge_id = challenge_resp["challenge_id"]
        nonce = base64.b64decode(challenge_resp["nonce"])

        # 5. Assinar desafio PoP com sk_ep do membro
        pop_sig = sign_pop(sk_ep, epoch_id, nonce)
        pop_sig_b64 = base64.b64encode(pop_sig).decode("utf-8")

        # 6. Solicitar emissão da credencial anónima
        status, cred_resp = self._http_request("POST", "/api/v1/credentials/issue", {
            "challenge_id": challenge_id,
            "member_id": member_id,
            "epoch_id": epoch_id,
            "pk_ep_raw": pk_ep_b64,
            "pop_signature": pop_sig_b64,
        })
        self.assertEqual(status, 201)
        self.assertEqual(cred_resp["epoch_id"], epoch_id)

        vault_ciphertext = base64.b64decode(cred_resp["vault"])
        cred_sig = base64.b64decode(cred_resp["signature"])

        # 7. Validar assinatura da credencial com a chave pública do Coordinator
        self.assertTrue(
            verify_credential(
                coordinator_pk=self.coord_pk,
                epoch_id=epoch_id,
                pk_ep_bytes=pk_ep_raw,
                vault_ciphertext=vault_ciphertext,
                signature=cred_sig,
            )
        )

        # 8. Verificar que o Arbiter consegue decifrar o cofre e ler a identidade
        decrypted_vault = ecies_decrypt(self.arbiter_sk, vault_ciphertext)
        dec_member, dec_pk, dec_epoch = parse_vault_payload(decrypted_vault)
        self.assertEqual(dec_member, member_id)
        self.assertEqual(dec_pk, pk_ep_raw)
        self.assertEqual(dec_epoch, epoch_id)

        # 9. Tentar pedir segunda credencial na mesma época deve falhar (409 Conflict)
        status, conflict_resp = self._http_request("POST", "/api/v1/auth/challenge", {
            "member_id": member_id,
            "epoch_id": epoch_id,
            "pk_ep_raw": pk_ep_b64,
        })
        self.assertEqual(status, 409)

        # 10. Obter chave da época K_ep cifrada para o membro
        status, key_resp = self._http_request("POST", "/api/v1/epoch/key", {
            "member_id": member_id,
            "epoch_id": epoch_id,
        })
        self.assertEqual(status, 200)
        wrapped_key = base64.b64decode(key_resp["wrapped_epoch_key"])
        decrypted_epoch_key = ecies_decrypt(member_enc_sk, wrapped_key)
        self.assertEqual(decrypted_epoch_key, epoch_key)

        # 11. Revogar membro e verificar recusa imediata
        self.db.revoke_member(member_id, reason="Chave comprometida em teste")
        status, rev_resp = self._http_request("POST", "/api/v1/auth/challenge", {
            "member_id": member_id,
            "epoch_id": epoch_id,
            "pk_ep_raw": pk_ep_b64,
        })
        self.assertEqual(status, 403)

        # 12. Verificar que o ficheiro de log foi preenchido
        self.assertTrue(COORDINATOR_LOG_FILE.exists())
        recent_logs = read_recent_logs(20)
        self.assertTrue(any("Credencial emitida com sucesso" in line for line in recent_logs))


if __name__ == "__main__":
    unittest.main()
