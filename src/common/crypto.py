"""Primitivas criptográficas para a plataforma de partilha privada de incidentes.

Implementa:
- Assinaturas Ed25519 com separação de domínio e codificação segura de comprimentos.
- Cifra simétrica autenticada AES-256-GCM com nonce aleatório de 12 bytes e associated_data.
- Cifra assimétrica ECIES (X25519 efémero + HKDF-SHA256 + AES-256-GCM) para cofres e chaves de época.
- Gestão e serialização de chaves usando a biblioteca cryptography.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --- Separação de Domínio ---
DOMAIN_CREDENTIAL = b"FED-CRED-v1"
DOMAIN_POP = b"FED-POP-v1"
DOMAIN_REPORT = b"FED-REPORT-v1"
DOMAIN_CORROB = b"FED-CORROB-v1"
DOMAIN_VERDICT = b"FED-VERDICT-v1"
DOMAIN_DIRECTORY = b"FED-DIR-v1"
DOMAIN_ADMISSION = b"FED-ADM-v1"

# Rótulos HKDF (separação de utilização) para a cadeia de pseudónimos
INFO_CHAIN_KEY = b"FED-CHAIN-key-v1"
INFO_CHAIN_NEXT = b"FED-CHAIN-next-v1"


def _pack_with_length(data: bytes) -> bytes:
    """Codifica bytes prefixados com o seu comprimento em 4 bytes (big-endian)."""
    return struct.pack(">I", len(data)) + data


# --- Chaves e Aleatoriedade ---

def generate_symmetric_key(length: int = 32) -> bytes:
    """Gera uma chave simétrica segura (ex.: 32 bytes para AES-256)."""
    return os.urandom(length)


def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Gera um par de chaves Ed25519 para assinatura."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Gera um par de chaves X25519 para troca de chaves/cifra."""
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


# --- Serialização de Chaves Ed25519 ---

def ed25519_private_to_pem(private_key: ed25519.Ed25519PrivateKey, passphrase: str | None = None) -> bytes:
    """Serializa chave privada Ed25519 para PEM (opcionalmente cifrada com BestAvailableEncryption)."""
    encryption: serialization.KeySerializationEncryption
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def ed25519_private_from_pem(pem_bytes: bytes, passphrase: str | None = None) -> ed25519.Ed25519PrivateKey:
    """Carrega chave privada Ed25519 a partir de PEM."""
    pwd = passphrase.encode("utf-8") if passphrase else None
    key = serialization.load_pem_private_key(pem_bytes, password=pwd)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("A chave PEM fornecida não é Ed25519.")
    return key


def ed25519_public_to_pem(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Serializa chave pública Ed25519 para PEM (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def ed25519_public_from_pem(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Carrega chave pública Ed25519 a partir de PEM."""
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("A chave PEM fornecida não é pública Ed25519.")
    return key


def ed25519_public_to_raw(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Devolve os 32 bytes brutos da chave pública Ed25519."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_public_from_raw(raw_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Reconstrói chave pública Ed25519 a partir dos 32 bytes brutos."""
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)


# --- Serialização de Chaves X25519 ---

def x25519_private_to_pem(private_key: x25519.X25519PrivateKey, passphrase: str | None = None) -> bytes:
    """Serializa chave privada X25519 para PEM."""
    encryption: serialization.KeySerializationEncryption
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def x25519_private_from_pem(pem_bytes: bytes, passphrase: str | None = None) -> x25519.X25519PrivateKey:
    """Carrega chave privada X25519 a partir de PEM."""
    pwd = passphrase.encode("utf-8") if passphrase else None
    key = serialization.load_pem_private_key(pem_bytes, password=pwd)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise ValueError("A chave PEM fornecida não é X25519.")
    return key


def x25519_public_to_pem(public_key: x25519.X25519PublicKey) -> bytes:
    """Serializa chave pública X25519 para PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def x25519_public_from_pem(pem_bytes: bytes) -> x25519.X25519PublicKey:
    """Carrega chave pública X25519 a partir de PEM."""
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, x25519.X25519PublicKey):
        raise ValueError("A chave PEM fornecida não é pública X25519.")
    return key


def x25519_public_to_raw(public_key: x25519.X25519PublicKey) -> bytes:
    """Devolve os 32 bytes brutos da chave pública X25519."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_from_raw(raw_bytes: bytes) -> x25519.X25519PublicKey:
    """Reconstrói chave pública X25519 a partir dos 32 bytes brutos."""
    return x25519.X25519PublicKey.from_public_bytes(raw_bytes)


# --- Cifra Simétrica Autenticada (AES-256-GCM) ---

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Cifra dados com AES-256-GCM gerando nonce aleatório de 12 bytes.

    Formato retornado: nonce (12 bytes) + ciphertext + tag de autenticação (16 bytes).
    """
    if len(key) != 32:
        raise ValueError("A chave para AES-256-GCM tem de ter exatamente 32 bytes.")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext_and_tag


def aes_gcm_decrypt(key: bytes, payload: bytes, associated_data: bytes | None = None) -> bytes:
    """Decifra dados AES-256-GCM (nonce de 12 bytes + ciphertext + tag de 16 bytes)."""
    if len(key) != 32:
        raise ValueError("A chave para AES-256-GCM tem de ter exatamente 32 bytes.")
    if len(payload) < 12 + 16:
        raise ValueError("Payload cifrado demasiado curto para conter nonce e tag.")
    nonce = payload[:12]
    ciphertext_and_tag = payload[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
    except InvalidTag:
        raise ValueError("Falha na autenticação do ciphertext AES-GCM (tag inválida ou adulterada).")


# --- Cifra Híbrida / ECIES (X25519 + HKDF-SHA256 + AES-256-GCM) ---

def _ecies_key(shared_secret: bytes, eph_pub_bytes: bytes, recipient_pub_bytes: bytes, info: bytes) -> bytes:
    """Deriva a chave AES do ECIES. O salt liga a chave às duas chaves públicas envolvidas."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub_bytes + recipient_pub_bytes,
        info=info,
    ).derive(shared_secret)


def ecies_encrypt(
    recipient_public_key: x25519.X25519PublicKey,
    plaintext: bytes,
    info: bytes = b"FED-ECIES-v1",
    associated_data: bytes | None = None,
) -> bytes:
    """Cifra para uma chave pública X25519 destinatária usando ECIES efémero.

    `info` separa utilizações (HKDF) e `associated_data` é autenticado pelo AES-GCM,
    de modo que um criptograma não possa ser reutilizado noutro contexto.

    Formato resultante:
    ephemeral_public_key (32 bytes) + nonce (12 bytes) + ciphertext_and_tag.
    """
    ephemeral_private, ephemeral_public = generate_x25519_keypair()
    shared_secret = ephemeral_private.exchange(recipient_public_key)

    eph_pub_bytes = x25519_public_to_raw(ephemeral_public)
    recipient_pub_bytes = x25519_public_to_raw(recipient_public_key)
    derived_aes_key = _ecies_key(shared_secret, eph_pub_bytes, recipient_pub_bytes, info)

    nonce = os.urandom(12)
    aesgcm = AESGCM(derived_aes_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    return eph_pub_bytes + nonce + ciphertext_and_tag


def ecies_decrypt(
    recipient_private_key: x25519.X25519PrivateKey,
    payload: bytes,
    info: bytes = b"FED-ECIES-v1",
    associated_data: bytes | None = None,
) -> bytes:
    """Decifra payload ECIES usando a chave privada X25519 do destinatário."""
    if len(payload) < 32 + 12 + 16:
        raise ValueError("Payload ECIES demasiado curto.")

    eph_pub_bytes = payload[:32]
    nonce = payload[32:44]
    ciphertext_and_tag = payload[44:]

    ephemeral_public = x25519_public_from_raw(eph_pub_bytes)
    shared_secret = recipient_private_key.exchange(ephemeral_public)

    recipient_pub_bytes = x25519_public_to_raw(recipient_private_key.public_key())
    derived_aes_key = _ecies_key(shared_secret, eph_pub_bytes, recipient_pub_bytes, info)

    aesgcm = AESGCM(derived_aes_key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
    except InvalidTag:
        raise ValueError("Falha na decifração ECIES (dados corrompidos, chave, info ou contexto incorretos).")


# --- Prova de Posse (Proof-of-Possession) do Membro ---

def create_pop_message(epoch_id: int, challenge_bytes: bytes) -> bytes:
    """Mensagem normalizada a assinar pelo membro para provar posse da sua sk_ep."""
    epoch_bytes = struct.pack(">I", epoch_id)
    return DOMAIN_POP + _pack_with_length(epoch_bytes) + _pack_with_length(challenge_bytes)


def sign_pop(sk_ep: ed25519.Ed25519PrivateKey, epoch_id: int, challenge_bytes: bytes) -> bytes:
    """Assina o desafio PoP com a chave privada efêmera do membro."""
    msg = create_pop_message(epoch_id, challenge_bytes)
    return sk_ep.sign(msg)


def verify_pop(pk_ep: ed25519.Ed25519PublicKey, epoch_id: int, challenge_bytes: bytes, signature: bytes) -> bool:
    """Verifica a assinatura da prova de posse com a chave pública efêmera."""
    msg = create_pop_message(epoch_id, challenge_bytes)
    try:
        pk_ep.verify(signature, msg)
        return True
    except InvalidSignature:
        return False


# --- Credenciais Emitidas pelo Coordinator ---

def create_credential_message(epoch_id: int, pk_ep_bytes: bytes, vault_ciphertext: bytes) -> bytes:
    """Mensagem normalizada assinada pelo Coordinator na emissão da credencial."""
    epoch_bytes = struct.pack(">I", epoch_id)
    vault_hash = hashlib.sha256(vault_ciphertext).digest()
    return (
        DOMAIN_CREDENTIAL
        + _pack_with_length(epoch_bytes)
        + _pack_with_length(pk_ep_bytes)
        + _pack_with_length(vault_hash)
    )


def sign_credential(coordinator_sk: ed25519.Ed25519PrivateKey, epoch_id: int, pk_ep_bytes: bytes, vault_ciphertext: bytes) -> bytes:
    """Assina a credencial de um membro para a época atual."""
    msg = create_credential_message(epoch_id, pk_ep_bytes, vault_ciphertext)
    return coordinator_sk.sign(msg)


def verify_credential(coordinator_pk: ed25519.Ed25519PublicKey, epoch_id: int, pk_ep_bytes: bytes, vault_ciphertext: bytes, signature: bytes) -> bool:
    """Verifica a assinatura da credencial emitida pelo Coordinator."""
    msg = create_credential_message(epoch_id, pk_ep_bytes, vault_ciphertext)
    try:
        coordinator_pk.verify(signature, msg)
        return True
    except InvalidSignature:
        return False


# --- Cofre do Arbiter (Vault) ---

def build_vault_payload(member_id: str, pk_ep_bytes: bytes, epoch_id: int) -> bytes:
    """Constrói o conteúdo interno em claro do cofre: member_id + pk_ep + epoch_id."""
    member_id_bytes = member_id.encode("utf-8")
    epoch_bytes = struct.pack(">I", epoch_id)
    return _pack_with_length(member_id_bytes) + _pack_with_length(pk_ep_bytes) + _pack_with_length(epoch_bytes)


def parse_vault_payload(plaintext: bytes) -> Tuple[str, bytes, int]:
    """Extrai os campos de um cofre aberto: (member_id, pk_ep_bytes, epoch_id)."""
    offset = 0

    def unpack_next() -> bytes:
        nonlocal offset
        if offset + 4 > len(plaintext):
            raise ValueError("Payload do cofre incompleto.")
        length = struct.unpack(">I", plaintext[offset:offset+4])[0]
        offset += 4
        if offset + length > len(plaintext):
            raise ValueError("Payload do cofre truncado.")
        chunk = plaintext[offset:offset+length]
        offset += length
        return chunk

    member_id = unpack_next().decode("utf-8")
    pk_ep_bytes = unpack_next()
    epoch_bytes = unpack_next()
    epoch_id = struct.unpack(">I", epoch_bytes)[0]
    return member_id, pk_ep_bytes, epoch_id


# --- Identificadores e lista de destinatários ---

def compute_rid(report_id: str) -> bytes:
    """rid = SHA-256(report_id). Público; o report_id fica só dentro do conteúdo cifrado."""
    return hashlib.sha256(report_id.encode("utf-8")).digest()


def recipient_key_id(recipient_pub_raw: bytes) -> bytes:
    """Identificador de um destinatário na lista de chaves: SHA-256 da chave pública de cifra."""
    return hashlib.sha256(recipient_pub_raw).digest()


def serialize_key_list(entries: list[tuple[bytes, bytes]]) -> bytes:
    """Serializa a lista de chaves [(key_id, K_c cifrada)] de forma determinística (ordem dada)."""
    out = struct.pack(">I", len(entries))
    for key_id, wrapped in entries:
        out += _pack_with_length(key_id) + _pack_with_length(wrapped)
    return out


def parse_key_list(data: bytes) -> list[tuple[bytes, bytes]]:
    """Inverso de serialize_key_list. Rejeita dados truncados ou com lixo no fim."""
    if len(data) < 4:
        raise ValueError("Lista de chaves incompleta.")
    (count,) = struct.unpack(">I", data[:4])
    offset = 4

    def take() -> bytes:
        nonlocal offset
        if offset + 4 > len(data):
            raise ValueError("Lista de chaves truncada.")
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        offset += 4
        if offset + length > len(data):
            raise ValueError("Lista de chaves truncada.")
        chunk = data[offset:offset + length]
        offset += length
        return chunk

    entries = []
    for _ in range(count):
        key_id = take()
        wrapped = take()
        entries.append((key_id, wrapped))
    if offset != len(data):
        raise ValueError("Lista de chaves com dados a mais.")
    return entries


def envelope_digest(ciphertext: bytes, key_list: bytes) -> bytes:
    """SHA-256 do ciphertext e da lista de chaves (com prefixos de comprimento)."""
    return hashlib.sha256(_pack_with_length(ciphertext) + _pack_with_length(key_list)).digest()


# --- Assinatura de relatórios e corroborações (sk_E) ---

def _envelope_message(domain: bytes, epoch_id: int, version: int, rid: bytes,
                      ciphertext: bytes, key_list: bytes) -> bytes:
    return (
        domain
        + _pack_with_length(struct.pack(">I", epoch_id))
        + _pack_with_length(struct.pack(">I", version))
        + _pack_with_length(rid)
        + _pack_with_length(envelope_digest(ciphertext, key_list))
    )


def _sign_envelope(domain: bytes, sk_ep: ed25519.Ed25519PrivateKey, epoch_id: int, version: int,
                   rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    return sk_ep.sign(_envelope_message(domain, epoch_id, version, rid, ciphertext, key_list))


def _verify_envelope(domain: bytes, pk_ep: ed25519.Ed25519PublicKey, epoch_id: int, version: int,
                     rid: bytes, ciphertext: bytes, key_list: bytes, signature: bytes) -> bool:
    try:
        pk_ep.verify(signature, _envelope_message(domain, epoch_id, version, rid, ciphertext, key_list))
        return True
    except InvalidSignature:
        return False


def sign_report(sk_ep, epoch_id: int, version: int, rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    """Assina um relatório com sk_E (domínio FED-REPORT-v1)."""
    return _sign_envelope(DOMAIN_REPORT, sk_ep, epoch_id, version, rid, ciphertext, key_list)


def verify_report(pk_ep, epoch_id: int, version: int, rid: bytes, ciphertext: bytes,
                  key_list: bytes, signature: bytes) -> bool:
    """Verifica a assinatura de um relatório."""
    return _verify_envelope(DOMAIN_REPORT, pk_ep, epoch_id, version, rid, ciphertext, key_list, signature)


def sign_corroboration(sk_ep, epoch_id: int, version: int, rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    """Assina uma corroboração com sk_E (domínio FED-CORROB-v1)."""
    return _sign_envelope(DOMAIN_CORROB, sk_ep, epoch_id, version, rid, ciphertext, key_list)


def verify_corroboration(pk_ep, epoch_id: int, version: int, rid: bytes, ciphertext: bytes,
                         key_list: bytes, signature: bytes) -> bool:
    """Verifica a assinatura de uma corroboração."""
    return _verify_envelope(DOMAIN_CORROB, pk_ep, epoch_id, version, rid, ciphertext, key_list, signature)


def report_aad(epoch_id: int, rid: bytes, version: int) -> bytes:
    """Dados associados do AES-GCM do conteúdo: época, rid e versão V."""
    return (
        _pack_with_length(struct.pack(">I", epoch_id))
        + _pack_with_length(rid)
        + _pack_with_length(struct.pack(">I", version))
    )


# --- Diretório de membros (Coordinator) ---

def create_directory_message(version: int, member_pubkeys: list[bytes]) -> bytes:
    """Mensagem do diretório V: versão e lista das chaves públicas de cifra dos membros ativos."""
    msg = DOMAIN_DIRECTORY + _pack_with_length(struct.pack(">I", version))
    msg += struct.pack(">I", len(member_pubkeys))
    for pub in member_pubkeys:
        msg += _pack_with_length(pub)
    return msg


def sign_directory(coordinator_sk: ed25519.Ed25519PrivateKey, version: int, member_pubkeys: list[bytes]) -> bytes:
    """O Coordinator assina o diretório da versão V."""
    return coordinator_sk.sign(create_directory_message(version, member_pubkeys))


def verify_directory(coordinator_pk: ed25519.Ed25519PublicKey, version: int,
                     member_pubkeys: list[bytes], signature: bytes) -> bool:
    """Verifica a assinatura do diretório da versão V."""
    try:
        coordinator_pk.verify(signature, create_directory_message(version, member_pubkeys))
        return True
    except InvalidSignature:
        return False


# --- Veredito (Arbiter) ---

def create_verdict_message(rid: bytes, result: str) -> bytes:
    return DOMAIN_VERDICT + _pack_with_length(rid) + _pack_with_length(result.encode("utf-8"))


def sign_verdict(arbiter_sk: ed25519.Ed25519PrivateKey, rid: bytes, result: str) -> bytes:
    """O Arbiter assina o veredito sobre um rid (sem identidade)."""
    return arbiter_sk.sign(create_verdict_message(rid, result))


def verify_verdict(arbiter_pk: ed25519.Ed25519PublicKey, rid: bytes, result: str, signature: bytes) -> bool:
    """Verifica a assinatura do veredito."""
    try:
        arbiter_pk.verify(signature, create_verdict_message(rid, result))
        return True
    except InvalidSignature:
        return False


# --- Cadeia de pseudónimos por época ---

def _hkdf32(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def derive_epoch_key(chain_key: bytes) -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    """Dado CK_E, devolve (sk_E, CK_E+1).

    sk_E = HKDF(CK_E, "key") e CK_E+1 = HKDF(CK_E, "next"). O chamador deve guardar
    CK_E+1 e deitar fora CK_E: quem obtiver CK_E+1 não consegue recuperar sk_E nem CK_E.
    """
    if len(chain_key) != 32:
        raise ValueError("A chave da cadeia tem de ter 32 bytes.")
    sk_seed = _hkdf32(chain_key, INFO_CHAIN_KEY)
    next_ck = _hkdf32(chain_key, INFO_CHAIN_NEXT)
    return ed25519.Ed25519PrivateKey.from_private_bytes(sk_seed), next_ck


def derive_epoch_batch(chain_key: bytes, count: int) -> Tuple[list[ed25519.Ed25519PrivateKey], bytes]:
    """Deriva as chaves de `count` épocas consecutivas e devolve também a CK seguinte."""
    if count < 1:
        raise ValueError("count tem de ser pelo menos 1.")
    keys = []
    ck = chain_key
    for _ in range(count):
        sk, ck = derive_epoch_key(ck)
        keys.append(sk)
    return keys, ck


# --- HMAC de admissão (K_adm) ---

def _admission_message(epoch_id: int, version: int, rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    return (
        DOMAIN_ADMISSION
        + _pack_with_length(struct.pack(">I", epoch_id))
        + _pack_with_length(struct.pack(">I", version))
        + _pack_with_length(rid)
        + _pack_with_length(envelope_digest(ciphertext, key_list))
    )


def compute_admission_hmac(k_adm: bytes, epoch_id: int, version: int, rid: bytes,
                           ciphertext: bytes, key_list: bytes) -> bytes:
    """HMAC-SHA256 de admissão com K_adm, ligado à época, versão, rid e envelope."""
    return hmac.new(k_adm, _admission_message(epoch_id, version, rid, ciphertext, key_list),
                    hashlib.sha256).digest()


def verify_admission_hmac(k_adm: bytes, epoch_id: int, version: int, rid: bytes,
                          ciphertext: bytes, key_list: bytes, tag: bytes) -> bool:
    """Verifica o HMAC de admissão em tempo constante."""
    expected = compute_admission_hmac(k_adm, epoch_id, version, rid, ciphertext, key_list)
    return hmac.compare_digest(expected, tag)
