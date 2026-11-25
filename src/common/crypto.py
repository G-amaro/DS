"""Primitivas criptográficas para a plataforma de partilha privada de incidentes.

Implementa:
- Assinaturas Ed25519 com separação de domínio e codificação segura de comprimentos.
- Cifra simétrica autenticada AES-256-GCM com nonce aleatório de 12 bytes e associated_data obrigatório.
- Cifra assimétrica ECIES (X25519 efémero + HKDF-SHA256 + AES-256-GCM) com `info` e
  associated_data obrigatórios, para que um criptograma não possa ser reutilizado noutro contexto.
- Entrega de K_c e de K_adm, cofre em duas camadas (Arbiter dentro, Coordinator fora).
- Cadeia de pseudónimos por época (HKDF), HMAC de admissão (K_adm) e cálculo de épocas de 12 h.
- Gestão e serialização de chaves usando a biblioteca cryptography (>= 42).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from datetime import datetime, timedelta, timezone
from typing import Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --- Separação de Domínio (assinaturas e HMAC) ---
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

# Rótulos HKDF do ECIES, um por utilização
INFO_KC = b"FED-KC-v1"                   # K_c para cada membro do diretório
INFO_DIRKEY = b"FED-DIRKEY-v1"           # K_adm para cada membro ativo
INFO_VAULT_INNER = b"FED-VAULT-IN-v1"    # Cofre interior (chave do Arbiter)
INFO_VAULT_OUTER = b"FED-VAULT-OUT-v1"   # Cofre exterior (chave de cofre do Coordinator)

# Duração da época E (12 h, fronteiras às 00:00 e 12:00 UTC)
EPOCH_SECONDS = 12 * 3600


def _pack_with_length(data: bytes) -> bytes:
    """Codifica bytes prefixados com o seu comprimento em 4 bytes (big-endian)."""
    return struct.pack(">I", len(data)) + data


def _u32(value: int) -> bytes:
    """Inteiro sem sinal de 32 bits, big-endian, prefixado com o comprimento."""
    return _pack_with_length(struct.pack(">I", value))


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


# --- Passphrases das chaves em disco ---

def _encryption_for(passphrase: str | None) -> serialization.KeySerializationEncryption:
    """None significa explicitamente "sem cifra"; uma passphrase vazia é recusada."""
    if passphrase is None:
        return serialization.NoEncryption()
    if passphrase == "":
        raise ValueError("Passphrase vazia: use None para guardar sem cifra.")
    return serialization.BestAvailableEncryption(passphrase.encode("utf-8"))


def _password_bytes(passphrase: str | None) -> bytes | None:
    if passphrase is None:
        return None
    if passphrase == "":
        raise ValueError("Passphrase vazia: use None para chaves sem cifra.")
    return passphrase.encode("utf-8")


# --- Serialização de Chaves Ed25519 ---

def ed25519_private_to_pem(private_key: ed25519.Ed25519PrivateKey, passphrase: str | None = None) -> bytes:
    """Serializa chave privada Ed25519 para PEM (cifrada com BestAvailableEncryption se houver passphrase)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_encryption_for(passphrase),
    )


def ed25519_private_from_pem(pem_bytes: bytes, passphrase: str | None = None) -> ed25519.Ed25519PrivateKey:
    """Carrega chave privada Ed25519 a partir de PEM."""
    key = serialization.load_pem_private_key(pem_bytes, password=_password_bytes(passphrase))
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
    """Serializa chave privada X25519 para PEM (cifrada se houver passphrase)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_encryption_for(passphrase),
    )


def x25519_private_from_pem(pem_bytes: bytes, passphrase: str | None = None) -> x25519.X25519PrivateKey:
    """Carrega chave privada X25519 a partir de PEM."""
    key = serialization.load_pem_private_key(pem_bytes, password=_password_bytes(passphrase))
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

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Cifra dados com AES-256-GCM gerando nonce aleatório de 12 bytes.

    `associated_data` é obrigatório (None é recusado) para ligar o criptograma ao contexto.
    Formato retornado: nonce (12 bytes) + ciphertext + tag de autenticação (16 bytes).
    """
    if len(key) != 32:
        raise ValueError("A chave para AES-256-GCM tem de ter exatamente 32 bytes.")
    if associated_data is None:
        raise ValueError("associated_data é obrigatório no AES-GCM.")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext_and_tag


def aes_gcm_decrypt(key: bytes, payload: bytes, associated_data: bytes) -> bytes:
    """Decifra dados AES-256-GCM (nonce de 12 bytes + ciphertext + tag de 16 bytes)."""
    if len(key) != 32:
        raise ValueError("A chave para AES-256-GCM tem de ter exatamente 32 bytes.")
    if associated_data is None:
        raise ValueError("associated_data é obrigatório no AES-GCM.")
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

def _check_ecies_context(info: bytes, associated_data: bytes) -> None:
    if not info:
        raise ValueError("ECIES exige um `info` não vazio (uma constante INFO_* por utilização).")
    if associated_data is None:
        raise ValueError("ECIES exige associated_data.")


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
    *,
    info: bytes,
    associated_data: bytes,
) -> bytes:
    """Cifra para uma chave pública X25519 destinatária usando ECIES efémero.

    `info` separa utilizações (HKDF) e `associated_data` é autenticado pelo AES-GCM;
    ambos são obrigatórios, de modo que um criptograma não possa ser reutilizado noutro contexto.

    Formato resultante:
    ephemeral_public_key (32 bytes) + nonce (12 bytes) + ciphertext_and_tag.
    """
    _check_ecies_context(info, associated_data)
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
    *,
    info: bytes,
    associated_data: bytes,
) -> bytes:
    """Decifra payload ECIES usando a chave privada X25519 do destinatário."""
    _check_ecies_context(info, associated_data)
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
    """Mensagem normalizada a assinar pelo membro para provar posse da sua sk_E."""
    return DOMAIN_POP + _u32(epoch_id) + _pack_with_length(challenge_bytes)


def sign_pop(sk_E: ed25519.Ed25519PrivateKey, epoch_id: int, challenge_bytes: bytes) -> bytes:
    """Assina o desafio PoP com a chave privada da época."""
    return sk_E.sign(create_pop_message(epoch_id, challenge_bytes))


def verify_pop(pk_E: ed25519.Ed25519PublicKey, epoch_id: int, challenge_bytes: bytes, signature: bytes) -> bool:
    """Verifica a assinatura da prova de posse com a chave pública da época."""
    try:
        pk_E.verify(signature, create_pop_message(epoch_id, challenge_bytes))
        return True
    except InvalidSignature:
        return False


# --- Credenciais Emitidas pelo Coordinator ---

def create_credential_message(epoch_id: int, pk_E_bytes: bytes, vault_ciphertext: bytes,
                              vault_key_gen: int) -> bytes:
    """Mensagem normalizada assinada pelo Coordinator na emissão da credencial.

    Liga a época, a pk_E, o SHA-256 do cofre e a geração das chaves de cofre usadas.
    """
    vault_hash = hashlib.sha256(vault_ciphertext).digest()
    return (
        DOMAIN_CREDENTIAL
        + _u32(epoch_id)
        + _pack_with_length(pk_E_bytes)
        + _pack_with_length(vault_hash)
        + _u32(vault_key_gen)
    )


def sign_credential(coordinator_sk: ed25519.Ed25519PrivateKey, epoch_id: int, pk_E_bytes: bytes,
                    vault_ciphertext: bytes, vault_key_gen: int) -> bytes:
    """Assina a credencial de um membro para a época E."""
    return coordinator_sk.sign(create_credential_message(epoch_id, pk_E_bytes, vault_ciphertext, vault_key_gen))


def verify_credential(coordinator_pk: ed25519.Ed25519PublicKey, epoch_id: int, pk_E_bytes: bytes,
                      vault_ciphertext: bytes, vault_key_gen: int, signature: bytes) -> bool:
    """Verifica a assinatura da credencial emitida pelo Coordinator."""
    msg = create_credential_message(epoch_id, pk_E_bytes, vault_ciphertext, vault_key_gen)
    try:
        coordinator_pk.verify(signature, msg)
        return True
    except InvalidSignature:
        return False


# --- Cofre em duas camadas ---

def build_vault_payload(member_id: str, pk_E_bytes: bytes, epoch_id: int) -> bytes:
    """Constrói o conteúdo em claro do cofre interior: member_id + pk_E + E."""
    return (
        _pack_with_length(member_id.encode("utf-8"))
        + _pack_with_length(pk_E_bytes)
        + _pack_with_length(struct.pack(">I", epoch_id))
    )


def parse_vault_payload(plaintext: bytes) -> Tuple[str, bytes, int]:
    """Extrai os campos de um cofre interior aberto: (member_id, pk_E_bytes, epoch_id)."""
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
    pk_E_bytes = unpack_next()
    epoch_bytes = unpack_next()
    if len(epoch_bytes) != 4 or offset != len(plaintext):
        raise ValueError("Payload do cofre malformado.")
    epoch_id = struct.unpack(">I", epoch_bytes)[0]
    return member_id, pk_E_bytes, epoch_id


def _vault_inner_aad(epoch_id: int, pk_E_bytes: bytes) -> bytes:
    """Dados associados da camada interior: liga o cofre à época e à pk_E da credencial."""
    return _u32(epoch_id) + _pack_with_length(pk_E_bytes)


def _vault_outer_aad(epoch_id: int, vault_key_gen: int) -> bytes:
    """Dados associados da camada exterior: época e geração da chave de cofre (sem pk_E,
    para o Coordinator a poder remover sem a conhecer)."""
    return _u32(epoch_id) + _u32(vault_key_gen)


def seal_vault(arbiter_pk: x25519.X25519PublicKey, coord_vault_pk: x25519.X25519PublicKey,
               vault_key_gen: int, member_id: str, pk_E_bytes: bytes, epoch_id: int) -> bytes:
    """Cria o cofre em duas camadas (feito pelo Coordinator na emissão da credencial).

    interior = ECIES(chave do Arbiter, member_id + pk_E + E)
    exterior = ECIES(chave de cofre do Coordinator da geração `vault_key_gen`, interior)
    """
    inner = ecies_encrypt(
        arbiter_pk,
        build_vault_payload(member_id, pk_E_bytes, epoch_id),
        info=INFO_VAULT_INNER,
        associated_data=_vault_inner_aad(epoch_id, pk_E_bytes),
    )
    return ecies_encrypt(
        coord_vault_pk,
        inner,
        info=INFO_VAULT_OUTER,
        associated_data=_vault_outer_aad(epoch_id, vault_key_gen),
    )


def open_vault_outer(coord_vault_sk: x25519.X25519PrivateKey, vault: bytes,
                     epoch_id: int, vault_key_gen: int) -> bytes:
    """O Coordinator remove a camada exterior (só a pedido do Arbiter, numa disputa procedente)."""
    return ecies_decrypt(
        coord_vault_sk,
        vault,
        info=INFO_VAULT_OUTER,
        associated_data=_vault_outer_aad(epoch_id, vault_key_gen),
    )


def open_vault_inner(arbiter_sk: x25519.X25519PrivateKey, inner: bytes,
                     epoch_id: int, pk_E_bytes: bytes) -> str:
    """O Arbiter abre a camada interior e devolve o member_id.

    Confirma que a pk_E e a época dentro do cofre coincidem com as da credencial;
    caso contrário lança ValueError.
    """
    plaintext = ecies_decrypt(
        arbiter_sk,
        inner,
        info=INFO_VAULT_INNER,
        associated_data=_vault_inner_aad(epoch_id, pk_E_bytes),
    )
    member_id, got_pk, got_epoch = parse_vault_payload(plaintext)
    if got_epoch != epoch_id or not hmac.compare_digest(got_pk, pk_E_bytes):
        raise ValueError("O cofre não corresponde à pk_E e época da credencial.")
    return member_id


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


def report_aad(epoch_id: int, rid: bytes, version: int) -> bytes:
    """Dados associados do conteúdo (AES-GCM) e da entrega de K_c: época, rid e versão V."""
    return _u32(epoch_id) + _pack_with_length(rid) + _u32(version)


# --- Entrega de K_c (uma entrada por membro do diretório) ---

def wrap_content_key(recipient_pub: x25519.X25519PublicKey, k_c: bytes,
                     epoch_id: int, rid: bytes, version: int) -> bytes:
    """Cifra K_c para um membro (ECIES, info FED-KC-v1, ligada a E, rid e V)."""
    return ecies_encrypt(recipient_pub, k_c, info=INFO_KC,
                         associated_data=report_aad(epoch_id, rid, version))


def unwrap_content_key(recipient_sk: x25519.X25519PrivateKey, wrapped: bytes,
                       epoch_id: int, rid: bytes, version: int) -> bytes:
    """Decifra a K_c destinada a este membro."""
    return ecies_decrypt(recipient_sk, wrapped, info=INFO_KC,
                         associated_data=report_aad(epoch_id, rid, version))


def build_key_list(member_pubs_raw: list[bytes], k_c: bytes,
                   epoch_id: int, rid: bytes, version: int) -> bytes:
    """Constrói a lista de chaves serializada para todos os membros do diretório V."""
    entries = []
    for raw in member_pubs_raw:
        wrapped = wrap_content_key(x25519_public_from_raw(raw), k_c, epoch_id, rid, version)
        entries.append((recipient_key_id(raw), wrapped))
    return serialize_key_list(entries)


def unwrap_from_key_list(recipient_sk: x25519.X25519PrivateKey, key_list: bytes,
                         epoch_id: int, rid: bytes, version: int) -> bytes:
    """Procura a entrada deste membro na lista de chaves e devolve a K_c.

    Lança ValueError se o membro não constar da lista ou se a entrada não decifrar.
    """
    my_id = recipient_key_id(x25519_public_to_raw(recipient_sk.public_key()))
    for key_id, wrapped in parse_key_list(key_list):
        if hmac.compare_digest(key_id, my_id):
            return unwrap_content_key(recipient_sk, wrapped, epoch_id, rid, version)
    raise ValueError("Este membro não consta da lista de destinatários.")


# --- Entrega de K_adm (versão V) ---

def wrap_k_adm(member_pub: x25519.X25519PublicKey, k_adm: bytes, version: int) -> bytes:
    """Cifra a K_adm da versão V para um membro ativo (ECIES, info FED-DIRKEY-v1)."""
    return ecies_encrypt(member_pub, k_adm, info=INFO_DIRKEY, associated_data=_u32(version))


def unwrap_k_adm(member_sk: x25519.X25519PrivateKey, wrapped: bytes, version: int) -> bytes:
    """Decifra a K_adm da versão V."""
    return ecies_decrypt(member_sk, wrapped, info=INFO_DIRKEY, associated_data=_u32(version))


# --- Assinatura de relatórios e corroborações (sk_E) ---

def _envelope_message(domain: bytes, epoch_id: int, version: int, rid: bytes,
                      ciphertext: bytes, key_list: bytes) -> bytes:
    return (
        domain
        + _u32(epoch_id)
        + _u32(version)
        + _pack_with_length(rid)
        + _pack_with_length(envelope_digest(ciphertext, key_list))
    )


def _sign_envelope(domain: bytes, sk_E: ed25519.Ed25519PrivateKey, epoch_id: int, version: int,
                   rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    return sk_E.sign(_envelope_message(domain, epoch_id, version, rid, ciphertext, key_list))


def _verify_envelope(domain: bytes, pk_E: ed25519.Ed25519PublicKey, epoch_id: int, version: int,
                     rid: bytes, ciphertext: bytes, key_list: bytes, signature: bytes) -> bool:
    try:
        pk_E.verify(signature, _envelope_message(domain, epoch_id, version, rid, ciphertext, key_list))
        return True
    except InvalidSignature:
        return False


def sign_report(sk_E, epoch_id: int, version: int, rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    """Assina um relatório com sk_E (domínio FED-REPORT-v1)."""
    return _sign_envelope(DOMAIN_REPORT, sk_E, epoch_id, version, rid, ciphertext, key_list)


def verify_report(pk_E, epoch_id: int, version: int, rid: bytes, ciphertext: bytes,
                  key_list: bytes, signature: bytes) -> bool:
    """Verifica a assinatura de um relatório."""
    return _verify_envelope(DOMAIN_REPORT, pk_E, epoch_id, version, rid, ciphertext, key_list, signature)


def sign_corroboration(sk_E, epoch_id: int, version: int, rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    """Assina uma corroboração com sk_E (domínio FED-CORROB-v1); `rid` é o do relatório alvo."""
    return _sign_envelope(DOMAIN_CORROB, sk_E, epoch_id, version, rid, ciphertext, key_list)


def verify_corroboration(pk_E, epoch_id: int, version: int, rid: bytes, ciphertext: bytes,
                         key_list: bytes, signature: bytes) -> bool:
    """Verifica a assinatura de uma corroboração."""
    return _verify_envelope(DOMAIN_CORROB, pk_E, epoch_id, version, rid, ciphertext, key_list, signature)


# --- Diretório de membros (Coordinator) ---

def create_directory_message(version: int, member_pubkeys: list[bytes]) -> bytes:
    """Mensagem do diretório V: versão e lista das chaves públicas de cifra dos membros ativos."""
    msg = DOMAIN_DIRECTORY + _u32(version)
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


# --- Épocas de 12 h ---

def epoch_id_for(moment: datetime) -> int:
    """Número da época E que contém `moment` (épocas de 12 h desde 1970-01-01 00:00 UTC).

    Como 12 h divide um dia, as fronteiras caem sempre às 00:00 e 12:00 UTC.
    Exige datetime com fuso horário, para não confundir hora local com UTC.
    """
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("O datetime tem de ter fuso horário (use UTC).")
    return int(moment.timestamp()) // EPOCH_SECONDS


def epoch_bounds(epoch_id: int) -> Tuple[datetime, datetime]:
    """Início (inclusive) e fim (exclusive) da época E, em UTC."""
    if epoch_id < 0:
        raise ValueError("Época inválida.")
    start = datetime.fromtimestamp(epoch_id * EPOCH_SECONDS, tz=timezone.utc)
    return start, start + timedelta(seconds=EPOCH_SECONDS)


def current_epoch() -> int:
    """Época E atual."""
    return epoch_id_for(datetime.now(timezone.utc))


# --- HMAC de admissão (K_adm) ---

def _admission_message(epoch_id: int, version: int, rid: bytes, ciphertext: bytes, key_list: bytes) -> bytes:
    return (
        DOMAIN_ADMISSION
        + _u32(epoch_id)
        + _u32(version)
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
