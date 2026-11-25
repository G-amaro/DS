# Graph Report - DS  (2026-11-25)

## Corpus Check
- 13 files · ~18,196 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 16 file(s) not represented in the graph (top: .mermaid 9, (none) 6, .ini 1)

## Summary
- 614 nodes · 1474 edges · 29 communities (23 shown, 6 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 126 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `b5d0d25a`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- TSA HTTP Service (FastAPI)
- ca.py
- Open Design Questions
- Implementation Plan Architecture
- test_crypto.py
- TSA Token Issuance
- test_ca.py
- 8. Estado do código
- test_full_report_envelope_flow
- crypto.py
- sign_directory
- CLAUDE.md
- open_vault_inner
- service.py
- Epoch Key Chain (HKDF)
- Federation Requirements
- generate_ed25519_keypair
- TimestampToken
- sign_pop
- Vault Payload
- Project Statement
- tsa/service.py
- X25519PublicKey
- _sign_hash
- struct
- _build_parser

## God Nodes (most connected - your core abstractions)
1. `CertificateAuthority` - 32 edges
2. `verify_token()` - 29 edges
3. `Plano de implementação em Python (19 nov 2026)` - 29 edges
4. `CAError` - 23 edges
5. `generate_csr()` - 23 edges
6. `TokenError` - 22 edges
7. `generate_x25519_keypair()` - 21 edges
8. `TimestampAuthority` - 20 edges
9. `generate_ed25519_keypair()` - 19 edges
10. `ecies_decrypt()` - 19 edges

## Surprising Connections (you probably didn't know these)
- `Chave de conteúdo K_c por mensagem (AES-256-GCM)` --conceptually_related_to--> `aes_gcm_encrypt()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `ECIES (X25519 efémero, HKDF-SHA256, AES-GCM)` --implements--> `ecies_encrypt()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `ECIES (X25519 efémero, HKDF-SHA256, AES-GCM)` --implements--> `ecies_decrypt()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `Formatos assinados FED-REPORT/CORROB/CRED/POP/DIR/VERDICT-v1` --implements--> `sign_pop()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `Formatos assinados FED-REPORT/CORROB/CRED/POP/DIR/VERDICT-v1` --implements--> `sign_credential()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Dispute de-anonymization (Arbiter, Coordinator, two-layer vault)** — docs_plano_de_implementação_em_python_2_dispute_flow, docs_plano_de_implementação_em_python_2_arbiter, docs_plano_de_implementação_em_python_2_coordinator, docs_plano_de_implementação_em_python_2_two_layer_vault [EXTRACTED 1.00]
- **Permitted Central Servers** — docs_enunciado_federation_coordinator, docs_enunciado_pubsub_broker, docs_enunciado_federation_arbiter, docs_enunciado_certification_authority, docs_enunciado_timestamping_authority [EXTRACTED 1.00]
- **Security Requirements Set** — docs_enunciado_confidentiality, docs_enunciado_anonymity, docs_enunciado_authenticity, docs_enunciado_integrity, docs_enunciado_trusted_timestamping, docs_enunciado_accountability, docs_enunciado_unlinkability [EXTRACTED 1.00]
- **Federation components (Member, Coordinator, Gateway, Arbiter, TSA, CA, Kafka)** — docs_plano_de_implementação_em_python_2_member_cli, docs_plano_de_implementação_em_python_2_coordinator, docs_plano_de_implementação_em_python_2_gateway, docs_plano_de_implementação_em_python_2_arbiter, docs_plano_de_implementação_em_python_2_tsa, docs_plano_de_implementação_em_python_2_ca, docs_plano_de_implementação_em_python_2_kafka [EXTRACTED 1.00]
- **Kafka topics** — docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_apache_kafka, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_topico_reports, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_topico_corroborations, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_topico_control [EXTRACTED 1.00]
- **Publish report flow (K_c, ECIES, sk_E signature, K_adm HMAC, Gateway, TSA, Kafka)** — docs_plano_de_implementação_em_python_2_content_key_k_c, docs_plano_de_implementação_em_python_2_ecies, docs_plano_de_implementação_em_python_2_epoch_pseudonyms, docs_plano_de_implementação_em_python_2_k_adm_hmac_admission, docs_plano_de_implementação_em_python_2_gateway, docs_plano_de_implementação_em_python_2_tsa, docs_plano_de_implementação_em_python_2_kafka [EXTRACTED 1.00]
- **Write-revocation enforcement at Gateway** — pergunta_k_adm, pergunta_gateway, pergunta_pk_e, pergunta_blacklist_pk_e, pergunta_credenciais_em_lote, pergunta_crl [EXTRACTED 1.00]
- **Separated trusted services (Coordinator, Arbiter, TSA, CA)** — docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_federation_coordinator, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_federation_arbiter, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_tsa, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_ca_privada, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_separacao_papeis [EXTRACTED 1.00]

## Communities (29 total, 6 thin omitted)

### Community 0 - "TSA HTTP Service (FastAPI)"
Cohesion: 0.06
Nodes (36): _signed_message(), TimestampAuthority, TimestampToken, TokenError, TSAError, _utcnow(), verify_token(), Clock (+28 more)

### Community 1 - "ca.py"
Cohesion: 0.14
Nodes (4): Trusted Timestamping Service (TSA), CRL (blocks login certificate only), _write_private(), test_concurrent_stamps_have_unique_serials()

### Community 2 - "Open Design Questions"
Cohesion: 0.06
Nodes (42): Member blacklist at coordinator (new epoch per revocation), Design notes (diagramas/notas.txt), Pseudonyms inspired by Bitcoin wallets (unlinkability), Is report id public? (open question), TSA different entity from CA?, Automatic corroboration updates after viewing report, PK verification in corroboration is incorrect, Accountability (Arbiter identity opening) (+34 more)

### Community 3 - "Implementation Plan Architecture"
Cohesion: 0.07
Nodes (33): Plano de implementação em Python (19 nov 2026), Arbiter (serviço isolado), Ordem de construção (9 passos), CA privada offline (ca.py), Coordinator (FastAPI, PostgreSQL), Regras de corroboração (mesma época, pk_E distinto, sem repetição), Versão V (diretório de membros + K_adm), Fluxo de disputa (+25 more)

### Community 4 - "test_crypto.py"
Cohesion: 0.15
Nodes (16): _check_ecies_context(), ecies_decrypt(), ecies_encrypt(), _ecies_key(), generate_x25519_keypair(), unwrap_k_adm(), _enc(), test_ecies_is_randomized() (+8 more)

### Community 5 - "TSA Token Issuance"
Cohesion: 0.15
Nodes (4): TimestampAuthority, TSAError, _utcnow(), verify_token()

### Community 6 - "test_ca.py"
Cohesion: 0.05
Nodes (50): CAError, CertificateAuthority, crl_contains(), crl_number(), CRLError, CSRError, fingerprint(), generate_csr() (+42 more)

### Community 7 - "8. Estado do código"
Cohesion: 0.18
Nodes (11): 8. Estado do código, current_epoch(), epoch_bounds(), epoch_id_for(), report_aad(), unwrap_content_key(), wrap_content_key(), test_content_key_bound_to_context() (+3 more)

### Community 8 - "test_full_report_envelope_flow"
Cohesion: 0.07
Nodes (35): aes_gcm_decrypt(), aes_gcm_encrypt(), build_key_list(), compute_admission_hmac(), compute_rid(), generate_symmetric_key(), parse_key_list(), recipient_key_id() (+27 more)

### Community 10 - "crypto.py"
Cohesion: 0.14
Nodes (11): _admission_message(), create_credential_message(), create_directory_message(), create_pop_message(), envelope_digest(), _envelope_message(), _pack_with_length(), seal_vault() (+3 more)

### Community 11 - "sign_directory"
Cohesion: 0.16
Nodes (9): create_verdict_message(), sign_directory(), sign_verdict(), verify_directory(), verify_verdict(), test_cross_domain_signature_not_accepted(), test_directory_boundary_not_ambiguous(), test_directory_roundtrip_and_failures() (+1 more)

### Community 12 - "CLAUDE.md"
Cohesion: 0.13
Nodes (14): 10. Notas do professor e como foram tratadas, 11. Limitações a declarar no relatório, 12. Decisões em aberto, 13. Como trabalhar neste repositório, 1. Objetivo e prazos, 2. O que o enunciado fixa, 3. Arquitetura decidida, 4. Parâmetros (+6 more)

### Community 13 - "open_vault_inner"
Cohesion: 0.26
Nodes (10): ed25519_public_to_raw(), open_vault_inner(), open_vault_outer(), test_arbiter_alone_cannot_open_vault(), test_chain_is_deterministic(), test_coordinator_alone_cannot_read_vault(), test_two_layer_vault_roundtrip(), test_vault_inner_bound_to_pk_E_and_epoch() (+2 more)

### Community 14 - "service.py"
Cohesion: 0.24
Nodes (5): app_from_env(), _b64(), create_app(), timestamp(), StampRequest

### Community 15 - "Epoch Key Chain (HKDF)"
Cohesion: 0.24
Nodes (8): derive_epoch_batch(), derive_epoch_key(), _hkdf32(), test_chain_batch_matches_stepwise_and_returns_next_ck(), test_chain_different_seeds_diverge(), test_chain_epochs_have_distinct_keys(), test_chain_input_validation(), test_chain_key_and_next_are_independent()

### Community 16 - "Federation Requirements"
Cohesion: 0.17
Nodes (8): Anonymous Corroboration, Dispute Resolution, Federation Arbiter, Federation Coordinator, Anonymous Incident Reporting, Member Enrollment and Revocation, Publish/Subscribe Distribution Broker, Incident Report JSON Format

### Community 17 - "generate_ed25519_keypair"
Cohesion: 0.09
Nodes (19): ed25519_private_from_pem(), ed25519_private_to_pem(), ed25519_public_from_pem(), ed25519_public_from_raw(), ed25519_public_to_pem(), _encryption_for(), generate_ed25519_keypair(), _password_bytes() (+11 more)

### Community 19 - "sign_pop"
Cohesion: 0.40
Nodes (4): sign_pop(), verify_pop(), test_derived_key_signs_and_verifies(), test_pop_roundtrip_and_failures()

### Community 20 - "Vault Payload"
Cohesion: 0.33
Nodes (4): build_vault_payload(), parse_vault_payload(), test_vault_payload_roundtrip(), test_vault_payload_truncated_fails()

### Community 21 - "Project Statement"
Cohesion: 0.67
Nodes (3): Project Statement (enunciado), Deliverables (code + 10-page report, Jan 8 2027; discussion Jan 12 2027), Privacy-Preserving Security Incident Sharing Platform

### Community 22 - "tsa/service.py"
Cohesion: 0.25
Nodes (5): app_from_env(), _b64(), create_app(), timestamp(), StampRequest

### Community 23 - "X25519PublicKey"
Cohesion: 0.29
Nodes (3): wrap_k_adm(), x25519_public_from_pem(), x25519_public_from_raw()

### Community 26 - "struct"
Cohesion: 0.50
Nodes (3): _lp(), _lp(), _signed_message()

## Ambiguous Edges - Review These
- `Network anonymity layer` → `Gateway (anonymous publish gateway)`  [AMBIGUOUS]
  pergunta.txt · relation: conceptually_related_to

## Knowledge Gaps
- **25 isolated node(s):** `CRL (blocks login certificate only)`, `Federation Arbiter`, `Federation Coordinator`, `Publish/Subscribe Distribution Broker`, `Incident Report JSON Format` (+20 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 198 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Plano de implementação em Python (19 nov 2026)` connect `Implementation Plan Architecture` to `Epoch Key Chain (HKDF)`?**
  _High betweenness centrality (0.067) - this node is a cross-community bridge._
- **Are the 14 inferred relationships involving `CertificateAuthority` (e.g. with `ca()` and `test_cannot_issue_after_root_expiry()`) actually correct?**
  _`CertificateAuthority` has 14 INFERRED edges - model-reasoned connections that need verification._
- **What connects `CRL (blocks login certificate only)`, `Federation Arbiter`, `Federation Coordinator` to the rest of the system?**
  _25 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `TSA HTTP Service (FastAPI)` be split into smaller, more focused modules?**
  _Cohesion score 0.06486486486486487 - nodes in this community are weakly interconnected._
- **Why does `Python `cryptography` library` connect `Open Design Questions` to `crypto.py`?**
  _High betweenness centrality (0.066) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `CAError` (e.g. with `test_cannot_issue_after_root_expiry()` and `test_init_refuses_empty_passphrase_and_overwrite()`) actually correct?**
  _`CAError` has 8 INFERRED edges - model-reasoned connections that need verification._

### Low-confidence Hints
_AMBIGUOUS edges — the extractor was unsure. Verify before acting on these._

- **What is the exact relationship between `Network anonymity layer` and `Gateway (anonymous publish gateway)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._