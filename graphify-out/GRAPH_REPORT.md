# Graph Report - DS  (2026-11-26)

## Corpus Check
- 10 files · ~14,706 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 16 file(s) not represented in the graph (top: .mermaid 9, (none) 6, .ini 1)

## Summary
- 620 nodes · 1478 edges · 50 communities (30 shown, 20 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 109 edges (avg confidence: 0.91)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `817b432e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_tsa.py
- ca.py
- Open Design Questions
- Implementation Plan Architecture
- pytest
- verify_token
- test_ca.py
- 8. Estado do código
- test_full_report_envelope_flow
- sign_report
- _pack_with_length
- Ed25519PrivateKey
- CLAUDE.md
- test_crypto.py
- Epoch Key Chain (HKDF)
- Federation Requirements
- test_pem_roundtrips_with_and_without_passphrase
- tsa.py
- generate_ed25519_keypair
- seal_vault
- Project Statement
- TSAError
- crypto.py
- ._issue
- CertificateAuthority
- verify_crl
- create_request
- build_key_list
- hybrid_encrypt
- compute_rid
- fingerprint

## God Nodes (most connected - your core abstractions)
1. `CertificateAuthority` - 29 edges
2. `Plano de implementação em Python (19 nov 2026)` - 29 edges
3. `verify_token()` - 24 edges
4. `_rsa()` - 23 edges
5. `CAError` - 23 edges
6. `generate_csr()` - 22 edges
7. `generate_ed25519_keypair()` - 21 edges
8. `TSAError` - 21 edges
9. `parse_token()` - 19 edges
10. `test_full_report_envelope_flow()` - 18 edges

## Surprising Connections (you probably didn't know these)
- `Chave de conteúdo K_c por mensagem (AES-256-GCM)` --conceptually_related_to--> `aes_gcm_encrypt()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `Cofre em duas camadas (Arbiter interior, Coordinator exterior)` --conceptually_related_to--> `build_vault_payload()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `8. Estado do código` --references--> `seal_vault()`  [INFERRED]
  CLAUDE.md → src/common/crypto.py
- `8. Estado do código` --references--> `open_vault_outer()`  [INFERRED]
  CLAUDE.md → src/common/crypto.py
- `8. Estado do código` --references--> `open_vault_inner()`  [INFERRED]
  CLAUDE.md → src/common/crypto.py

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

## Communities (50 total, 20 thin omitted)

### Community 0 - "test_tsa.py"
Cohesion: 0.12
Nodes (22): TokenError, ca(), _make_tsa(), _stamp(), test_bad_signature_rejected(), test_concurrent_stamps_have_unique_serials(), work(), test_corrupt_serial_fails_closed() (+14 more)

### Community 1 - "ca.py"
Cohesion: 0.08
Nodes (13): Certification Authority (trusted service), CRL (blocks login certificate only), _build_parser(), _load_csr(), main(), _passphrase(), _pem(), _sign_hash() (+5 more)

### Community 2 - "Open Design Questions"
Cohesion: 0.06
Nodes (42): Member blacklist at coordinator (new epoch per revocation), Design notes (diagramas/notas.txt), Pseudonyms inspired by Bitcoin wallets (unlinkability), Is report id public? (open question), TSA different entity from CA?, Automatic corroboration updates after viewing report, PK verification in corroboration is incorrect, Accountability (Arbiter identity opening) (+34 more)

### Community 3 - "Implementation Plan Architecture"
Cohesion: 0.08
Nodes (31): Plano de implementação em Python (19 nov 2026), Arbiter (serviço isolado), Ordem de construção (9 passos), CA privada offline (ca.py), Coordinator (FastAPI, PostgreSQL), Regras de corroboração (mesma época, pk_E distinto, sem repetição), Versão V (diretório de membros + K_adm), Fluxo de disputa (+23 more)

### Community 4 - "pytest"
Cohesion: 0.17
Nodes (17): generate_rsa_keypair(), _oaep(), rsa_oaep_decrypt(), rsa_oaep_encrypt(), unwrap_content_key(), unwrap_k_adm(), _rsa(), test_content_key_bound_to_rid() (+9 more)

### Community 5 - "verify_token"
Cohesion: 0.20
Nodes (4): TimestampToken, _utcnow(), verify_token(), test_stamp_and_verify()

### Community 6 - "test_ca.py"
Cohesion: 0.13
Nodes (15): CSRError, generate_csr(), verify_certificate(), _cn(), _ext(), test_csr_key_policy(), test_csr_with_bad_signature_rejected(), test_init_creates_valid_root() (+7 more)

### Community 7 - "8. Estado do código"
Cohesion: 0.36
Nodes (6): 8. Estado do código, current_epoch(), epoch_bounds(), epoch_id_for(), test_epoch_boundaries_at_00_and_12_utc(), test_epoch_respects_timezone_and_rejects_naive()

### Community 8 - "test_full_report_envelope_flow"
Cohesion: 0.21
Nodes (13): aes_gcm_decrypt(), aes_gcm_encrypt(), generate_symmetric_key(), unwrap_from_key_list(), _der(), test_aes_gcm_nonce_is_random(), test_aes_gcm_requires_associated_data(), test_aes_gcm_roundtrip() (+5 more)

### Community 9 - "sign_report"
Cohesion: 0.24
Nodes (9): sign_report(), verify_corroboration(), _verify_envelope(), verify_report(), _envelope(), test_report_and_corroboration_domains_are_separated(), test_report_roundtrip(), test_report_signature_binds_every_field() (+1 more)

### Community 10 - "_pack_with_length"
Cohesion: 0.16
Nodes (11): _admission_message(), create_credential_message(), create_directory_message(), create_pop_message(), envelope_digest(), _envelope_message(), _pack_with_length(), report_aad() (+3 more)

### Community 11 - "Ed25519PrivateKey"
Cohesion: 0.13
Nodes (11): Formatos assinados FED-REPORT/CORROB/CRED/POP/DIR/VERDICT-v1, rid = SHA-256(report_id), create_verdict_message(), sign_corroboration(), sign_credential(), sign_directory(), _sign_envelope(), sign_pop() (+3 more)

### Community 12 - "CLAUDE.md"
Cohesion: 0.13
Nodes (14): 10. Notas do professor e como foram tratadas, 11. Limitações a declarar no relatório, 12. Decisões em aberto, 13. Como trabalhar neste repositório, 1. Objetivo e prazos, 2. O que o enunciado fixa, 3. Arquitetura decidida, 4. Parâmetros (+6 more)

### Community 13 - "test_crypto.py"
Cohesion: 0.13
Nodes (15): ed25519_public_to_raw(), open_vault_inner(), open_vault_outer(), parse_vault_payload(), test_arbiter_alone_cannot_open_vault(), test_chain_epochs_have_distinct_keys(), test_chain_input_validation(), test_chain_is_deterministic() (+7 more)

### Community 15 - "Epoch Key Chain (HKDF)"
Cohesion: 0.20
Nodes (8): derive_epoch_batch(), derive_epoch_key(), _hkdf32(), verify_pop(), test_chain_batch_matches_stepwise_and_returns_next_ck(), test_chain_different_seeds_diverge(), test_chain_key_and_next_are_independent(), test_derived_key_signs_and_verifies()

### Community 16 - "Federation Requirements"
Cohesion: 0.17
Nodes (8): Anonymous Corroboration, Dispute Resolution, Federation Arbiter, Federation Coordinator, Anonymous Incident Reporting, Member Enrollment and Revocation, Publish/Subscribe Distribution Broker, Incident Report JSON Format

### Community 17 - "test_pem_roundtrips_with_and_without_passphrase"
Cohesion: 0.17
Nodes (11): ed25519_private_from_pem(), ed25519_private_to_pem(), ed25519_public_from_pem(), _encryption_for(), _password_bytes(), rsa_private_from_pem(), rsa_private_to_pem(), test_empty_passphrase_rejected() (+3 more)

### Community 18 - "tsa.py"
Cohesion: 0.15
Nodes (14): Trusted Timestamping Service (TSA), _children(), _DERError, _expect(), _generalized_time(), _oid_to_str(), parse_request(), parse_token() (+6 more)

### Community 19 - "generate_ed25519_keypair"
Cohesion: 0.15
Nodes (11): ed25519_public_to_pem(), generate_ed25519_keypair(), verify_credential(), verify_directory(), test_build_key_list_rejects_non_rsa_keys(), test_credential_roundtrip_and_failures(), test_cross_domain_signature_not_accepted(), test_directory_boundary_not_ambiguous() (+3 more)

### Community 20 - "seal_vault"
Cohesion: 0.33
Nodes (3): build_vault_payload(), seal_vault(), _vault_outer_aad()

### Community 21 - "Project Statement"
Cohesion: 0.67
Nodes (3): Project Statement (enunciado), Deliverables (code + 10-page report, Jan 8 2027; discussion Jan 12 2027), Privacy-Preserving Security Incident Sharing Platform

### Community 22 - "TSAError"
Cohesion: 0.12
Nodes (11): app_from_env(), create_app(), _config_text(), load_from_env(), openssl_available(), _run_openssl(), TimestampAuthority, TSAError (+3 more)

### Community 23 - "crypto.py"
Cohesion: 0.12
Nodes (8): _check_rsa_key(), ed25519_public_from_raw(), _kadm_label(), rsa_public_from_der(), rsa_public_from_pem(), rsa_public_to_der(), rsa_public_to_pem(), wrap_k_adm()

### Community 25 - "._issue"
Cohesion: 0.17
Nodes (3): _iso(), _now(), _validate_csr()

### Community 26 - "CertificateAuthority"
Cohesion: 0.16
Nodes (12): CAError, CertificateAuthority, serial_to_hex(), ca(), test_cannot_issue_after_root_expiry(), test_cli_end_to_end(), test_init_refuses_empty_passphrase_and_overwrite(), test_leaf_validity_capped_by_root() (+4 more)

### Community 27 - "verify_crl"
Cohesion: 0.20
Nodes (10): crl_contains(), crl_number(), CRLError, verify_crl(), test_crl_from_other_ca_rejected(), test_crl_number_increases_and_stale_rejected(), test_crl_signed_by_impostor_with_same_name_rejected(), test_empty_crl_is_valid() (+2 more)

### Community 29 - "create_request"
Cohesion: 0.19
Nodes (10): create_request(), _der_uint(), _tlv(), test_non_sha256_request_rejected(), test_openssl_cli_accepts_reply(), test_rejection_response_raises(), test_request_is_valid_rfc3161_for_openssl(), test_request_nonce_is_random() (+2 more)

### Community 30 - "build_key_list"
Cohesion: 0.15
Nodes (7): build_key_list(), _kc_label(), parse_key_list(), recipient_key_id(), serialize_key_list(), wrap_content_key(), test_key_list_roundtrip_and_malformed()

### Community 31 - "hybrid_encrypt"
Cohesion: 0.27
Nodes (7): hybrid_decrypt(), hybrid_encrypt(), test_hybrid_bound_to_label_and_associated_data(), test_hybrid_requires_label_and_associated_data(), test_hybrid_roundtrip_large_payload(), test_hybrid_tampered_and_truncated_fail(), test_vault_inner_rejects_mismatched_content()

### Community 32 - "compute_rid"
Cohesion: 0.31
Nodes (6): compute_admission_hmac(), compute_rid(), verify_admission_hmac(), test_admission_hmac_boundary_not_ambiguous(), test_admission_hmac_roundtrip_and_failures(), test_rid_is_deterministic_and_32_bytes()

## Ambiguous Edges - Review These
- `Network anonymity layer` → `Gateway (anonymous publish gateway)`  [AMBIGUOUS]
  pergunta.txt · relation: conceptually_related_to

## Knowledge Gaps
- **25 isolated node(s):** `CRL (blocks login certificate only)`, `Federation Arbiter`, `Federation Coordinator`, `Publish/Subscribe Distribution Broker`, `Incident Report JSON Format` (+20 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 217 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **20 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Python `cryptography` library` connect `Open Design Questions` to `crypto.py`?**
  _High betweenness centrality (0.068) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `CertificateAuthority` (e.g. with `ca()` and `test_cannot_issue_after_root_expiry()`) actually correct?**
  _`CertificateAuthority` has 11 INFERRED edges - model-reasoned connections that need verification._
- **What connects `CRL (blocks login certificate only)`, `Federation Arbiter`, `Federation Coordinator` to the rest of the system?**
  _25 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `test_tsa.py` be split into smaller, more focused modules?**
  _Cohesion score 0.12121212121212122 - nodes in this community are weakly interconnected._
- **Why does `Plano de implementação em Python (19 nov 2026)` connect `Implementation Plan Architecture` to `Ed25519PrivateKey`?**
  _High betweenness centrality (0.068) - this node is a cross-community bridge._
- **Should `ca.py` be split into smaller, more focused modules?**
  _Cohesion score 0.0773109243697479 - nodes in this community are weakly interconnected._

### Low-confidence Hints
_AMBIGUOUS edges — the extractor was unsure. Verify before acting on these._

- **What is the exact relationship between `Network anonymity layer` and `Gateway (anonymous publish gateway)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._