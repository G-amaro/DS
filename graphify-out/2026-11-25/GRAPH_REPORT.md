# Graph Report - DS  (2026-11-25)

## Corpus Check
- Corpus is ~12,833 words - fits in a single context window. You may not need a graph.

## Summary
- 544 nodes · 1265 edges · 25 communities (22 shown, 3 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 110 edges (avg confidence: 0.91)
- Token cost: 160,004 input · 0 output

## Community Hubs (Navigation)
- TSA HTTP Service (FastAPI)
- Trust Services & Dependencies
- Open Design Questions
- Implementation Plan Architecture
- ECIES & X25519 Keys
- TSA Token Issuance
- CA Certificate Issuance
- CSR & CA Tests
- AES-GCM & Admission HMAC
- Report Signing & Key List
- Crypto Core & Integrity
- Directory & Ed25519 Keys
- CA CLI & PKCS12 Export
- CA Root Lifecycle
- CRL Validation
- Epoch Key Chain (HKDF)
- Federation Requirements
- Member Credentials
- Verdict & Domain Separation
- Proof of Possession
- Vault Payload
- Project Statement
- Certificate Fingerprint
- Key List Parsing

## God Nodes (most connected - your core abstractions)
1. `CertificateAuthority` - 32 edges
2. `verify_token()` - 29 edges
3. `Plano de implementação em Python (19 nov 2026)` - 29 edges
4. `CAError` - 23 edges
5. `generate_csr()` - 23 edges
6. `TokenError` - 22 edges
7. `TimestampAuthority` - 20 edges
8. `test_full_report_envelope_flow()` - 19 edges
9. `main()` - 18 edges
10. `TSAError` - 18 edges

## Surprising Connections (you probably didn't know these)
- `Chave de conteúdo K_c por mensagem (AES-256-GCM)` --conceptually_related_to--> `aes_gcm_encrypt()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `Formatos assinados FED-REPORT/CORROB/CRED/POP/DIR/VERDICT-v1` --implements--> `sign_pop()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `Formatos assinados FED-REPORT/CORROB/CRED/POP/DIR/VERDICT-v1` --implements--> `sign_credential()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `Cofre em duas camadas (Arbiter interior, Coordinator exterior)` --conceptually_related_to--> `build_vault_payload()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py
- `rid = SHA-256(report_id)` --implements--> `compute_rid()`  [INFERRED]
  docs/Plano de implementação em Python-2.pdf → src/common/crypto.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Separated trusted services (Coordinator, Arbiter, TSA, CA)** — docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_federation_coordinator, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_federation_arbiter, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_tsa, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_ca_privada, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_separacao_papeis [EXTRACTED 1.00]
- **Write-revocation enforcement at Gateway** — pergunta_k_adm, pergunta_gateway, pergunta_pk_e, pergunta_blacklist_pk_e, pergunta_credenciais_em_lote, pergunta_crl [EXTRACTED 1.00]
- **Kafka topics** — docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_apache_kafka, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_topico_reports, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_topico_corroborations, docs_plataforma_de_partilha_privada_de_incidentes_estado_das_decisões_topico_control [EXTRACTED 1.00]
- **Security Requirements Set** — docs_enunciado_confidentiality, docs_enunciado_anonymity, docs_enunciado_authenticity, docs_enunciado_integrity, docs_enunciado_trusted_timestamping, docs_enunciado_accountability, docs_enunciado_unlinkability [EXTRACTED 1.00]
- **Permitted Central Servers** — docs_enunciado_federation_coordinator, docs_enunciado_pubsub_broker, docs_enunciado_federation_arbiter, docs_enunciado_certification_authority, docs_enunciado_timestamping_authority [EXTRACTED 1.00]
- **Federation components (Member, Coordinator, Gateway, Arbiter, TSA, CA, Kafka)** — docs_plano_de_implementação_em_python_2_member_cli, docs_plano_de_implementação_em_python_2_coordinator, docs_plano_de_implementação_em_python_2_gateway, docs_plano_de_implementação_em_python_2_arbiter, docs_plano_de_implementação_em_python_2_tsa, docs_plano_de_implementação_em_python_2_ca, docs_plano_de_implementação_em_python_2_kafka [EXTRACTED 1.00]
- **Publish report flow (K_c, ECIES, sk_E signature, K_adm HMAC, Gateway, TSA, Kafka)** — docs_plano_de_implementação_em_python_2_content_key_k_c, docs_plano_de_implementação_em_python_2_ecies, docs_plano_de_implementação_em_python_2_epoch_pseudonyms, docs_plano_de_implementação_em_python_2_k_adm_hmac_admission, docs_plano_de_implementação_em_python_2_gateway, docs_plano_de_implementação_em_python_2_tsa, docs_plano_de_implementação_em_python_2_kafka [EXTRACTED 1.00]
- **Dispute de-anonymization (Arbiter, Coordinator, two-layer vault)** — docs_plano_de_implementação_em_python_2_dispute_flow, docs_plano_de_implementação_em_python_2_arbiter, docs_plano_de_implementação_em_python_2_coordinator, docs_plano_de_implementação_em_python_2_two_layer_vault [EXTRACTED 1.00]

## Communities (25 total, 3 thin omitted)

### Community 0 - "TSA HTTP Service (FastAPI)"
Cohesion: 0.06
Nodes (41): app_from_env(), _b64(), create_app(), timestamp(), StampRequest, _signed_message(), TimestampAuthority, TimestampToken (+33 more)

### Community 1 - "Trust Services & Dependencies"
Cohesion: 0.07
Nodes (14): Certification Authority (trusted service), Trusted Timestamping Service (TSA), CRL (blocks login certificate only), _build_parser(), _sign_hash(), app_from_env(), _b64(), create_app() (+6 more)

### Community 2 - "Open Design Questions"
Cohesion: 0.06
Nodes (42): Member blacklist at coordinator (new epoch per revocation), Design notes (diagramas/notas.txt), Pseudonyms inspired by Bitcoin wallets (unlinkability), Is report id public? (open question), TSA different entity from CA?, Automatic corroboration updates after viewing report, PK verification in corroboration is incorrect, Accountability (Arbiter identity opening) (+34 more)

### Community 3 - "Implementation Plan Architecture"
Cohesion: 0.08
Nodes (31): Plano de implementação em Python (19 nov 2026), Arbiter (serviço isolado), Ordem de construção (9 passos), CA privada offline (ca.py), Coordinator (FastAPI, PostgreSQL), Regras de corroboração (mesma época, pk_E distinto, sem repetição), Versão V (diretório de membros + K_adm), Fluxo de disputa (+23 more)

### Community 4 - "ECIES & X25519 Keys"
Cohesion: 0.11
Nodes (20): ecies_decrypt(), ecies_encrypt(), _ecies_key(), ed25519_public_from_pem(), generate_x25519_keypair(), x25519_private_from_pem(), x25519_private_to_pem(), x25519_public_from_pem() (+12 more)

### Community 5 - "TSA Token Issuance"
Cohesion: 0.11
Nodes (6): TimestampAuthority, TimestampToken, TokenError, TSAError, _utcnow(), verify_token()

### Community 6 - "CA Certificate Issuance"
Cohesion: 0.16
Nodes (4): _iso(), _now(), _validate_csr(), verify_certificate()

### Community 7 - "CSR & CA Tests"
Cohesion: 0.15
Nodes (16): CSRError, generate_csr(), serial_to_hex(), _cn(), _ext(), test_cli_end_to_end(), test_csr_key_policy(), test_csr_with_bad_signature_rejected() (+8 more)

### Community 8 - "AES-GCM & Admission HMAC"
Cohesion: 0.14
Nodes (17): aes_gcm_decrypt(), aes_gcm_encrypt(), compute_admission_hmac(), compute_rid(), generate_symmetric_key(), report_aad(), verify_admission_hmac(), test_admission_hmac_boundary_not_ambiguous() (+9 more)

### Community 9 - "Report Signing & Key List"
Cohesion: 0.18
Nodes (10): recipient_key_id(), serialize_key_list(), sign_report(), verify_report(), _envelope(), test_key_list_roundtrip_and_malformed(), test_report_and_corroboration_domains_are_separated(), test_report_roundtrip() (+2 more)

### Community 10 - "Crypto Core & Integrity"
Cohesion: 0.17
Nodes (8): _admission_message(), envelope_digest(), _envelope_message(), _pack_with_length(), sign_corroboration(), _sign_envelope(), verify_corroboration(), _verify_envelope()

### Community 11 - "Directory & Ed25519 Keys"
Cohesion: 0.16
Nodes (10): create_directory_message(), ed25519_private_from_pem(), ed25519_private_to_pem(), generate_ed25519_keypair(), sign_directory(), verify_directory(), test_cross_domain_signature_not_accepted(), test_directory_boundary_not_ambiguous() (+2 more)

### Community 12 - "CA CLI & PKCS12 Export"
Cohesion: 0.16
Nodes (11): CAError, _load_csr(), main(), _passphrase(), _pem(), to_pkcs12(), to_truststore(), test_cli_wrong_passphrase() (+3 more)

### Community 13 - "CA Root Lifecycle"
Cohesion: 0.17
Nodes (8): CertificateAuthority, _write_private(), ca(), test_cannot_issue_after_root_expiry(), test_init_refuses_empty_passphrase_and_overwrite(), test_leaf_validity_capped_by_root(), test_verify_certificate_failures(), ca()

### Community 14 - "CRL Validation"
Cohesion: 0.19
Nodes (11): crl_contains(), crl_number(), CRLError, verify_crl(), test_crl_from_other_ca_rejected(), test_crl_number_increases_and_stale_rejected(), test_crl_signed_by_impostor_with_same_name_rejected(), test_empty_crl_is_valid() (+3 more)

### Community 15 - "Epoch Key Chain (HKDF)"
Cohesion: 0.19
Nodes (10): derive_epoch_batch(), derive_epoch_key(), ed25519_public_to_raw(), _hkdf32(), test_chain_batch_matches_stepwise_and_returns_next_ck(), test_chain_different_seeds_diverge(), test_chain_epochs_have_distinct_keys(), test_chain_input_validation() (+2 more)

### Community 16 - "Federation Requirements"
Cohesion: 0.17
Nodes (8): Anonymous Corroboration, Dispute Resolution, Federation Arbiter, Federation Coordinator, Anonymous Incident Reporting, Member Enrollment and Revocation, Publish/Subscribe Distribution Broker, Incident Report JSON Format

### Community 17 - "Member Credentials"
Cohesion: 0.18
Nodes (6): create_credential_message(), ed25519_public_from_raw(), ed25519_public_to_pem(), sign_credential(), verify_credential(), test_credential_roundtrip_and_failures()

### Community 18 - "Verdict & Domain Separation"
Cohesion: 0.25
Nodes (6): Formatos assinados FED-REPORT/CORROB/CRED/POP/DIR/VERDICT-v1, rid = SHA-256(report_id), create_verdict_message(), sign_verdict(), verify_verdict(), test_verdict_roundtrip_and_failures()

### Community 19 - "Proof of Possession"
Cohesion: 0.32
Nodes (5): create_pop_message(), sign_pop(), verify_pop(), test_derived_key_signs_and_verifies(), test_pop_roundtrip_and_failures()

### Community 20 - "Vault Payload"
Cohesion: 0.33
Nodes (4): build_vault_payload(), parse_vault_payload(), test_vault_payload_roundtrip(), test_vault_payload_truncated_fails()

### Community 21 - "Project Statement"
Cohesion: 0.67
Nodes (3): Project Statement (enunciado), Deliverables (code + 10-page report, Jan 8 2027; discussion Jan 12 2027), Privacy-Preserving Security Incident Sharing Platform

## Ambiguous Edges - Review These
- `Network anonymity layer` → `Gateway (anonymous publish gateway)`  [AMBIGUOUS]
  pergunta.txt · relation: conceptually_related_to

## Knowledge Gaps
- **25 isolated node(s):** `Federation of network operators`, `Member (client)`, `Google CA Service / Certificate Manager Public CA (rejected alternative)`, `Dispute / reporter de-anonymization`, `Server TLS certificates` (+20 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 165 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Plano de implementação em Python (19 nov 2026)` connect `Implementation Plan Architecture` to `Verdict & Domain Separation`, `ECIES & X25519 Keys`?**
  _High betweenness centrality (0.074) - this node is a cross-community bridge._
- **Are the 14 inferred relationships involving `CertificateAuthority` (e.g. with `ca()` and `test_cannot_issue_after_root_expiry()`) actually correct?**
  _`CertificateAuthority` has 14 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Federation of network operators`, `Member (client)`, `Google CA Service / Certificate Manager Public CA (rejected alternative)` to the rest of the system?**
  _25 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `TSA HTTP Service (FastAPI)` be split into smaller, more focused modules?**
  _Cohesion score 0.05546218487394958 - nodes in this community are weakly interconnected._
- **Why does `Private federation CA` connect `Open Design Questions` to `Trust Services & Dependencies`?**
  _High betweenness centrality (0.073) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `CAError` (e.g. with `test_cannot_issue_after_root_expiry()` and `test_init_refuses_empty_passphrase_and_overwrite()`) actually correct?**
  _`CAError` has 8 INFERRED edges - model-reasoned connections that need verification._

### Low-confidence Hints
_AMBIGUOUS edges — the extractor was unsure. Verify before acting on these._

- **What is the exact relationship between `Network anonymity layer` and `Gateway (anonymous publish gateway)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._