# Plataforma de partilha privada de incidentes: estado das decisões

Documento de trabalho, 22 de outubro de 2026. Reúne o que o enunciado fixa, o que já ficou decidido e o que continua em aberto.

## 1. Contexto e prazos

O projeto consiste em desenhar e desenvolver uma plataforma que preserva a privacidade para partilha de relatórios de incidentes de segurança (DDoS, scanning, botnet C2, prefix hijacking) entre uma federação de operadores de rede, usando criptografia aplicada. A plataforma tem de proteger também os operadores que reportam de exposição reputacional.

| Item | Detalhe |
| --- | --- |
| Entrega (código documentado e relatório até 10 páginas) | 8 de janeiro de 2027, via Blackboard |
| Atraso | Penalização de 10% por dia |
| Discussão | 12 de janeiro de 2027, 20 minutos, presença obrigatória de todos os elementos (a falta implica "Não Admitido") |
| Regra de ouro | Para cada requisito, justificar a escolha e comparar com pelo menos uma alternativa |

## 2. O que o enunciado fixa

**Funcionalidades**

- Inscrição e revogação geridas pelo Federation Coordinator. Após a revogação, o membro deixa de publicar, corroborar e ler novos relatórios.
- Reporte anónimo que chega a todos os membros ativos.
- Corroboração anónima, no máximo uma vez por membro por relatório e nunca do próprio relatório. A contagem é pública e serve de indicador de confiança.
- Disputa aberta por qualquer membro. Só o Federation Arbiter revela o reporter, que não pode repudiar a autoria. Os corroboradores continuam protegidos.

**Formato dos dados**

- Relatório em JSON com `report_id` (UUID aleatório do reporter), `incident_type`, `indicators`, `observation_period`, `severity` e `recommended_mitigation`, com os valores permitidos definidos no enunciado.
- Timestamps em ISO 8601 UTC.
- É permitido acrescentar campos à volta do objeto (assinaturas, tokens, pseudónimos), mas não alterar os campos de conteúdo.

**Requisitos de segurança:** confidencialidade, anonimato, autenticidade, integridade, timestamping de confiança, accountability e unlinkability (esta última flexível, com nível a definir e justificar).

**Modelo de ameaça**

- Servidores honest-but-curious.
- Membros potencialmente maliciosos (forjar relatórios, impersonar, corroborar mais do que uma vez).
- Comunicações cliente-servidor com confidencialidade e integridade.
- Discussão obrigatória dos metadados de rede (IP de origem).

**Restrições de arquitetura:** distribuição a todos os membros ativos e recuperação do histórico por membros que estiveram offline.

## 3. Decisões tomadas

| Decisão | Escolha | Justificação resumida |
| --- | --- | --- |
| Distribuição | Apache Kafka (sugerido pelo professor) | Log persistente com offsets, o que permite recuperação de membros offline, e ordem total dentro de uma partição |
| Entidades | Membros, Kafka, Coordinator, Arbiter, TSA, mais uma CA | Cobrem todos os serviços centrais que o enunciado permite |
| Biblioteca criptográfica | `cryptography` (Python) | Escolha do grupo; cobre chaves, certificados X.509, assinaturas, cifra autenticada e derivação de chaves |
| CA | CA privada própria feita com `cryptography`, em vez de CAs da Google | Ver secção 5 |

## 4. Arquitetura

A arquitetura tem três camadas. Os membros (clientes) ligam-se a uma camada de anonimato de rede e, através dela, ao Kafka. Os serviços de confiança (Coordinator, Arbiter, TSA) são acedidos diretamente por TLS, fora do Kafka.

| Entidade | Função | O que vê |
| --- | --- | --- |
| Membro (cliente) | Gera o relatório, assina anonimamente, cifra com a chave de grupo, publica, consome, decifra e verifica | O conteúdo, por ser membro ativo |
| Camada de anonimato | Esconde o IP de origem de quem publica | O IP, mas não o conteúdo cifrado |
| Kafka | Guarda e distribui mensagens a todos, incluindo quem esteve offline | Só dados cifrados e o momento de chegada |
| Coordinator | Inscreve membros, emite credenciais, revoga, distribui novas chaves de grupo | Quem é membro, mas não quem escreveu o quê |
| Arbiter | Abre a identidade do reporter numa disputa | Só o que lhe é submetido numa disputa |
| TSA | Emite timestamps | O hash do relatório, sem conteúdo nem identidade |

**Tópicos do Kafka**

- `reports`: relatórios cifrados, com assinatura anónima e token de timestamp.
- `corroborations`: corroborações cifradas, com assinatura anónima, tag dependente do `report_id` e timestamp.
- `control`: novas chaves de grupo (cifradas só para membros ativos) e atualizações de revogação.

**Princípio de segurança do Kafka:** o broker é tratado como honest-but-curious e só vê dados já cifrados. A validação de autenticidade, integridade, revogação e dupla corroboração é feita pelos clientes, com base na criptografia das próprias mensagens. Os membros não se autenticam no Kafka com a sua identidade, porque isso ligaria cada mensagem ao seu autor.

## 5. CA e confiança

Há três tipos de certificado em jogo:

1. **Certificados de servidor** (Kafka, Coordinator, Arbiter, TSA), usados no TLS e assinados pela CA da federação.
2. **Certificado da TSA**, com a extensão de uso `timeStamping`, também assinado pela CA.
3. **Credencial de membro**, emitida pelo Coordinator. Não é um certificado X.509 com identidade, é uma credencial anónima ou chave de grupo.

**Forma da CA.** Uma CA privada implementada como módulo ou CLI offline com `cryptography` (por exemplo `ca.py`). Gera a raiz autoassinada, assina os CSRs dos serviços e distribui o certificado raiz aos membros como trust anchor. A chave da CA não participa no funcionamento normal do sistema.

**Separação de papéis**

- O Arbiter não é o Coordinator nem a CA. Se uma só entidade conseguisse inscrever, revogar e desanonimizar, o conluio deixava de ter barreira.
- A TSA não é a CA nem um membro, para que o valor do timestamp venha da independência face a quem reporta.

**Porque não as CAs da Google**

- O Certificate Authority Service é pago, com taxa mensal por CA e um custo por certificado emitido, e exige conta de faturação.
- A Public CA do Certificate Manager tem certificados gratuitos, mas exige conta de faturação, só valida domínios que controlas (não serve para `localhost` nem Docker) e não emite certificados de TSA nem credenciais de membro.
- Colocaria uma empresa externa como raiz de confiança de uma federação fechada.

As duas serão apresentadas no relatório como alternativas comparadas.

**Limitações da biblioteca `cryptography`**

- Não gera tokens RFC 3161 nem implementa assinaturas de grupo, assinaturas de anel ou credenciais anónimas.
- Para os timestamps, as opções são usar OpenSSL (`openssl ts`) ou uma TSA simplificada que assina o hash do relatório mais a hora, declarando a simplificação no relatório.
- Para o anonimato, o mecanismo terá de ser construído sobre primitivas ou com uma biblioteca adicional.

## 6. Requisitos de segurança: ponto de situação

| Requisito | Mecanismo possível | Estado |
| --- | --- | --- |
| Confidencialidade | Chave de grupo simétrica por época, com rekeying a cada revogação | A decidir (alternativas: cifra por membro, broadcast encryption) |
| Anonimato | A definir; condiciona Coordinator e Arbiter | A decidir |
| Autenticidade | Assinatura anónima verificável pelos clientes | Depende do mecanismo de anonimato |
| Integridade | Assinatura sobre o relatório e cifra autenticada (AES-GCM) | Direção provável |
| Timestamping | TSA própria (RFC 3161 completo ou simplificado) | Entidade decidida, formato a decidir |
| Accountability | Abertura de identidade pelo Arbiter | Depende do mecanismo de anonimato |
| Unlinkability | Nível a definir | A decidir |
| Anti-dupla corroboração | Tag dependente do `report_id` | A decidir |
| Metadados de rede | Tor ou relay de publicação, com possível batching e atrasos aleatórios | A decidir |

## 7. Decisões em aberto

Por ordem de dependência:

1. **Nível de unlinkability** (nenhum, por relatório, por período ou total). Condiciona quase tudo o resto.
2. **Mecanismo de autenticação anónima** (assinaturas de grupo, assinaturas cegas, credenciais anónimas ou pseudónimos rotativos), tendo em conta que terá de ser implementado sobre `cryptography`.
3. **Onde fica a identidade do reporter** e o que o Arbiter e o Coordinator sabem, incluindo se o conluio entre ambos é tratado.
4. **Confidencialidade e revogação**: quem gera e distribui as chaves de época (a proposta atual é o Coordinator, pelo tópico `control`).
5. **Anti-dupla corroboração e proibição de auto-corroboração** sem quebrar o anonimato.
6. **Formato do timestamp** e como estabelecer quem reportou primeiro.
7. **Anonimato de rede**: Tor, relay próprio ou ambos, e como se integra com o Kafka.
8. **Escala assumida** (número de membros e frequência de relatórios).

## 8. Assunções a declarar no relatório

- Corroborar um relatório não prova criptograficamente que o membro observou o incidente. O sistema só garante a regra de uma corroboração por membro e por relatório.
- O que acontece aos relatórios e corroborações anteriores à revogação de um membro (mantêm-se válidos ou não).
- Quem pode abrir uma disputa, que prova é necessária e o que acontece depois (por exemplo, retirada do relatório de uma blocklist).
- Que informação sobre os outros relatórios do mesmo autor fica exposta quando o Arbiter abre um deles.
- O que o Coordinator, o Arbiter e a CA podem aprender e em que condições.
- A TSA e a CA são serviços de confiança que o enunciado permite assumir. Declarar quem os opera.

## 9. Estrutura prevista para o relatório final (10 páginas)

1. Assunções e modelo de ameaça.
2. Arquitetura e entidades.
3. Uma tabela requisito, mecanismo, alternativa e justificação.
4. Secção dedicada à unlinkability: nível adotado, custos e riscos residuais.
5. Metadados de rede.
6. Limitações conhecidas.

## 10. Próximo passo

Fechar o nível de unlinkability e o mecanismo de autenticação anónima, porque definem o que o Coordinator e o Arbiter sabem e como funciona a corroboração. A partir daí as restantes decisões ficam muito mais restritas.
