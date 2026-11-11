# 🛡️ AppSec Protection & Monitoring Service

Serviço autônomo de **Monitoramento e Proteção de Segurança de Aplicações (AppSec)** em tempo real. Este microserviço intercepta, audita e analisa o tráfego de requisições e respostas HTTP de APIs para identificar ataques (OWASP Top 10), mitigar exfiltração de dados sensíveis (PII) e detectar abusos comportamentais por meio de Machine Learning (Isolation Forest) integrado com heurísticas de segurança.

---

## 🎯 OBJETIVOS E CAPACIDADES DO SERVIÇO
1. **WAF Core Light (OWASP Top 10):** Inspeção rigorosa de cabeçalhos, parâmetros de busca (query string) e corpo de requisições (clonando os buffers de leitura com segurança) contra injeções SQL (SQLi), Cross-Site Scripting (XSS) e Path Traversal (LFI/RFI).
2. **Detecção de Anomalias de API (Machine Learning):** Modelo baseado no algoritmo **Isolation Forest** da biblioteca *scikit-learn* alimentado por vetores de comportamento (`path_len`, `num_query_params`, `payload_size`, `requests_per_minute`). Conta com regras de segurança heurísticas auxiliares para proteção contra cold-start e ataques volumétricos repentinos.
3. **Limitação de Taxa & Bloqueio Dinâmico (Blocklist):** Registro em memória de picos de requisições por IP, aplicando banimentos temporários automáticos de 10 minutos na base SQLite local em modo *Enforcement*.
4. **Sanitização de PII & Segredos (LGPD/GDPR):** Mascaramento automático recursivo de CPFs, CNPJs, e-mails, números de cartões de crédito, tokens JWT, senhas e chaves privadas nos payloads antes de realizar qualquer gravação de log em banco de dados ou despachar alertas.
5. **Painel de Controle SOC & Alertas:** Dashboard visual rico (HTML5 + Tailwind CSS + Chart.js) integrado com suporte a Webhooks Slack/Discord para relatórios automatizados de incidentes em tempo real de forma assíncrona (não-bloqueante).

---

## 🏗️ ARQUITETURA DO SERVIÇO DE APPSEC

O fluxo de interceptação e proteção ocorre de ponta a ponta na camada HTTP, conforme ilustrado no diagrama ASCII abaixo:

### Diagrama de Fluxo de Inspeção

```text
       +---------+
       | Cliente |
       +----+----+
            |
            | 1. Requisição HTTP (Headers, URL, Body)
            v
+------------------------------------------------------------+
| AppSec Security Middleware (Interceptador WAF)             |
|                                                            |
|  [Fase 1: Verificação de Blocklist]                        |
|    - O IP de origem está na tabela sqlite `ip_blocklist`?  |
|      --> SIM: Retorna HTTP 403 Forbidden imediatamente.     |
|      --> NÃO: Continua.                                    |
|                                                            |
|  [Fase 2: Inspeção OWASP Top 10 Signatures]                |
|    - Regex Checks em: Headers, Path, Query Params, Body.   |
|                                                            |
|  [Fase 3: Heurísticas & Perfil Comportamental ML]          |
|    - IP Request Speed + Payload Size + Query Count.        |
|    - Predict via Isolation Forest (Detecção de Anomalia).   |
+----------------------------+-------------------------------+
            |                |
            | 2. Sem Ameaças | 2b. Ameaça Detectada?
            |                +-----------------------------------------+
            |                                                          |
            v                                                          v
+---------------------------+                      +---------------------------------------+
| Aplicação Core / APIs     |                      | Processador de Mitigação              |
|                           |                      |                                       |
|  - Processa endpoint      |                      |  [Modo Enforcement (Ativo)]            |
|    (ex: /api/v1/resource) |                      |    - Registra log com PII Mascarada.  |
|  - Gera resposta normal.  |                      |    - Bloqueia IP no DB por 10 minutos. |
|                           |                      |    - Dispara Webhook de Alerta (Slack) |
|                           |                      |    - Retorna HTTP 403 Forbidden.      |
|                           |                      |                                       |
|                           |                      |  [Modo Audit-Only (Passivo)]          |
|                           |                      |    - Registra log com PII Mascarada.  |
|                           |                      |    - Dispara Alerta Assíncrono.       |
|                           |                      |    - Permite tráfego (HTTP 200).      |
+---------------------------+                      +---------------------------------------+
            |                                                          |
            | 3. Resposta Normal                                       | 3b. Resposta Bloqueio
            v                                                          v
+------------------------------------------------------------------------------------------+
|                                  Sanitização de Resposta                                 |
+------------------------------------------------------------------------------------------+
                                            |
                                            | 4. Resposta Sanitizada
                                            v
                                      +-----------+
                                      |  Cliente  |
                                      +-----------+
```

---

## 📊 TABELA MESTRA DE VETORES DE ATAQUE MONITORADOS

Abaixo estão listados os vetores de ataque mitigados ativamente por este serviço, acompanhados de suas respectivas estratégias de detecção e classificação de risco:

| Vetor de Ataque | Tipo de Inspeção | Assinatura / Gatilho | Risco do Impacto | Ação de Mitigação |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Assinatura (Regex) | `SELECT`, `UNION ALL SELECT`, `' OR 1=1 --`, `DROP TABLE`, `INSERT INTO` | **CRÍTICO** | Bloqueio imediato (403), Log de auditoria, Notificação SOC e Banning de IP. |
| **Cross-Site Scripting (XSS)** | Assinatura (Regex) | `<script>`, `javascript:`, `onerror=`, `onload=`, `<iframe>` | **ALTO** | Bloqueio imediato (403), Log de auditoria, Notificação SOC e Banning de IP. |
| **Path Traversal (LFI)** | Assinatura (Regex) | `../../`, `..\`, `/etc/passwd`, `/etc/shadow`, `win.ini` | **CRÍTICO** | Bloqueio imediato (403), Log de auditoria, Notificação SOC e Banning de IP. |
| **API Abuse (Credential Stuffing)** | Comportamental / ML | Taxa de requisição anormal detectada pelo Isolation Forest (Anomalia) | **ALTO** | Bloqueio no modo Enforcement, Notificação Slack. |
| **Rate Limiting / Brute Force** | Comportamental (Métrica) | Limite máximo de requisições por minuto excedido (ex: >100 req/min) | **MÉDIO** | Ban temporário automático do IP por 10 minutos (600s). |
| **Sensitive Data Exposure (LGPD)** | Mascaramento Dinâmico | Exfiltração de CPFs, CNPJs, e-mails ou cartões de crédito em logs/payloads | **CRÍTICO** | Higienização dinâmica via Sanitizador Recursivo de PII antes do armazenamento. |

---

## 📂 ESTRUTURA DO PROJETO

```text
appsec-protection-service/
├── app/
│   ├── __init__.py
│   ├── main.py               # Servidor FastAPI, APIs de Teste e Controles Administrativos
│   ├── security_middleware.py # Core WAF HTTP Interceptor & Motor de Mitigação
│   ├── anomaly_detector.py   # Machine Learning Isolation Forest + Heurísticas Auxiliares
│   ├── pii_sanitizer.py       # Algoritmo de Mascaramento de dados confidenciais
│   ├── alert_manager.py      # Gestor de Webhooks e Despacho Assíncrono de Incidentes
│   ├── database.py           # Persistência SQLite local para Logs de Auditoria e Blocklist
│   └── templates/
│       └── dashboard.html     # Painel de Controle Visual SOC (Tailwind + Chart.js)
├── tests/
│   ├── __init__.py
│   └── test_appsec.py         # Suite de Testes Unitários e Integração (pytest)
├── Dockerfile                 # Dockerfile otimizado de produção
├── docker-compose.yml         # Orquestrador local do serviço
├── requirements.txt           # Dependências do projeto
└── README.md                  # Documentação completa
```

---

## 🚀 COMO EXECUTAR E DEPLOYAR

### Pré-requisitos
- Python 3.11 ou superior instalado localmente (caso queira rodar sem Docker).
- Docker e Docker Compose instalados.

### Opção 1: Executando Localmente (Sem Docker)

1. **Instalar as dependências do projeto:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Iniciar o microserviço de segurança:**
   ```bash
   python -m app.main
   ```
   O servidor estará ativo em `http://localhost:8000`.

3. **Acessar o Painel Visual SOC (Security Dashboard):**
   Abra seu navegador e vá para: [http://localhost:8000/admin/dashboard](http://localhost:8000/admin/dashboard).

---

### Opção 2: Implantando com Docker Compose (Produção)

1. **Subir o container em segundo plano:**
   ```bash
   docker-compose up --build -d
   ```

2. **Verificar os logs de auditoria de segurança no console:**
   ```bash
   docker-compose logs -f
   ```

---

## 🧪 MANUAL DE TESTE DE VETORES DE SEGURANÇA

Você pode testar a eficácia de bloqueio do serviço disparando requisições com os payloads maliciosos de exemplo descritos abaixo:

### 1. Testar SQL Injection (SQLi)
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin '\'' OR '\''1'\''='\''1 --", "password": "abc"}'
```
**Resposta esperada (HTTP 403 Forbidden):**
```json
{
  "error": "Security Blocked",
  "reason": "Malicious payload or behavior detected.",
  "violations": ["SQL Injection (SQLi)"],
  "mitigation_mode": "ENFORCEMENT"
}
```

### 2. Testar Cross-Site Scripting (XSS)
```bash
curl "http://localhost:8000/api/v1/resource?q=<script>alert('hack')</script>"
```
**Resposta esperada (HTTP 403 Forbidden):**
- O tráfego é bloqueado e as assinaturas correspondentes de XSS/SQLi são salvas no banco de dados.

### 3. Testar Path Traversal
```bash
curl "http://localhost:8000/api/v1/resource/../../etc/passwd"
```

### 4. Visualizar Logs Sanitizados e Métricas
Ao acessar o endpoint administrativo `/admin/logs`, você verá que senhas, CPFs e dados de cartões de crédito enviados no corpo das requisições foram gravados de forma totalmente higienizada (criptografada/mascarada) no banco de dados local:
```bash
curl http://localhost:8000/admin/logs
```

---

## 📊 OPERATIONAL API REFERENCE (CONTROL PLANE)

| Endpoint | Método | Descrição | Parâmetros / Corpo |
| :--- | :--- | :--- | :--- |
| `/admin/dashboard` | `GET` | Painel visual de monitoramento SOC para o administrador. | - |
| `/admin/metrics` | `GET` | Estatísticas unificadas, contagem de ataques e modo operacional do gateway. | - |
| `/admin/logs` | `GET` | Retorna o histórico recente de incidentes de segurança. | `limit` (opcional) |
| `/admin/blocklist` | `GET` | Lista todos os IPs ativamente bloqueados e o tempo de expiração do ban. | - |
| `/admin/blocklist` | `POST` | Insere manualmente um IP na blocklist. | `ip` (string), `duration` (segundos), `reason` (string) |
| `/admin/blocklist/unblock` | `POST` | Libera manualmente um IP bloqueado. | `ip` (query string) |
| `/admin/config` | `POST` | Altera configurações globais da esteira de proteção. | `mode` ("enforcement" ou "audit"), `rate_limit_requests_per_min`, `webhook_url` |
| `/admin/retrain` | `POST` | Força retreinamento online do algoritmo de Machine Learning Isolation Forest. | - |

---

## 🔒 MELHORES PRÁTICAS DE APPSEC & DEVSECOPS SEGUIDAS
- **Princípio do Privilégio Mínimo:** Base SQLite e rotas administrativas `/admin` isoladas por contexto lógico.
- **Fail-Secure System:** Caso o modelo de Machine Learning (`IsolationForest`) falhe em carregar ou sofra timeout, o gateway ativa as heurísticas determinísticas automaticamente, garantindo que a segurança nunca fique inoperante (*Fail-Open* indesejado).
- **Inspeção sem Efeitos Colaterais:** O Middleware lê o corpo da requisição de forma clonada, não interferindo na leitura de dados pela aplicação core e mantendo baixíssima latência.
- **Mascaramento de Dados na Origem:** Sanitização executada antes do log, garantindo conformidade absoluta com a LGPD/GDPR desde o primeiro instante (*Privacy by Design*).
