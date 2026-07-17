# Social Privacy Detector

**Progetto per l'esame di Sistemi Distribuiti e Cloud Computing (SDCC) — a.a. 2025/26**
**Università della Calabria** | Studente: Filippo Abbeduto | Matricola: 276572

---

## Descrizione

Applicazione cloud-based a microservizi per il monitoraggio, la raccolta e l'analisi dell'esposizione pubblica di dati personali (PII) sui social network, con valutazione dei rischi di privacy e social engineering.

L'estrazione delle PII avviene con **Microsoft Presidio + spaCy italiano** (locale e deterministico, con post-processing dedicato per l'italiano); lo **score di rischio** è calcolato in codice deterministico con un modello **empirico** (rischio atteso = probabilità × impatto per ciascun vettore d'attacco, con pesi ancorati a report di settore — IC3, DBIR, Proofpoint — su framework NIST SP 800-30). L'AI generativa (Google Gemini) **spiega** i vettori d'attacco individuati dallo score, senza calcolarli.

## Architettura

```
                    ┌──────────────────────────────────┐
                    │   Nginx Reverse Proxy (80/443)    │
                    └─────────┬───────────┬────────────┘
                              │           │
                    ┌─────────▼──┐  ┌─────▼──────────┐
                    │  React SPA │  │ FastAPI Backend │
                    │ (Port 3000)│  │  (Port 8000)   │
                    └────────────┘  └───────┬────────┘
                                            │ Boto3 SDK
                    ┌───────────────────────▼────────────────────┐
                    │            AWS Managed Services             │
                    │ Textract │ Rekognition │ DynamoDB │ S3 │ (Comprehend opz.) │
                    └────────────────────────────────────────────┘
       PII: Presidio + spaCy IT (locale, default)   ·   report: Google Gemini (HTTPS)
```

| Layer | Tecnologia |
|-------|-----------|
| Frontend | React 19 + TypeScript + Vite + TailwindCSS |
| Backend | FastAPI (Python 3.12) + Uvicorn |
| Container | Docker + Docker Compose |
| CI/CD | GitHub Actions → Amazon ECR → EC2 |
| Hosting | Amazon EC2 (t3.micro) + Nginx (TLS su 443) |
| Estrazione PII | **Presidio + spaCy `it_core_news_lg`** (+ recognizer per riferimenti familiari) (locale, deterministico, default) · **ensemble** (Presidio + LLM esterno con grounding: l'LLM aggiunge i fuzzy mancanti *e* verifica quelli del NER, opt-in) · Amazon Comprehend + post-processing · Regex — commutabili via `PII_PROVIDER` |
| OCR immagini | Amazon Textract (`DetectDocumentText`) |
| Analisi visiva | Amazon Rekognition: DetectLabels (esposizione) + DetectFaces solo AGE_RANGE (segnalazione minori) |
| Modello di rischio | `empirical` (default): Rischio = Σ Pₐ·Iₐ con pesi da studi (IC3, DBIR, Proofpoint) su framework NIST SP 800-30 · `heuristic` — commutabili via `RISK_MODEL` |
| AI Report | Google Gemini (gemini-2.5-flash) — spiega i vettori d'attacco calcolati dallo score. Catena di fallback se non risponde (es. quota giornaliera esaurita): LLM esterno via Ollama (`GEN_LLM_MODEL`) → mock locale deterministico |
| Database | Amazon DynamoDB (mock locale in-memory) |
| Storage | Amazon S3 (mock locale in-memory) |

## Avvio Locale (Docker)

```bash
# Clona il repository
git clone <repo-url>
cd social-privacy-detector

# Avvia tutti i container
docker compose up --build -d

# Apri nel browser
# Frontend:  http://localhost
# API Docs:  http://localhost/api/docs
# Health:    http://localhost/api/health
```

## Stop

```bash
docker compose down
```

## Struttura Progetto

```
social-privacy-detector/
├── .github/workflows/
│   └── deploy.yml              # CI/CD pipeline GitHub Actions
├── frontend/
│   ├── Dockerfile              # Multi-stage build (node → nginx)
│   ├── nginx.conf              # Serve file statici su porta 3000
│   ├── src/
│   │   ├── App.tsx             # Componente principale React
│   │   ├── main.tsx            # Entry point
│   │   └── index.css           # Stili TailwindCSS
│   ├── package.json
│   └── tsconfig.json
├── backend/
│   ├── Dockerfile              # Python 3.12-slim + uvicorn
│   ├── main.py                 # Entry point FastAPI
│   ├── requirements.txt
│   ├── models/
│   │   └── schemas.py          # Modelli Pydantic (validazione I/O)
│   ├── routers/
│   │   └── analysis.py         # Endpoint REST (/api/analyze, /api/analyze-image, /api/rescore, /api/sanitize-bio, /api/leverage, /api/attack-example, /api/analysis/{id}) + worker async
│   ├── services/
│   │   ├── pii_detector.py     # PII: dispatcher PII_PROVIDER (presidio/ensemble/comprehend/regex) + OCR (Textract) + visione (Rekognition)
│   │   ├── pii_presidio.py     # Estrazione PII con Presidio + spaCy IT + recognizer custom + post-processing (default)
│   │   ├── pii_llm.py          # Estrattore LLM (modalità ensemble) sui tipi fuzzy: grounding deterministico + verifica dei candidati NER
│   │   ├── visual_exposure.py  # Classificazione etichette visive sensibili (minori/documenti/geolocalizzazione)
│   │   ├── comuni.py           # Decodifica deterministica comune di nascita dal CF (tabella codici catastali)
│   │   ├── report_generator.py # Report AI (spiega gli attacchi dello score) + prompt engineering + bio sanitizzata
│   │   ├── attack_example.py   # Esempio didattico di messaggio d'attacco (LLM Ollama, on-demand)
│   │   ├── risk_scorer.py      # Risk scoring: dispatcher RISK_MODEL + euristico + compressione + leva/bonifica
│   │   ├── risk_empirical.py   # Modello di rischio empirico (Σ Pₐ·Iₐ, pesi da studi, NIST SP 800-30)
│   │   ├── dossier.py          # Identità ricomposta dai frammenti PII (deterministica)
│   │   ├── secret_resolver.py  # Risoluzione segreti: env → SSM SecureString
│   │   ├── metrics.py          # Metriche custom CloudWatch (osservabilità)
│   │   ├── queue.py            # Coda SQS (modalità worker distribuita)
│   │   ├── pipeline.py         # Pipeline di analisi condivisa (thread in-process / Lambda)
│   │   ├── scraper.py          # Scraping social (Apify)
│   │   └── storage.py          # Persistenza (DynamoDB+S3 / in-memory mock)
│   └── tests/                  # Suite pytest (176 test)
├── infra/
│   ├── cloud.yaml              # IaC CloudFormation (SQS+DLQ+Lambda+CloudWatch)
│   ├── oidc-trust.json         # Trust OIDC per il ruolo di deploy (no chiavi statiche)
│   ├── gha-deploy-policy.json  # Permessi IAM della pipeline CI
│   └── cleanup.sh              # Smontaggio risorse AWS
├── relazione/
│   └── relazione.pdf           # Relazione (deliverable)
├── report-esempio/             # Tre report d'esempio (rischio alto/medio/basso)
├── fonti/                      # Report di settore consultati (IC3, DBIR, Proofpoint, NIST)
├── docker-compose.yml          # Orchestrazione 3 container (sviluppo)
├── docker-compose.prod.yml     # Orchestrazione produzione (immagini ECR)
├── nginx.conf                  # Reverse proxy principale
├── preflight.py                # Verifica connettività AWS pre-test
├── .env.example
├── .gitignore
└── README.md
```
