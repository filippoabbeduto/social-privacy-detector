# Social Privacy Detector

**Progetto per l'esame di Sistemi Distribuiti e Cloud Computing (SDCC) — a.a. 2025/26**
**Università della Calabria** | Studente: Filippo Abbeduto | Matricola: 276572

---

## Descrizione

Applicazione cloud-based a microservizi per il monitoraggio, la raccolta e l'analisi dell'esposizione pubblica di dati personali (PII) sui social network, con valutazione dei rischi di privacy e social engineering.

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
                    │ Comprehend │ Textract │ Rekognition │ DDB │ S3 │
                    └────────────────────────────────────────────┘
              report: Google Gemini (LLM esterno, via HTTPS)
```

| Layer | Tecnologia |
|-------|-----------|
| Frontend | React 19 + TypeScript + Vite + TailwindCSS |
| Backend | FastAPI (Python 3.12) + Uvicorn |
| Container | Docker + Docker Compose |
| CI/CD | GitHub Actions → Amazon ECR → EC2 |
| Hosting | Amazon EC2 (t3.micro) + Nginx (TLS su 443) |
| PII Detection | Amazon Comprehend + Textract (mock locale via Regex) |
| Analisi visiva | Amazon Rekognition (DetectLabels) — esposizione dalle immagini |
| AI Report | Google Gemini (gemini-2.5-flash) — LLM esterno; mock locale deterministico |
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
│   │   └── analysis.py         # Endpoint REST (/api/analyze, /api/analyze-image, /api/analysis/{id}) + worker async
│   ├── services/
│   │   ├── pii_detector.py     # PII (Comprehend/Regex) + OCR (Textract) + visione (Rekognition)
│   │   ├── report_generator.py # Report AI + prompt engineering
│   │   ├── risk_scorer.py      # Risk scoring (feature engineering)
│   │   ├── scraper.py          # Scraping social (Apify)
│   │   └── storage.py          # Persistenza (DynamoDB+S3 / in-memory mock)
│   └── tests/                  # Suite pytest (15 test)
├── docs/
│   └── REGISTRO_SVILUPPO_AI.md # Registro dello sviluppo assistito da IA
├── docker-compose.yml          # Orchestrazione 3 container (sviluppo)
├── docker-compose.prod.yml     # Orchestrazione produzione (immagini ECR)
├── nginx.conf                  # Reverse proxy principale
├── preflight.py                # Verifica connettività AWS pre-test
├── .env.example
├── .gitignore
└── README.md
```
