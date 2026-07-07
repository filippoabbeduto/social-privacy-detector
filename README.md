# 🔒 Social Privacy Detector

**Progetto per l'esame di Sistemi Distribuiti e Cloud Computing (SDCC) — a.a. 2025/26**
**Università della Calabria** | Studente: Filippo Abbeduto | Matricola: 276572

---

## 📋 Descrizione

Applicazione cloud-based a microservizi per il monitoraggio, la raccolta e l'analisi dell'esposizione pubblica di dati personali (PII) sui social network, con valutazione dei rischi di privacy e social engineering.

## 🏗️ Architettura

```
                    ┌──────────────────────────────────┐
                    │   Nginx Reverse Proxy (Porta 80)  │
                    └─────────┬───────────┬────────────┘
                              │           │
                    ┌─────────▼──┐  ┌─────▼──────────┐
                    │  React SPA │  │ FastAPI Backend │
                    │ (Port 3000)│  │  (Port 8000)   │
                    └────────────┘  └───────┬────────┘
                                            │ Boto3 SDK
                    ┌───────────────────────▼────────────────────┐
                    │            AWS Managed Services             │
                    │  Comprehend │ Textract │ Bedrock │ DynamoDB │
                    └────────────────────────────────────────────┘
```

| Layer | Tecnologia |
|-------|-----------|
| Frontend | React 18 + TypeScript + Vite + TailwindCSS |
| Backend | FastAPI (Python 3.12) + Uvicorn |
| Container | Docker + Docker Compose |
| CI/CD | GitHub Actions → Amazon ECR → EC2 |
| Hosting | Amazon EC2 (t2.micro) |
| PII Detection | Amazon Comprehend + Textract (mock locale via Regex) |
| AI Report | Amazon Bedrock / Claude (mock locale deterministico) |
| Database | Amazon DynamoDB (mock locale in-memory) |
| Storage | Amazon S3 (mock locale in-memory) |

## 🚀 Avvio Locale (Docker)

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

## 🛑 Stop

```bash
docker compose down
```

## 📁 Struttura Progetto

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
│   │   └── analysis.py         # Endpoint /api/analyze, /api/analyses
│   └── services/
│       ├── pii_detector.py     # PII Detection (Comprehend/Regex)
│       ├── report_generator.py # Report AI (Bedrock Claude/Mock)
│       ├── scraper.py          # Scraping social (Apify/Mock)
│       └── storage.py          # Persistenza (DynamoDB+S3/In-Memory)
├── docker-compose.yml          # Orchestrazione 3 container
├── nginx.conf                  # Reverse proxy principale
├── .env.example
├── .gitignore
└── README.md
```
