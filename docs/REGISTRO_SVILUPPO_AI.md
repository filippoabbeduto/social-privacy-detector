# Registro dello sviluppo assistito da IA

Questo documento registra, in modo trasparente, l'uso di un **assistente di
programmazione basato su IA generativa** (Claude Code, Anthropic) nello sviluppo del
progetto *Social Privacy Detector*. Lo sviluppo ha seguito un paradigma di
**pair-programming**: lo studente definisce obiettivi, requisiti e vincoli; l'assistente
propone alternative, piani e bozze; lo studente valuta, decide, corregge e collauda. Ogni
contributo dell'IA è stato letto, compreso e verificato (suite di 15 test automatici +
prove end-to-end) prima dell'integrazione.

> **Nota.** I prompt riportati sono **esemplificativi** (ricostruiti, non trascrizioni
> letterali): illustrano lo stile di conduzione — è lo studente a impartire le direttive.

Ogni voce segue quattro campi:

- **Task** — il macro-obiettivo o la funzionalità realizzata.
- **File modificati** — i moduli sorgente interessati.
- **Sintesi del prompt** — l'istruzione conferita (in forma sintetica).
- **Spiegazione tecnica** — la motivazione e le scelte di progetto adottate.

---

## 1 — Architettura e strategia *local-first*

- **Task**: impostare il backend FastAPI a microservizi e una modalità di esecuzione
  offline a costo zero.
- **File modificati**: `docker-compose.yml`, `backend/main.py`, `backend/services/*`
- **Sintesi del prompt**: *"Impostiamo un backend FastAPI a microservizi con uno strato di
  servizi (scraping, PII, report, rischio, storage). Prima di scrivere codice, proponimi
  come strutturare i moduli e come rendere l'app eseguibile offline senza chiamare AWS."*
- **Spiegazione tecnica**: strato `services/` con una responsabilità per modulo e un
  *mock* attivabile via `AWS_MOCK`; lo stesso codice gira in locale (senza costi) e in
  produzione contro i servizi AWS reali.

## 2 — Rilevamento delle PII (Comprehend + regole per l'Italia)

- **Task**: estrarre le informazioni personali, inclusi codice fiscale e IBAN italiani.
- **File modificati**: `backend/services/pii_detector.py`, `backend/models/schemas.py`
- **Sintesi del prompt**: *"Devo rilevare anche gli identificatori italiani (codice
  fiscale, IBAN) che Comprehend non riconosce. Proponi 2-3 approcci con pro e contro; deve
  restare economico, girare in-process e fondersi con l'output di Comprehend senza
  duplicati. Poi implementa quello a regole con regex commentate e un test."*
- **Spiegazione tecnica**: strategia **ibrida** — Comprehend (NER gestito) per il testo
  libero, motore a espressioni regolari per i codici a formato fisso; fusione con
  preferenza alle regole sui codici, per precisione superiore.

## 3 — OCR delle immagini (Amazon Textract)

- **Task**: analizzare il testo visibile nelle immagini (upload e post scrapati).
- **File modificati**: `backend/services/pii_detector.py`, `backend/routers/analysis.py`
- **Sintesi del prompt**: *"Aggiungiamo l'analisi delle immagini: un endpoint per l'upload
  di una foto e, durante lo scraping, l'OCR retrospettivo sulle immagini dei post. Metti un
  limite configurabile al numero di immagini per contenere i costi."*
- **Spiegazione tecnica**: Textract (`DetectDocumentText`) estrae il testo, che confluisce
  nella stessa pipeline PII; `MAX_POST_IMAGES_OCR` e controlli di titolarità (solo post del
  profilo) per correttezza e costo.

## 4 — Report generativo e prompt engineering (provider switchable)

- **Task**: generare sintesi e vettori d'attacco con un LLM, in modo intercambiabile.
- **File modificati**: `backend/services/report_generator.py`
- **Sintesi del prompt**: *"Il report va generato da un LLM. Rendi il provider switchable
  (Bedrock/Gemini/mock) con un solo code path OpenAI-compatible, e progetta il prompt con
  few-shot, output strutturato JSON e difese contro il prompt injection sul testo
  scrapato."*
- **Spiegazione tecnica**: provider intercambiabili via `REPORT_PROVIDER`; prompt con
  messaggio di sistema (ruolo + regole difensive + esempio) separato dai dati non fidati, e
  `response_format` JSON per un parsing deterministico.

## 5 — Assegnazione del rischio (*feature engineering*)

- **Task**: calcolare un punteggio di rischio 0-100 trasparente e interpretabile.
- **File modificati**: `backend/services/risk_scorer.py`
- **Sintesi del prompt**: *"Serve un punteggio 0-100 e tre livelli, trasparente e
  interpretabile. Assegna pesi per tipo di PII, bonus per combinazioni pericolose e per la
  diversità, e riporta ogni contributo nel report. Aggiungi test ai vari livelli."*
- **Spiegazione tecnica**: modello **a regole esplicite** (non appreso) con aggregazione
  monotòna e saturazione a 100; ogni contributo è tracciato, così il punteggio è
  spiegabile — proprietà preziosa nel dominio privacy.

## 6 — Persistenza e conformità GDPR (DynamoDB + S3)

- **Task**: persistere le analisi senza conservare i dati personali in modo permanente.
- **File modificati**: `backend/services/storage.py`, `docker-compose*.yml`
- **Sintesi del prompt**: *"I dati personali non devono essere conservati in modo
  permanente. Aggiungi una scadenza ai record e una regola di lifecycle, così i dati si
  cancellano da soli dopo una finestra configurabile."*
- **Spiegazione tecnica**: **storage limitation** con TTL nativo di DynamoDB su
  `expires_at` + lifecycle S3; la conservazione è vincolata allo scopo pur usando storage
  gestito AWS.

## 7 — Interfaccia web (React)

- **Task**: realizzare la SPA con due modalità di analisi e la visualizzazione dei
  risultati.
- **File modificati**: `frontend/src/App.tsx`, `frontend/src/index.css`
- **Sintesi del prompt**: *"Interfaccia a due colonne, due modalità (Profilo/Immagine),
  colore usato solo per la severità del rischio. Aggiungi l'export del report in PDF lato
  client e un dettaglio distintivo: le PII coperte da una barra di 'redazione' che si
  ritrae."*
- **Spiegazione tecnica**: SPA con colore semantico, generazione PDF client-side (libreria
  caricata on-demand) e animazione di redazione che rappresenta ciò che il profilo espone.

## 8 — CI/CD, reverse proxy e HTTPS

- **Task**: automatizzare il deploy e esporre il sistema dietro un unico entrypoint sicuro.
- **File modificati**: `.github/workflows/deploy.yml`, `nginx.conf`,
  `docker-compose.prod.yml`
- **Sintesi del prompt**: *"Automatizza il deploy: build delle immagini su ECR e rilascio
  su EC2 a ogni push. Metti Nginx come reverse proxy unico entrypoint con terminazione TLS
  su 443 e redirect da HTTP."*
- **Spiegazione tecnica**: pipeline GitHub Actions (build → ECR → SSH → restart); Nginx come
  edge router (path-based routing, niente CORS, TLS); immagini immutabili taggate con lo
  SHA del commit per deploy riproducibile e rollback.

## 9 — Revisione di sicurezza del codice

- **Task**: individuare e correggere bug e vulnerabilità di sicurezza.
- **File modificati**: `backend/routers/analysis.py`, `backend/services/storage.py`,
  `nginx.conf`
- **Sintesi del prompt**: *"Fai una revisione completa del codice per bug e vulnerabilità
  di sicurezza; per ognuna indica dove, perché è un problema, il caso peggiore e come
  correggerla."*
- **Spiegazione tecnica**: individuate e corrette criticità reali — **SSRF** sul download
  delle immagini (validazione host + no redirect), **DoS** per download illimitato (tetto
  in streaming), **divulgazione di PII** (rimosso l'endpoint che elencava tutte le analisi),
  igiene dei segreti nei log, *race condition* sullo store in memoria.

## 10 — Audit di minimalità e correzione di difetti

- **Task**: ridurre il codice all'essenziale e risolvere il 502 di Nginx.
- **File modificati**: `backend/services/risk_scorer.py`, `backend/routers/analysis.py`,
  `nginx.conf`
- **Sintesi del prompt**: *"Verifica che il codice sia ridotto all'osso senza cambiare il
  comportamento; rimuovi codice morto. E risolvi il 502 di Nginx alla ricreazione dei
  container."*
- **Spiegazione tecnica**: rimosse feature calcolate e mai usate e ripetizioni (helper
  condivisi lato frontend); risolto il 502 con `resolver` DNS + `proxy_pass` via variabile
  (risoluzione a runtime dell'upstream).

## 11 — Copertura delle piattaforme di scraping

- **Task**: mantenere solo i social realmente scrapabili col piano gratuito.
- **File modificati**: `backend/services/scraper.py`, `frontend/src/App.tsx`
- **Sintesi del prompt**: *"Verifica quali social sono realmente scrapabili col piano
  gratuito di Apify; rimuovi quelli che non restituiscono dati, motivando la scelta."*
- **Spiegazione tecnica**: X/Twitter e LinkedIn non restituiscono dati sul piano gratuito;
  rimossi per non lasciare percorsi non funzionanti, mantenendo Instagram, TikTok e
  Facebook; scelta documentata in relazione.

## 12 — Stesura della relazione

- **Task**: strutturare e approfondire la relazione, allineandola al codice reale.
- **File modificati**: `relazione/relazione.tex`
- **Sintesi del prompt**: *"Aiutami a strutturare e approfondire la relazione: àncora ogni
  scelta ai concetti di sistemi distribuiti e cloud, con tabelle, esempi numerici e figure.
  Verifica la coerenza col codice reale."*
- **Spiegazione tecnica**: relazione in LaTeX con inquadramento teorico (multi-tier,
  consistenza, sicurezza), tabelle (pesi di rischio, PII, requisiti), listati (prompt,
  regex, guardia SSRF) e diagrammi; contenuti verificati contro il codice.

---

*I contenuti prodotti con l'ausilio dell'assistente sono stati integralmente compresi,
adattati e collaudati dall'autore, che mantiene la responsabilità delle scelte
progettuali.*
