# Report di settore consultati

Documenti di riferimento su cui si fonda il **modello di rischio empirico**
(`backend/services/risk_empirical.py`): il rischio è `Σ Pₐ·Iₐ` sugli attacchi abilitati,
e questi report sono la fonte dei pesi. Sono inclusi per permettere la verifica diretta
dei valori dichiarati in relazione.

## Fonti citate in bibliografia

| Documento | Uso nel progetto |
|---|---|
| `2025_IC3Report.pdf` — FBI IC3, *2025 Annual Report* | **Impatti (I)**: perdite medie per vittima, mappate su scala 1–10 |
| `2026-dbir-data-breach-investigations-report.pdf` — Verizon DBIR 2026 | **Probabilità (P)** di phishing (~1,4%) e phone-centric (~2%) |
| `proofpoint-state-of-the-phish-2024.pdf` — Proofpoint, *2024 State of the Phish* | **Probabilità (P)**: tassi di fallimento delle simulazioni |
| `nistspecialpublication800-30r1.pdf` — NIST SP 800-30 Rev. 1 | **Framework**: Rischio = Probabilità × Impatto, scala semi-quantitativa |

Le `P` non ricavabili da questi report (spear phishing, account takeover, SIM swap) sono
**verosimiglianze modellate**, dichiarate come tali nella tabella del catalogo attacchi
(colonna *Origine*) e nel capitolo sul modello di rischio.

## Materiale di consultazione (non citato)

Letto durante la progettazione ma non usato per i pesi, quindi non in bibliografia:

- `cost-of-a-data-breach-2025-full-report.pdf` — IBM, *Cost of a Data Breach 2025*
- `csn-annual-data-book-2024.pdf` — FTC, *Consumer Sentinel Network Data Book 2024*
- `pages_nist.pdf` — estratto NIST SP 800-63B (linee guida sull'autenticazione)

## Nota

I documenti sono di proprietà dei rispettivi autori e qui inclusi al solo scopo di
consultazione accademica. I collegamenti alle fonti ufficiali sono nella bibliografia
della relazione.
