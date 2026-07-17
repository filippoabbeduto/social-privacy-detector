import React, { useState, useEffect, useRef } from "react";
import {
  Sun,
  Moon,
  Search,
  ArrowRight,
  RefreshCw,
  Trash2,
  ChevronRight,
  ChevronDown,
  Download,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Gauge,
  Eye,
  Target,
  Mail,
  Phone,
  MapPin,
  User,
  Calendar,
  Fingerprint,
  Landmark,
  Building2,
  AtSign,
  Link2,
  Tag,
  Cpu,
  ScanText,
  Sparkles,
  Share2,
  Repeat,
  Check,
  Plus,
  TrendingDown,
  TrendingUp,
  Info,
  Users,
} from "lucide-react";

// Logo dell'applicazione (mark del brand nell'header). Import via Vite: restituisce
// l'URL dell'asset ottimizzato, che viene incluso nel bundle con hash.
import logoUrl from "./assets/logo.png";

// ─── Esempi di biografia: popolano la textarea (modalità "bio") per provare i tre
// livelli di rischio. In questa modalità si valuta SOLO il testo della bio, quindi
// gli esempi non citano piattaforme social: sono etichettati per livello di rischio
// atteso (alto/medio/basso) in base alla quantità e sensibilità delle PII contenute. ───
const DEMO_PROFILES = [
  {
    label: "Rischio alto",
    content:
      "Mi chiamo Filippo Abbeduto, studente alla Sapienza di Roma. Scrivimi a filippo.abb@sapienza.it o al 333-1234567. Nato il 15/03/1999, codice fiscale ABBFPP99C15D086X, IBAN IT60X0542811101000000123456.",
  },
  {
    label: "Rischio medio",
    content:
      "Studentessa a Cosenza, tirocinio presso Enel. Scrivimi a mara.v@example.com o al 331-9988776, nata il 22/06/2000.",
  },
  {
    label: "Rischio basso",
    content:
      "Appassionato di OSINT e sicurezza informatica. Ricorda di limitare l'esposizione di informazioni identificabili sui canali pubblici.",
  },
];

interface PIIEntity {
  type: string;
  text: string;
  score: number;
}
interface SocialEngineeringThreat {
  threat_vector: string;
  severity: string;
  explanation: string;
}
interface RiskCombo {
  label: string;
  types: string[];
  points: number;
}
interface RiskRepetition {
  type: string;
  text: string;
  count: number;
  label: string;
}
interface RiskAssessment {
  risk_level: string;
  explanation: string;
  score: number;
  motivations: string[];
  combos?: RiskCombo[];
  repetitions?: RiskRepetition[];
}
interface ImageLabel {
  name: string;
  confidence: number;
}
interface SensitiveLabel {
  category: string; // MINORI | DOCUMENTI | GEO
  label: string;
  confidence: number;
}
interface AttackerDossier {
  text: string;
  missing: string[];
}
interface FiscalCodeInfo {
  code: string;
  birthplace: string;
}
interface AnalysisResult {
  analysis_id: string;
  social_url: string;
  status: string;
  detected_pii?: PIIEntity[];
  image_labels?: ImageLabel[];
  sensitive_visual?: SensitiveLabel[];
  attacker_dossier?: AttackerDossier;
  fiscal_code_info?: FiscalCodeInfo[];
  narrative_summary?: string;
  social_engineering_report?: SocialEngineeringThreat[];
  risk_assessment?: RiskAssessment;
  error?: string;
}

// Le tre modalità di analisi, ognuna con il PROPRIO stato di risultato.
type Mode = "profile" | "bio" | "image";
// Oggetto su cui è stata avviata l'analisi (mostrato sopra i risultati):
// il link del profilo, il testo della bio o l'anteprima dell'immagine.
type Source =
  | { kind: "profile"; url: string }
  | { kind: "bio"; text: string }
  | { kind: "image"; name: string; preview: string };
interface ModeState {
  result: AnalysisResult | null;
  error: string | null;
  jobStatus: string | null;
  loading: boolean;
  source: Source | null;
}
const EMPTY_STATE: ModeState = { result: null, error: null, jobStatus: null, loading: false, source: null };

// Etichette leggibili + icona per ogni tipo di PII restituito dal backend.
const PII_META: Record<string, { label: string; Icon: React.ComponentType<{ className?: string }> }> = {
  NAME: { label: "Nome", Icon: User },
  EMAIL: { label: "Email", Icon: Mail },
  PHONE: { label: "Telefono", Icon: Phone },
  PHONE_NUMBER: { label: "Telefono", Icon: Phone },
  LOCATION: { label: "Luogo", Icon: MapPin },
  ADDRESS: { label: "Indirizzo", Icon: MapPin },
  DATE_OF_BIRTH: { label: "Data di nascita", Icon: Calendar },
  AGE: { label: "Età", Icon: Calendar },
  DATE: { label: "Data", Icon: Calendar },
  FISCAL_CODE: { label: "Codice fiscale", Icon: Fingerprint },
  IBAN: { label: "IBAN", Icon: Landmark },
  ORGANIZATION: { label: "Organizzazione", Icon: Building2 },
  USERNAME: { label: "Username", Icon: AtSign },
  URL: { label: "URL", Icon: Link2 },
  // Legame familiare dichiarato in pubblico ("mia figlia Sofia"). Non pesa sullo
  // score: è un segnale qualitativo, come le etichette visive sensibili.
  FAMILY_REF: { label: "Riferimento familiare", Icon: Users },
};
const piiMeta = (type: string) => PII_META[type] || { label: type, Icon: Tag };

// Soglia di confidenza sotto la quale un rilevamento NON viene conteggiato nel
// punteggio (identica a CONFIDENCE_FLOOR nel backend, risk_scorer.py). Serve alla
// UI per mostrare onestamente quali dati sono "troppo incerti per pesare".
const CONFIDENCE_FLOOR = 0.55;

// Nome leggibile della combinazione pericolosa (label interne di COMBO_BONUSES).
const COMBO_LABELS: Record<string, string> = {
  contatto_diretto_multiplo: "Contatto diretto multiplo",
  identita_phishing_combo: "Identità per phishing",
  identita_sim_swap_combo: "Rischio SIM swap",
  profilazione_lavorativa: "Profilazione lavorativa",
  spear_phishing_geografico: "Spear phishing geografico",
  identita_geografica: "Identità geografica",
  identita_completa: "Identità completa",
  profilo_attacco_completo: "Profilo d'attacco completo",
  identita_completa_geo: "Identità completa + geografia",
  massima_esposizione: "Massima esposizione",
  doxing_esposizione_fisica: "Doxing / esposizione fisica",
  identificazione_completa: "Identificazione completa",
  doxing_contattabile: "Doxing contattabile",
  localizzazione_contattabile: "Localizzazione contattabile",
  identita_contattabile: "Identità contattabile",
  identita_anagrafica_cf: "Identità anagrafica (CF)",
  recupero_account_cf: "Recupero account (CF)",
  identita_sim_cf: "Identità + SIM (CF)",
  frode_finanziaria: "Frode finanziaria",
  frode_pagamento_bec: "Frode di pagamento (BEC)",
  frode_carta: "Frode con carta",
  identita_finanziaria: "Identità finanziaria",
  identita_finanziaria_totale: "Identità finanziaria totale",
};
const comboLabel = (l: string) =>
  COMBO_LABELS[l] || l.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

// Etichetta compatta per i nodi del grafo (deve stare sotto un pallino stretto).
const GRAPH_LABEL: Record<string, string> = {
  EMAIL: "Email",
  PHONE: "Telefono",
  PHONE_NUMBER: "Telefono",
  DATE_OF_BIRTH: "Nascita",
  LOCATION: "Luogo",
  ADDRESS: "Indirizzo",
  ORGANIZATION: "Org.",
  NAME: "Nome",
  AGE: "Età",
  FISCAL_CODE: "Cod. fiscale",
  IBAN: "IBAN",
  CREDIT_DEBIT_NUMBER: "Carta",
  BANK_ACCOUNT_NUMBER: "Conto",
  INTERNATIONAL_BANK_ACCOUNT_NUMBER: "IBAN",
  SSN: "SSN",
};
const graphLabel = (type: string) => GRAPH_LABEL[type] || piiMeta(type).label;

// Etichette visive (Rekognition) che di per sé espongono dati sensibili o localizzano.
const SENSITIVE_VISUAL = ["license plate", "targa", "document", "passport", "id card", "identity", "credit card", "debit card", "face", "home", "house", "street sign", "map", "boarding pass", "child", "children", "baby", "kid", "toddler", "boy", "girl", "infant", "newborn"];
const GEO_VISUAL = ["beach", "mountain", "landmark", "monument", "building", "city", "street", "tower", "stadium", "church", "nature", "coast", "harbor"];
const isSensitiveVisual = (name: string) => SENSITIVE_VISUAL.some((k) => name.toLowerCase().includes(k));
const isGeoVisual = (name: string) => GEO_VISUAL.some((k) => name.toLowerCase().includes(k));

// ─── Decodifica del codice fiscale italiano ───────────────────────────────────
// Il CF NON è un dato isolato: codifica data di nascita, sesso e comune di nascita.
// Decodifica deterministica (nessuna fonte esterna). Gestisce l'omocodia (cifre
// sostituite da lettere in caso di collisione). Il comune resta come codice catastale
// (Belfiore): mapparlo al nome richiederebbe una tabella di ~8000 voci, qui omessa.
const CF_MONTHS: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, E: 4, H: 5, L: 6, M: 7, P: 8, R: 9, S: 10, T: 11 };
const CF_OMO: Record<string, string> = { L: "0", M: "1", N: "2", P: "3", Q: "4", R: "5", S: "6", T: "7", U: "8", V: "9" };
const cfDeOmo = (ch: string) => CF_OMO[ch] ?? ch;

function decodeFiscalCode(raw: string): { date: string; sex: "M" | "F"; comune: string } | null {
  const cf = (raw || "").toUpperCase().trim();
  if (cf.length !== 16) return null;
  const mLetter = cf[8];
  if (!(mLetter in CF_MONTHS)) return null;
  const dd = parseInt(cfDeOmo(cf[9]) + cfDeOmo(cf[10]), 10);
  const yy = parseInt(cfDeOmo(cf[6]) + cfDeOmo(cf[7]), 10);
  if (isNaN(dd) || isNaN(yy)) return null;
  const sex: "M" | "F" = dd > 40 ? "F" : "M";
  const day = dd > 40 ? dd - 40 : dd;
  if (day < 1 || day > 31) return null;
  const month = CF_MONTHS[mLetter];
  // Secolo ambiguo (2 cifre): euristica — se l'anno supera l'anno corrente a 2 cifre
  // è del '900, altrimenti del 2000.
  const nowYY = new Date().getFullYear() % 100;
  const year = yy > nowYY ? 1900 + yy : 2000 + yy;
  const comune = cf[11] + cfDeOmo(cf[12]) + cfDeOmo(cf[13]) + cfDeOmo(cf[14]);
  const date = `${String(day).padStart(2, "0")}/${String(month + 1).padStart(2, "0")}/${year}`;
  return { date, sex, comune };
}

// Evidenzia nel testo sorgente (bio) i frammenti riconosciuti come PII: segmenta il
// testo cercando ogni PII (match case-insensitive) e avvolge le occorrenze in <mark>
// con tooltip = tipo. Gli overlap si risolvono greedy (prima i match più lunghi). Così
// l'utente vede QUALE parola, e dove, lo espone — non solo una lista a parte.
function highlightPii(text: string, piis: { type: string; text: string }[]): React.ReactNode[] {
  const lower = text.toLowerCase();
  type M = { start: number; end: number; label: string };
  const matches: M[] = [];
  for (const p of piis) {
    const needle = p.text.toLowerCase().trim();
    if (needle.length < 2) continue;
    let i = lower.indexOf(needle);
    while (i !== -1) {
      matches.push({ start: i, end: i + needle.length, label: piiMeta(p.type).label });
      i = lower.indexOf(needle, i + needle.length);
    }
  }
  matches.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const chosen: M[] = [];
  let lastEnd = -1;
  for (const m of matches) if (m.start >= lastEnd) { chosen.push(m); lastEnd = m.end; }
  const out: React.ReactNode[] = [];
  let pos = 0;
  chosen.forEach((m, k) => {
    if (m.start > pos) out.push(<span key={`t${k}`}>{text.slice(pos, m.start)}</span>);
    out.push(
      <mark key={`m${k}`} title={m.label} className="rounded-sm bg-accent/15 text-ink px-0.5 underline decoration-dotted decoration-accent/60 underline-offset-2">
        {text.slice(m.start, m.end)}
      </mark>
    );
    pos = m.end;
  });
  if (pos < text.length) out.push(<span key="tail">{text.slice(pos)}</span>);
  return out;
}

// Livello di rischio → token colore semantico (gli unici saturi dell'interfaccia).
type RiskKey = "high" | "med" | "low";
const riskInfo = (level: string): { key: RiskKey; label: string } => {
  const l = (level || "").toUpperCase();
  if (l === "HIGH") return { key: "high", label: "Alto" };
  if (l === "MEDIUM") return { key: "med", label: "Medio" };
  return { key: "low", label: "Basso" };
};
const RISK_TEXT: Record<RiskKey, string> = { high: "text-high", med: "text-med", low: "text-low" };
const RISK_BG: Record<RiskKey, string> = { high: "bg-high", med: "bg-med", low: "bg-low" };
const RISK_PILL: Record<RiskKey, string> = {
  high: "text-high border-high/40 bg-high/10",
  med: "text-med border-med/40 bg-med/10",
  low: "text-low border-low/40 bg-low/10",
};

// Pillola severità in stile "badge" (come la tabella della reference).
function SeverityPill({ level }: { level: string }) {
  const r = riskInfo(level);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${RISK_PILL[r.key]}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${RISK_BG[r.key]}`} />
      {r.label}
    </span>
  );
}

// Anima un numero da 0 al valore target (easeOutCubic). Rispetta reduced-motion.
function useCountUp(target: number, duration = 850): number {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      setVal(target);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setVal(Math.round(target * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return val;
}

// Gauge radiale del punteggio (SVG). Numero e anello "contano" da 0 all'apertura.
function ScoreGauge({ score, riskKey }: { score: number; riskKey: RiskKey }) {
  const R = 34;
  const C = 2 * Math.PI * R;
  const clamped = Math.min(100, Math.max(0, score));
  const display = useCountUp(clamped);
  const offset = C * (1 - display / 100);
  return (
    <div className="relative w-24 h-24 shrink-0">
      <svg viewBox="0 0 80 80" className="w-24 h-24 -rotate-90">
        <circle cx="40" cy="40" r={R} fill="none" stroke="var(--c-line)" strokeWidth="7" />
        <circle
          cx="40"
          cy="40"
          r={R}
          fill="none"
          stroke="currentColor"
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={offset}
          className={RISK_TEXT[riskKey]}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-display text-2xl font-extrabold leading-none ${RISK_TEXT[riskKey]}`}>{display}</span>
        <span className="text-[10px] font-mono text-faint mt-0.5">/100</span>
      </div>
    </div>
  );
}

// Mappa dell'aggregazione: dati come nodi in alto, ogni COMBINAZIONE pericolosa come
// nodo "attacco" in basso collegato ai suoi membri. Con "tutte le combo" un dato può
// alimentare più attacchi → un nodo dato si collega a più nodi attacco. Rende visibile
// la tesi: da pochi dati banali nascono molti vettori d'attacco. SVG a mano (come
// ScoreGauge), nessuna libreria di grafi. La mappa mostra al più MAX_MAP_COMBOS combo
// (le più gravi, già ordinate dal backend); le altre restano nel dettaglio del punteggio.
//
// DUE VINCOLI DI LEGGIBILITÀ, imparati da un profilo con 11 tipi esposti:
//  1. si disegnano SOLO i tipi coinvolti nelle combo mostrate. Il viewBox cresce con il
//     numero di nodi ma la larghezza a schermo è fissa (w-full): ogni nodo in più
//     rimpicciolisce TUTTO il disegno. Con 11 tipi il testo scendeva sotto gli 8px.
//     I tipi non coinvolti, oltretutto, apparivano grigi — leggibile come "innocuo" —
//     mentre in realtà alimentano le combo che non stiamo disegnando: informazione
//     assente e messaggio fuorviante, al prezzo del 64% della larghezza.
//  2. ogni nodo attacco sta sotto il BARICENTRO dei suoi membri. Distribuirli a passo
//     fisso sull'intera larghezza produceva archi diagonali che attraversavano tutto il
//     disegno, perché i membri sono addensati a sinistra.
const MAX_MAP_COMBOS = 5;
function ComboMap({ allTypes, combos, riskKey, max = MAX_MAP_COMBOS }: { allTypes: string[]; combos: RiskCombo[]; riskKey: RiskKey; max?: number }) {
  const shown = combos.slice(0, max);
  // Multimappa tipo → indici delle combo a cui appartiene (le combo si sovrappongono).
  const comboIdxOf = new Map<string, number[]>();
  shown.forEach((c, j) => c.types.forEach((t) => {
    const arr = comboIdxOf.get(t) || [];
    arr.push(j);
    comboIdxOf.set(t, arr);
  }));
  // Solo i tipi che entrano in almeno una combo mostrata (vedi vincolo 1).
  const types = shown.flatMap((c) => c.types).filter((t, i, a) => allTypes.includes(t) && a.indexOf(t) === i);
  const n = types.length || 1;
  const FONT = 10.5;
  const W = Math.max(340, n * 78), H = 182, topY = 42, attackY = 142;
  const slot = W / n;
  const cap = slot * 0.84;
  const xs = types.map((_, i) => slot * (i + 0.5));
  // Nodo attacco sotto il baricentro dei suoi membri (vedi vincolo 2), poi separazione
  // minima perché due attacchi con membri simili non si sovrappongano.
  const GAP = 30;
  const centers = shown.map((c) => {
    const px = c.types.map((t) => types.indexOf(t)).filter((i) => i >= 0).map((i) => xs[i]);
    return px.length ? px.reduce((s, x) => s + x, 0) / px.length : W / 2;
  });
  const order = centers.map((x, j) => ({ x, j })).sort((a, b) => a.x - b.x);
  for (let k = 1; k < order.length; k++) {
    if (order[k].x - order[k - 1].x < GAP) order[k].x = order[k - 1].x + GAP;
  }
  const over = order.length ? order[order.length - 1].x - (W - 16) : 0;
  if (over > 0) order.forEach((o) => { o.x = Math.max(16, o.x - over); });
  const attackX: number[] = [];
  order.forEach((o) => { attackX[o.j] = o.x; });
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className={`w-full h-auto ${RISK_TEXT[riskKey]}`}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label={shown.map((c) => `${c.types.map(graphLabel).join(", ")} → ${comboLabel(c.label)}`).join("; ")}
    >
      {/* archi: ogni dato verso TUTTI i nodi attacco delle combo a cui appartiene */}
      {types.map((t, i) =>
        (comboIdxOf.get(t) || []).map((j) => (
          <line key={`l${i}-${j}`} x1={xs[i]} y1={topY} x2={attackX[j]} y2={attackY} stroke="currentColor" strokeWidth={1.25} strokeOpacity={0.35} />
        ))
      )}
      {/* nodi attacco, numerati per collegarli alla lista sotto */}
      {shown.map((_, j) => (
        <g key={`a${j}`}>
          <circle cx={attackX[j]} cy={attackY} r={11} fill="currentColor" />
          <text x={attackX[j]} y={attackY + 3.5} textAnchor="middle" fontSize="10" fontWeight="700" fill="var(--c-surface)">
            {j + 1}
          </text>
        </g>
      ))}
      {/* nodi dato: tutti membri di almeno una combo mostrata (vedi vincolo 1) */}
      {types.map((t, i) => {
        const label = graphLabel(t);
        const clamped = label.length * FONT * 0.62 > cap;
        return (
          <g key={`n${i}`}>
            <text
              x={xs[i]}
              y={topY - 12}
              textAnchor="middle"
              fontSize={FONT}
              fill="currentColor"
              fontWeight="600"
              {...(clamped ? { textLength: cap, lengthAdjust: "spacingAndGlyphs" } : {})}
            >
              {label}
            </text>
            <circle
              cx={xs[i]}
              cy={topY}
              r={6.5}
              fill="var(--c-surface)"
              stroke="currentColor"
              strokeWidth={1.5}
            />
          </g>
        );
      })}
    </svg>
  );
}

// Card KPI (icona tinta + etichetta + valore grande), stile reference "KPI Summary".
function StatCard({
  Icon,
  label,
  value,
  sub,
  tone = "neutral",
}: {
  Icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  tone?: "neutral" | "accent" | RiskKey;
}) {
  // Solo la card del punteggio porta il colore del rischio; le altre restano
  // neutre, così il colore comunica la severità e non fa "rumore" cromatico.
  const tint =
    tone === "neutral"
      ? "bg-surface2 text-muted"
      : tone === "accent"
      ? "bg-accent/10 text-accent"
      : tone === "high"
      ? "bg-high/10 text-high"
      : tone === "med"
      ? "bg-med/10 text-med"
      : "bg-low/10 text-low";
  return (
    <div className="rounded-2xl border border-line bg-surface shadow-soft p-4">
      <div className={`grid place-items-center w-9 h-9 rounded-xl ${tint} mb-3`}>
        <Icon className="w-4.5 h-4.5" />
      </div>
      <div className="text-[11px] uppercase tracking-wider text-muted font-semibold">{label}</div>
      <div className="font-display text-2xl font-extrabold mt-0.5">{value}</div>
      {sub && <div className="text-xs text-muted mt-0.5">{sub}</div>}
    </div>
  );
}

// Tab di modalità (Profilo/Biografia/Immagine). Estratto per riusarlo due volte:
// inline nell'header su desktop, e su una riga a parte a piena larghezza su mobile.
function ModeTabs({ mode, onSelect, className = "" }: { mode: Mode; onSelect: (m: Mode) => void; className?: string }) {
  const tabs: [Mode, string][] = [["profile", "Profilo"], ["bio", "Biografia"], ["image", "Immagine"]];
  return (
    <nav className={`flex items-center gap-1 rounded-xl border border-line bg-surface p-1 ${className}`}>
      {tabs.map(([m, label]) => (
        <button
          key={m}
          type="button"
          onClick={() => onSelect(m)}
          className={`flex-1 px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors ${
            mode === m ? "bg-accent text-accentink" : "text-muted hover:text-ink"
          }`}
        >
          {label}
        </button>
      ))}
    </nav>
  );
}

export default function App() {
  // ─── Tema: legge quello già impostato dallo script inline in <head> (default chiaro) ───
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const cur = typeof document !== "undefined" ? document.documentElement.getAttribute("data-theme") : null;
    return cur === "dark" ? "dark" : "light";
  });
  useEffect(() => {
    const root = document.documentElement;
    // Disattiva le transizioni durante lo switch: senza, le box con `transition-colors`
    // ANIMANO il cambio di colore (sfondo/bordo) e sembrano "in ritardo" rispetto al
    // resto. Si riattivano al frame successivo, così il tema cambia di colpo e ovunque.
    root.classList.add("no-theme-anim");
    root.setAttribute("data-theme", theme);
    const id = requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("no-theme-anim")));
    try {
      localStorage.setItem("spd-theme", theme);
    } catch {
      /* localStorage non disponibile: il tema resta per la sessione */
    }
    return () => cancelAnimationFrame(id);
  }, [theme]);

  // ─── Stato form / analisi ───
  const [socialUrl, setSocialUrl] = useState("");
  const [scrapedContent, setScrapedContent] = useState("");
  const [activeTemplate, setActiveTemplate] = useState<number | null>(null);
  // Esempi collassabili, chiusi di default: tengono il form pulito.
  const [showExamples, setShowExamples] = useState(false);
  // Modalità di analisi selezionabile dalla navbar:
  //  - "profile": analizza un profilo reale (scraping dei dati pubblici);
  //  - "bio":     analizza un testo di biografia incollato (controllo pre-pubblicazione);
  //  - "image":   analizza una foto (OCR Textract + visione Rekognition).
  const [mode, setMode] = useState<Mode>("profile");
  // Immagine selezionata ma NON ancora analizzata: l'analisi parte solo al click
  // esplicito su "Analizza", non alla semplice selezione del file.
  const [imageFile, setImageFile] = useState<File | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Stato dei risultati SEPARATO per ogni modalità: ognuna conserva il proprio
  // esito, così il risultato di una sezione NON compare nelle altre e non va perso
  // cambiando sezione. Si azzera solo con una nuova analisi nella stessa modalità
  // (o alla chiusura dell'app, quando lo stato torna vuoto).
  const [states, setStates] = useState<Record<Mode, ModeState>>({
    profile: EMPTY_STATE,
    bio: EMPTY_STATE,
    image: EMPTY_STATE,
  });
  const patchState = (m: Mode, p: Partial<ModeState>) =>
    setStates((s) => ({ ...s, [m]: { ...s[m], ...p } }));
  // Valori della modalità attualmente visualizzata (li usa la colonna dei risultati).
  const { result, error, jobStatus, loading: isLoading, source } = states[mode];

  // ─── Ricalcolo interattivo del rischio ("e se non l'avessi pubblicato?" + conferma
  // dei rilevamenti incerti). `excluded` = indici delle PII NON conteggiate; `live` =
  // valutazione ricalcolata dal server sul sottoinsieme scelto (null = quella originale). ───
  const [excluded, setExcluded] = useState<Set<number>>(new Set());
  const [live, setLive] = useState<RiskAssessment | null>(null);
  const [rescoring, setRescoring] = useState(false);
  // Priorità di bonifica: leva (calo dello score) di ciascuna PII se rimossa.
  const [leverage, setLeverage] = useState<{ base_score: number; items: { type: string; text: string; delta: number }[] } | null>(null);
  // Esempio didattico del messaggio d'attacco (on-demand, via Ollama).
  // null = non richiesto; {message} = esito (message vuoto + reason per la diagnosi).
  const [attackExample, setAttackExample] = useState<{ message: string; reason: string } | null>(null);
  const [loadingExample, setLoadingExample] = useState(false);
  // Versione sicura della bio (feature "bio ripulita").
  const [sanitized, setSanitized] = useState<{ cleaned_text: string; score: number; risk_level: string; removed_types: string[]; kept_types: string[] } | null>(null);
  const [sanitizing, setSanitizing] = useState(false);
  // Espansione della lista di etichette visive (Rekognition ne restituisce decine).
  const [showAllLabels, setShowAllLabels] = useState(false);
  // Espansione delle combinazioni/attacchi sulla mappa dell'aggregazione.
  const [showAllCombos, setShowAllCombos] = useState(false);
  // Feedback visivo del drag & drop sull'area di caricamento immagine.
  const [dragOver, setDragOver] = useState(false);
  const analysisId = result?.analysis_id;

  // Al cambio di risultato (nuova analisi o cambio modalità) reimposta la selezione:
  // di default sono escluse le PII sotto la soglia di confidenza, così il punteggio
  // di partenza coincide con quello calcolato dal server.
  useEffect(() => {
    const pii = result?.detected_pii;
    const ac = new AbortController();
    if (pii) {
      const init = new Set<number>();
      pii.forEach((p, i) => {
        if (p.score < CONFIDENCE_FLOOR) init.add(i);
      });
      setExcluded(init);
      // Priorità di bonifica: chiede al server la leva di ogni PII (una chiamata).
      // `signal`: se l'analisi cambia mentre la fetch è in volo, la risposta vecchia
      // viene annullata e non sovrascrive la leva di quella nuova.
      fetch("/api/leverage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ detected_pii: pii }),
        signal: ac.signal,
      })
        .then((r) => (r.ok ? r.json() : null))
        .then(setLeverage)
        .catch(() => { if (!ac.signal.aborted) setLeverage(null); });
    } else {
      setExcluded(new Set());
      setLeverage(null);
    }
    setLive(null);
    setSanitized(null);
    setAttackExample(null);
    return () => ac.abort();
  }, [analysisId]);

  // Chiede al backend una riscrittura della bio senza PII + il rischio ricalcolato.
  const sanitizeBio = async () => {
    if (source?.kind !== "bio") return;
    setSanitizing(true);
    try {
      const res = await fetch("/api/sanitize-bio", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Passa le PII gia' rilevate: il backend non ri-esegue il NER (spaCy pesa troppo
        // per il web tier). Vedi SanitizeRequest.
        body: JSON.stringify({ text: source.text, detected_pii: result?.detected_pii || [] }),
      });
      if (res.ok) setSanitized(await res.json());
    } catch (err) {
      console.error("Sanitize error:", err);
    } finally {
      setSanitizing(false);
    }
  };

  // Chiede al server il ricalcolo sul sottoinsieme conteggiato. Endpoint sincrono e
  // senza I/O esterna: risponde subito, adatto a ogni click.
  const runRescore = async (nextExcluded: Set<number>) => {
    const pii = result?.detected_pii;
    if (!pii) return;
    const counted = pii.filter((_, i) => !nextExcluded.has(i));
    setRescoring(true);
    try {
      const res = await fetch("/api/rescore", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ detected_pii: counted }),
      });
      if (res.ok) setLive(await res.json());
    } catch (err) {
      console.error("Rescore error:", err);
    } finally {
      setRescoring(false);
    }
  };

  // Conteggia/esclude una PII e ricalcola. Vale sia per il contro-fattuale (togliere
  // un dato certo) sia per la conferma di un rilevamento incerto (includerne uno sotto soglia).
  const togglePii = (i: number) => {
    setExcluded((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      runRescore(next);
      return next;
    });
  };

  // Esempio didattico del messaggio d'attacco per il vettore più grave (on-demand, Ollama).
  const fetchAttackExample = async () => {
    const pii = result?.detected_pii || [];
    const vector = result?.social_engineering_report?.[0]?.threat_vector || "";
    if (!pii.length || !vector) return;
    setLoadingExample(true);
    try {
      const res = await fetch("/api/attack-example", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pii, vector_label: vector }),
      });
      const data = await res.json();
      setAttackExample({ message: data.message || "", reason: data.reason || "" });
    } catch {
      setAttackExample({ message: "", reason: "no_response" });
    } finally {
      setLoadingExample(false);
    }
  };

  // Ferma il polling in corso. Centralizzato perché serve a più handler
  // (cambio modalità, pulisci, esito COMPLETED/FAILED, smontaggio del componente).
  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };
  // Riporta la modalità corrente allo stato iniziale (nessun esito, nessun errore).
  const resetOutcome = () => patchState(mode, EMPTY_STATE);

  // Allo smontaggio, interrompe un eventuale polling attivo.
  useEffect(() => stopPolling, []);

  // Riempie la textarea della biografia con un esempio pronto (modalità "bio").
  const applyTemplate = (index: number) => {
    setScrapedContent(DEMO_PROFILES[index].content);
    setActiveTemplate(index);
    patchState("bio", { error: null });
  };

  // Polling dello stato del job. 'm' identifica la modalità che ha avviato
  // l'analisi, così l'esito viene scritto NELLO stato di quella sezione anche se
  // nel frattempo l'utente ne sta guardando un'altra.
  const startPolling = (analysisId: string, m: Mode) => {
    stopPolling();
    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/analysis/${analysisId}`);
        if (!res.ok) throw new Error(`Polling error: ${res.status}`);
        const data: AnalysisResult = await res.json();
        patchState(m, { jobStatus: data.status });
        if (data.status === "COMPLETED") {
          stopPolling();
          patchState(m, { result: data, loading: false });
        } else if (data.status === "FAILED") {
          stopPolling();
          patchState(m, { error: data.error || "Analisi non riuscita.", loading: false });
        }
      } catch (err) {
        console.error("Polling error:", err); // errori di rete temporanei: continua il polling
      }
    }, 3000);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    // Campo vuoto: non si parte (il bottone è comunque disabilitato). Guardia.
    if (!socialUrl.trim()) return;
    patchState("profile", {
      loading: true, error: null, result: null, jobStatus: "PENDING",
      source: { kind: "profile", url: socialUrl.trim() },
    });
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Modalità profilo: si analizzano i dati reali restituiti dallo scraping,
        // quindi NON si invia testo manuale (scraped_content = null).
        body: JSON.stringify({ social_url: socialUrl, scraped_content: null }),
      });
      if (!response.ok) throw new Error(`Il server ha risposto ${response.status}.`);
      const job = await response.json();
      startPolling(job.analysis_id, "profile");
    } catch (err: any) {
      console.error(err);
      patchState("profile", {
        error: err.message || "Impossibile raggiungere il servizio di analisi. Riprova più tardi.",
        loading: false,
        jobStatus: null,
      });
    }
  };

  // Analisi di un testo di biografia incollato manualmente: NON fa scraping,
  // passa direttamente il testo come scraped_content sullo stesso endpoint
  // (controllo pre-pubblicazione: "quanto è sicuro ciò che scrivo in bio?").
  const handleAnalyzeBio = async (e: React.FormEvent) => {
    e.preventDefault();
    // Testo vuoto: non si parte, senza mostrare errori (il bottone è comunque
    // disabilitato in questo caso; guardia di sicurezza, coerente con profilo/immagine).
    if (!scrapedContent.trim()) return;
    patchState("bio", {
      loading: true, error: null, result: null, jobStatus: "PENDING",
      source: { kind: "bio", text: scrapedContent.trim() },
    });
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ social_url: "Biografia inserita", scraped_content: scrapedContent }),
      });
      if (!response.ok) throw new Error(`Il server ha risposto ${response.status}.`);
      const job = await response.json();
      startPolling(job.analysis_id, "bio");
    } catch (err: any) {
      console.error(err);
      patchState("bio", {
        error: err.message || "Impossibile raggiungere il servizio di analisi. Riprova più tardi.",
        loading: false,
        jobStatus: null,
      });
    }
  };

  // Analisi da immagine: carica il file su /api/analyze-image (OCR Textract lato
  // backend), poi riusa lo stesso polling del flusso testuale.
  const handleImageUpload = async (file: File) => {
    // Rilascia l'anteprima precedente (object URL) prima di crearne una nuova,
    // così i blob delle immagini analizzate in precedenza non restano orfani in
    // memoria del browser.
    const prev = states.image.source;
    if (prev?.kind === "image") URL.revokeObjectURL(prev.preview);
    patchState("image", {
      loading: true, error: null, result: null, jobStatus: "PENDING",
      source: { kind: "image", name: file.name, preview: URL.createObjectURL(file) },
    });
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch("/api/analyze-image", { method: "POST", body: fd });
      if (!res.ok) {
        let msg = `Il server ha risposto ${res.status}.`;
        try {
          const j = await res.json();
          if (j.detail) msg = j.detail; // messaggio chiaro dal backend (es. "Nessun testo leggibile")
        } catch {
          /* corpo non JSON: usa il messaggio generico */
        }
        throw new Error(msg);
      }
      const job = await res.json();
      startPolling(job.analysis_id, "image");
    } catch (err: any) {
      console.error(err);
      patchState("image", {
        error: err.message || "Caricamento immagine non riuscito.",
        loading: false,
        jobStatus: null,
      });
    }
  };

  // Cambio modalità: mostra soltanto la sezione scelta. Ogni modalità ha il suo
  // stato (risultato/errore/caricamento), quindi cambiando sezione si vede il suo
  // esito precedente (o nulla) e mai quello di un'altra: nessun travaso.
  const selectMode = (m: Mode) => {
    if (m !== mode) setMode(m);
  };

  // Scarica l'ultimo report come PDF (nessun login: l'utente conserva in locale
  // i report che ritiene utili). Generazione interamente client-side.
  const downloadReport = async () => {
    if (!result || !result.risk_assessment) return;
    // jsPDF caricato solo qui (dynamic import): non pesa sul bundle iniziale.
    const { jsPDF } = await import("jspdf");
    // Il report segue la SIMULAZIONE corrente: se l'utente ha escluso/confermato
    // dati, verdetto, combo e routine riflettono quella selezione (live), non
    // l'analisi originale. I vettori LLM e la sintesi restano quelli del
    // rilevamento completo (non vengono ricalcolati sul sottoinsieme).
    const assessment = live ?? result.risk_assessment;
    const r = riskInfo(assessment.risk_level);
    const pii = result.detected_pii || [];
    const threats = result.social_engineering_report || [];
    const riskColor: [number, number, number] =
      r.key === "high" ? [220, 38, 38] : r.key === "med" ? [217, 119, 6] : [22, 163, 74];

    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 48;
    const width = pageW - margin * 2;
    let y = margin;

    const ensure = (h: number) => {
      if (y + h > pageH - margin) {
        doc.addPage();
        y = margin;
      }
    };
    // Scrive un blocco di testo con a-capo automatico e colore/dimensione dati.
    const write = (str: string, size = 11, bold = false, color: [number, number, number] = [40, 40, 40], gap = 1.4) => {
      doc.setFont("helvetica", bold ? "bold" : "normal");
      doc.setFontSize(size);
      doc.setTextColor(color[0], color[1], color[2]);
      doc.splitTextToSize(str, width).forEach((ln: string) => {
        ensure(size * gap);
        doc.text(ln, margin, y);
        y += size * gap;
      });
    };
    const space = (h = 8) => { y += h; };
    const heading = (str: string) => {
      space(10);
      write(str, 12, true, [17, 17, 17]);
      space(4);
    };

    write("Social Privacy Detector", 18, true, [17, 17, 17]);
    write("Report di analisi dell'esposizione pubblica", 11, false, [110, 110, 110]);
    space(10);
    write(`Profilo / sorgente: ${result.social_url}`, 10, false, [90, 90, 90]);
    write(`ID analisi: ${result.analysis_id}`, 10, false, [90, 90, 90]);
    write(`Data: ${new Date().toLocaleString("it-IT")}`, 10, false, [90, 90, 90]);

    heading("Verdetto");
    write(`Rischio ${r.label.toLowerCase()} — ${assessment.score}/100`, 14, true, riskColor);
    if (live) {
      space(1);
      write(
        "Punteggio simulato sulla selezione dei dati fatta dall'utente. I vettori di attacco e la sintesi si riferiscono al rilevamento completo.",
        8.5, false, [140, 140, 140]
      );
    }
    if (assessment.explanation) {
      space(2);
      write(assessment.explanation, 10, false, [60, 60, 60]);
    }

    if (assessment.combos && assessment.combos.length) {
      heading(assessment.combos.length > 1 ? "Combinazioni a rischio" : "Combinazione a rischio");
      assessment.combos.forEach((c) =>
        write(
          `${c.types.map(graphLabel).join(" + ")}  →  ${comboLabel(c.label)}  (+${c.points} pt)`,
          10, true, riskColor
        )
      );
      write("Presi singolarmente questi dati sono innocui: è la loro combinazione ad abilitare l'attacco.", 9.5, false, [90, 90, 90]);
    }

    if (assessment.repetitions && assessment.repetitions.length) {
      heading("Segnale di routine");
      assessment.repetitions.forEach((rep) =>
        write(`•  ${rep.text}  ×${rep.count}  —  ${rep.label}`, 10, false, [55, 55, 55])
      );
    }

    if (result.narrative_summary) {
      heading("Sintesi dell'esposizione");
      write(result.narrative_summary, 10, false, [60, 60, 60]);
    }

    heading(`Dati personali rilevati (${pii.length})`);
    if (pii.length) {
      pii.forEach((e, i) =>
        write(
          `•  ${piiMeta(e.type).label} [${e.type}]: ${e.text}  —  conf. ${(e.score * 100).toFixed(0)}%${excluded.has(i) ? "  (escluso dal punteggio)" : ""}`,
          10, false, [55, 55, 55]
        )
      );
    } else {
      write("Nessun dato personale leggibile.", 10, false, [110, 110, 110]);
    }

    const labels = result.image_labels || [];
    if (labels.length) {
      // Sensibili prima, poi per confidenza; cap per non riempire il report di rumore
      // (abiti, cibo, scene). Il resto è indicato come conteggio.
      const PDF_CAP = 20;
      const sortedLabels = [...labels].sort(
        (a, b) =>
          Number(isSensitiveVisual(b.name)) - Number(isSensitiveVisual(a.name)) || b.confidence - a.confidence
      );
      const shownL = sortedLabels.slice(0, PDF_CAP);
      heading(`Esposizione visiva (${labels.length})`);
      write(
        shownL.map((l) => `${l.name} (${l.confidence.toFixed(0)}%)`).join(",  ") +
          (labels.length > PDF_CAP ? `  … +${labels.length - PDF_CAP} altre` : ""),
        10,
        false,
        [55, 55, 55]
      );
    }

    heading(`Vettori di Social Engineering (${threats.length})`);
    threats.forEach((t) => {
      write(`[${t.severity}]  ${t.threat_vector}`, 10.5, true, [40, 40, 40]);
      write(t.explanation, 10, false, [70, 70, 70]);
      space(3);
    });

    space(12);
    write(
      "Generato da Social Privacy Detector — SDCC, Università della Calabria. Analisi basata esclusivamente su contenuti pubblici.",
      8.5,
      false,
      [140, 140, 140]
    );

    doc.save(`report-${result.analysis_id.slice(0, 8)}.pdf`);
  };

  const handleClear = () => {
    stopPolling();
    setSocialUrl("");
    setScrapedContent("");
    setActiveTemplate(null);
    setShowExamples(false);
    setImageFile(null);
    resetOutcome();
  };

  const risk = result?.risk_assessment ? riskInfo(result.risk_assessment.risk_level) : null;
  const piiList = result?.detected_pii || [];
  const threats = result?.social_engineering_report || [];

  // Valutazione MOSTRATA: quella ricalcolata dal vivo se l'utente ha modificato la
  // selezione, altrimenti l'originale. Gauge, verdetto, mappa e motivazioni la seguono.
  const baseAssessment = result?.risk_assessment || null;
  const shownAssessment = live ?? baseAssessment;
  const shownRisk = shownAssessment ? riskInfo(shownAssessment.risk_level) : risk;
  const shownKey: RiskKey = shownRisk ? shownRisk.key : "low";
  const scoreDelta = (shownAssessment?.score ?? 0) - (baseAssessment?.score ?? 0);
  // Tipi distinti tra i dati attualmente CONTEGGIATI: la mappa li disegna tutti e
  // collega all'attacco solo quelli della combo (coerente con la simulazione live).
  const countedTypes = Array.from(new Set(piiList.filter((_, i) => !excluded.has(i)).map((p) => p.type)));

  return (
    <div className="min-h-screen bg-bg text-ink flex flex-col">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-line bg-bg/85 backdrop-blur">
        <div className="max-w-6xl mx-auto px-5 sm:px-8">
          <div className="h-16 flex items-center justify-between gap-3">
            {/* Identità: mark del brand + wordmark. */}
            <div className="flex items-center gap-3 min-w-0">
              <img
                src={logoUrl}
                alt="Logo Social Privacy Detector"
                width={40}
                height={40}
                className="w-10 h-10 rounded-lg shrink-0 ring-1 ring-line"
              />
              <div className="leading-tight min-w-0">
                <div className="text-[10px] font-mono uppercase tracking-widest text-faint truncate">
                  Università della Calabria · SDCC 25/26
                </div>
                <h1 className="font-display text-[15px] sm:text-[17px] font-bold tracking-tight truncate">Social Privacy Detector</h1>
              </div>
            </div>

            {/* Gruppo destro: tab (da tablet in su) + tema */}
            <div className="flex items-center gap-2.5 shrink-0">
              <ModeTabs mode={mode} onSelect={selectMode} className="hidden sm:flex" />
              <button
                type="button"
                onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
                aria-label={theme === "dark" ? "Passa al tema chiaro" : "Passa al tema scuro"}
                className="grid place-items-center w-9 h-9 rounded-xl border border-line bg-surface text-muted hover:text-ink transition-colors shrink-0"
              >
                {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Su mobile i tab vanno su una riga propria a piena larghezza (nell'header non entrano). */}
          <ModeTabs mode={mode} onSelect={selectMode} className="sm:hidden w-full mb-3" />
        </div>
      </header>

      <main className="w-full flex-1 max-w-6xl mx-auto px-5 sm:px-8 py-8 sm:py-10">
        {/* ── Intro ─────────────────────────────────────────────────────────── */}
        <section className="mb-8 max-w-2xl">
          {mode === "profile" ? (
            <>
              <h2 className="font-display text-3xl sm:text-[38px] leading-[1.1] font-extrabold tracking-tight">
                Quanto è esposto il tuo profilo social?
              </h2>
              <p className="text-muted text-sm sm:text-base leading-relaxed mt-3">
                Da una biografia e pochi post, un estraneo può ricostruire chi sei, dove vivi e come
                contattarti. Individua i dati personali esposti, i possibili attacchi e un punteggio di rischio.
              </p>
            </>
          ) : mode === "bio" ? (
            <>
              <h2 className="font-display text-3xl sm:text-[38px] leading-[1.1] font-extrabold tracking-tight">
                Cosa esponi nella tua biografia?
              </h2>
              <p className="text-muted text-sm sm:text-base leading-relaxed mt-3">
                Prima di scriverlo nel profilo, incolla il testo della bio e verifica quali dati personali
                riveleresti — e quanto rischio comportano — senza pubblicarlo davvero.
              </p>
            </>
          ) : (
            <>
              <h2 className="font-display text-3xl sm:text-[38px] leading-[1.1] font-extrabold tracking-tight">
                Un'immagine può rivelare più di quanto pensi.
              </h2>
              <p className="text-muted text-sm sm:text-base leading-relaxed mt-3">
                Prima di pubblicare una foto — uno screenshot, un documento, un biglietto — controlla il testo
                visibile: l'OCR lo estrae e ne analizza l'esposizione di dati personali.
              </p>
            </>
          )}
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* ── Colonna sinistra: input (dipende dalla modalità) ────────────── */}
          <div className="lg:col-span-5 space-y-5 lg:sticky lg:top-20 lg:self-start">
            {mode === "profile" && (
            <div className="space-y-5">
            <form onSubmit={handleAnalyze} className="rounded-2xl border border-line bg-surface shadow-soft p-6 space-y-5">
              <div className="space-y-2">
                <label htmlFor="social-url" className="block text-sm font-semibold">
                  Profilo social
                </label>
                <div className="relative">
                  <Search className="w-4 h-4 text-faint absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    id="social-url"
                    type="url"
                    required
                    value={socialUrl}
                    onChange={(e) => {
                      setSocialUrl(e.target.value);
                      setActiveTemplate(null);
                    }}
                    placeholder="https://instagram.com/nome.utente"
                    className="w-full rounded-xl border border-line bg-bg py-2.5 pl-10 pr-3 text-sm font-mono placeholder:text-faint focus:border-accent transition-colors"
                  />
                </div>
              </div>

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={handleClear}
                  disabled={isLoading}
                  className="w-1/3 rounded-xl border border-line py-2.5 text-sm font-semibold text-muted hover:text-ink hover:bg-surface2 transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
                >
                  <Trash2 className="w-4 h-4" />
                  Pulisci
                </button>
                <button
                  type="submit"
                  disabled={isLoading || !socialUrl.trim()}
                  className="w-2/3 rounded-xl bg-accent text-accentink py-2.5 text-sm font-bold hover:opacity-90 transition-opacity flex items-center justify-center gap-2 disabled:opacity-60 shadow-soft"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Analisi in corso…
                    </>
                  ) : (
                    <>
                      Analizza profilo
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </form>

            </div>
            )}

            {mode === "bio" && (
            <div className="space-y-5">
              <div className="rounded-2xl border border-line bg-surface shadow-soft p-6 space-y-3">
                <h2 className="font-display text-lg font-bold">Analizza una biografia</h2>
                <p className="text-sm text-muted">
                  Incolla il testo che vorresti mettere nella tua bio: viene analizzato per rilevare i dati
                  personali esposti e stimarne il rischio — senza pubblicarlo davvero.
                </p>
                <form onSubmit={handleAnalyzeBio} className="space-y-3">
                  <textarea
                    aria-label="Testo della biografia"
                    rows={7}
                    value={scrapedContent}
                    onChange={(e) => setScrapedContent(e.target.value)}
                    placeholder="Es. Studente di Ingegneria a Cosenza, nato il 12/05/1999. Scrivimi a mario.rossi@example.com"
                    className="w-full rounded-xl border border-line bg-bg p-3.5 text-sm leading-relaxed placeholder:text-faint focus:border-accent transition-colors resize-y"
                  />
                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={handleClear}
                      disabled={isLoading}
                      className="w-1/3 rounded-xl border border-line py-2.5 text-sm font-semibold text-muted hover:text-ink hover:bg-surface2 transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
                    >
                      <Trash2 className="w-4 h-4" />
                      Pulisci
                    </button>
                    <button
                      type="submit"
                      disabled={isLoading || !scrapedContent.trim()}
                      className="w-2/3 rounded-xl bg-accent text-accentink py-2.5 text-sm font-bold hover:opacity-90 transition-opacity flex items-center justify-center gap-2 disabled:opacity-60 shadow-soft"
                    >
                      {isLoading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Analisi in corso…
                        </>
                      ) : (
                        <>
                          Analizza biografia
                          <ArrowRight className="w-4 h-4" />
                        </>
                      )}
                    </button>
                  </div>
                </form>
              </div>

              {/* Esempi di biografia pronti (collassabili, chiusi di default) */}
              <div className="rounded-2xl border border-line bg-surface shadow-soft p-6">
                <button
                  type="button"
                  onClick={() => setShowExamples((v) => !v)}
                  className="w-full flex items-center justify-between text-[11px] uppercase tracking-wider text-muted font-semibold hover:text-ink transition-colors"
                >
                  <span>Esempi di biografia</span>
                  <ChevronDown className={`w-4 h-4 transition-transform ${showExamples ? "rotate-180" : ""}`} />
                </button>
                <div className={`space-y-2 ${showExamples ? "mt-3" : "hidden"}`}>
                  {DEMO_PROFILES.map((p, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => applyTemplate(idx)}
                      className={`w-full text-left rounded-xl px-3.5 py-2.5 text-sm border transition-colors flex items-center justify-between gap-2 ${
                        activeTemplate === idx ? "border-accent bg-accent/5 text-ink" : "border-line hover:bg-surface2"
                      }`}
                    >
                      <span>{p.label}</span>
                      <ArrowRight
                        className={`w-4 h-4 shrink-0 ${activeTemplate === idx ? "text-accent" : "text-faint"}`}
                      />
                    </button>
                  ))}
                </div>
              </div>
            </div>
            )}

            {mode === "image" && (
              <div className="rounded-2xl border border-line bg-surface shadow-soft p-6 space-y-3">
                <h2 className="font-display text-lg font-bold">Analizza un'immagine</h2>
                <p className="text-sm text-muted">
                  Carica uno screenshot o la foto di un documento: il testo visibile viene estratto con OCR
                  (Amazon Textract) e analizzato per rilevare eventuali dati personali esposti.
                </p>

                {/* Selezione dell'immagine: alla selezione NON parte l'analisi, si
                    memorizza soltanto il file; l'analisi parte al click su "Analizza". */}
                {!imageFile ? (
                  <label
                    onDragOver={(e) => {
                      e.preventDefault();
                      setDragOver(true);
                    }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setDragOver(false);
                      const f = e.dataTransfer.files?.[0];
                      if (f && f.type.startsWith("image/")) setImageFile(f); // solo selezione
                    }}
                    className={`flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed py-10 text-sm font-semibold cursor-pointer transition-colors ${
                      dragOver
                        ? "border-accent bg-accent/5 text-ink"
                        : "border-line text-muted hover:text-ink hover:border-accent hover:bg-surface2"
                    }`}
                  >
                    <ScanText className="w-6 h-6" />
                    {dragOver ? "Rilascia qui l'immagine" : "Carica immagine o trascinala qui"}
                    <span className="text-xs font-normal text-faint">PNG o JPEG · max 5 MB</span>
                    <input
                      type="file"
                      accept="image/*"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) setImageFile(f); // solo selezione, niente analisi automatica
                        e.target.value = ""; // consente di riselezionare lo stesso file
                      }}
                    />
                  </label>
                ) : (
                  <div className="space-y-3">
                    {/* Riquadro: conferma che l'immagine è stata caricata */}
                    <div className="flex items-center gap-3 rounded-xl border border-line bg-surface2 p-3.5">
                      <div className="grid place-items-center w-9 h-9 rounded-lg bg-accent/10 text-accent shrink-0">
                        <ScanText className="w-4 h-4" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-semibold truncate">{imageFile.name}</div>
                        <div className="text-xs text-muted">
                          {(imageFile.size / 1024).toFixed(0)} KB · immagine caricata
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setImageFile(null)}
                        disabled={isLoading}
                        aria-label="Rimuovi immagine"
                        className="grid place-items-center w-8 h-8 rounded-lg border border-line text-muted hover:text-high hover:bg-surface transition-colors disabled:opacity-50 shrink-0"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                    {/* Bottone esplicito: fa partire l'analisi */}
                    <button
                      type="button"
                      onClick={() => handleImageUpload(imageFile)}
                      disabled={isLoading}
                      className="w-full rounded-xl bg-accent text-accentink py-2.5 text-sm font-bold hover:opacity-90 transition-opacity flex items-center justify-center gap-2 disabled:opacity-60 shadow-soft"
                    >
                      {isLoading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Analisi in corso…
                        </>
                      ) : (
                        <>
                          Analizza immagine
                          <ArrowRight className="w-4 h-4" />
                        </>
                      )}
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Uso consentito. Sta sotto il form, non nel footer: va letta prima di
                avviare un'analisi, non dopo. */}
            <div className="rounded-2xl border border-line bg-surface shadow-soft p-6 text-sm">
              <span className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted font-semibold mb-3">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                Uso consentito
              </span>
              <p className="text-muted leading-relaxed">
                La piattaforma è destinata <span className="text-ink font-semibold">esclusivamente
                all'analisi dei propri dati personali</span>. L'acquisizione e l'analisi di dati
                personali di terzi esulano dalle finalità del servizio e ricadono sotto la
                responsabilità esclusiva di chi le effettua, non dello sviluppatore della
                piattaforma.
              </p>
            </div>
          </div>

          {/* ── Colonna destra: risultati ───────────────────────────────────── */}
          <div className="lg:col-span-7 space-y-5">
            {/* Oggetto dell'analisi corrente: link (profilo), testo (bio) o anteprima (immagine) */}
            {source && (
              <div className="rounded-2xl border border-line bg-surface shadow-soft p-5">
                <div className="text-[11px] uppercase tracking-wider text-muted font-semibold mb-2.5">
                  Analisi di
                </div>
                {source.kind === "profile" && (
                  <a
                    href={source.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 text-sm font-mono text-accent break-all hover:underline"
                  >
                    <Link2 className="w-4 h-4 shrink-0" />
                    {source.url}
                  </a>
                )}
                {source.kind === "bio" && (
                  <>
                    <p className="text-sm text-muted leading-relaxed whitespace-pre-wrap max-h-40 overflow-y-auto">
                      {result?.detected_pii && result.detected_pii.length > 0
                        ? highlightPii(source.text, result.detected_pii)
                        : source.text}
                    </p>
                    {result?.detected_pii && result.detected_pii.length > 0 && (
                      <p className="text-[11px] text-faint mt-2 flex items-center gap-1.5">
                        <Info className="w-3 h-3 shrink-0" />
                        Evidenziati i frammenti riconosciuti come dati personali (passa sopra per il tipo).
                      </p>
                    )}
                  </>
                )}
                {source.kind === "image" && (
                  <div className="flex items-center gap-3">
                    <img
                      src={source.preview}
                      alt={source.name}
                      className="w-16 h-16 rounded-lg object-cover border border-line shrink-0"
                    />
                    <span className="text-sm font-mono text-muted break-all">{source.name}</span>
                  </div>
                )}
              </div>
            )}

            {error && (
              <div className="rounded-2xl border border-high/40 bg-high/10 shadow-soft p-5 flex gap-3 items-start" role="alert">
                <AlertTriangle className="w-5 h-5 text-high shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h3 className="text-sm font-bold text-high">Analisi non riuscita</h3>
                  <p className="text-sm text-muted leading-relaxed">{error}</p>
                </div>
              </div>
            )}

            {isLoading && jobStatus && !result && (
              <div className="rounded-2xl border border-line bg-surface shadow-soft p-10 text-center">
                <div className="relative w-14 h-14 mx-auto mb-5">
                  <div className="absolute inset-0 rounded-full border-2 border-line" />
                  <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-accent animate-spin" />
                  <Cpu className="w-5 h-5 absolute inset-0 m-auto text-accent" />
                </div>
                <h3 className="font-display font-bold">
                  {jobStatus === "PENDING" ? "Richiesta in coda" : "Elaborazione in corso"}
                </h3>
                <p className="text-sm text-muted max-w-sm mx-auto mt-1.5 leading-relaxed">
                  {jobStatus === "PENDING"
                    ? "La richiesta è stata accodata e verrà elaborata a breve."
                    : "Recupero del testo pubblico, rilevamento dei dati personali e calcolo del rischio."}
                </p>
                <div className="flex flex-wrap items-center justify-center gap-1.5 mt-5">
                  {["Recupero testo", "Dati personali", "Punteggio", "Report"].map((step, idx) => (
                    <React.Fragment key={step}>
                      <span
                        className={`text-[11px] font-medium rounded-lg px-2.5 py-1 border ${
                          jobStatus === "PROCESSING" && idx <= 1 ? "border-accent text-accent" : "border-line text-faint"
                        }`}
                      >
                        {step}
                      </span>
                      {idx < 3 && <ChevronRight className="w-3.5 h-3.5 text-faint" />}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}

            {result && result.status === "COMPLETED" && result.risk_assessment && risk ? (
              <>
                {/* Barra azioni: scarica il report. Nota: il PDF rispecchia la SELEZIONE
                    corrente dei dati (esclusioni/conferme), non l'analisi iniziale — reso
                    esplicito qui perché non sia ambiguo per l'utente. */}
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <p className="text-xs text-muted max-w-md flex items-start gap-1.5">
                    <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    {live
                      ? "Il report rispecchia i dati che hai selezionato (simulazione in corso), non l'analisi iniziale."
                      : "Il report rispecchia i dati attualmente conteggiati: se ne escludi o confermi qualcuno più sotto, il PDF si adegua."}
                  </p>
                  <button
                    type="button"
                    onClick={downloadReport}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-line py-2 px-3 text-sm font-semibold text-muted hover:text-ink hover:bg-surface2 transition-colors shrink-0"
                  >
                    <Download className="w-4 h-4" />
                    Scarica report
                  </button>
                </div>

                {/* KPI Summary (stile reference) */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                  <StatCard
                    Icon={Gauge}
                    tone={shownKey}
                    label="Punteggio"
                    value={`${shownAssessment?.score ?? 0}`}
                    sub={scoreDelta !== 0 ? `/ 100 · ${scoreDelta > 0 ? "+" : ""}${scoreDelta} vs originale` : "/ 100"}
                  />
                  <StatCard Icon={Eye} label="Dati esposti" value={piiList.length} sub={piiList.length === 1 ? "elemento" : "elementi"} />
                  <StatCard Icon={Target} label="Vettori d'attacco" value={threats.length} sub={threats.length === 1 ? "scenario" : "scenari"} />
                </div>

                {/* Verdetto: gauge + spiegazione (segue la valutazione MOSTRATA, che
                    cambia dal vivo quando l'utente esclude/conferma un dato più sotto) */}
                <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6">
                  <div className="flex items-center gap-5">
                    <ScoreGauge score={shownAssessment?.score ?? 0} riskKey={shownKey} />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <ShieldAlert className={`w-4 h-4 ${RISK_TEXT[shownKey]}`} />
                        <span className="text-[11px] uppercase tracking-wider text-muted font-semibold">Verdetto</span>
                        {live && (
                          <span className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 text-accent px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider">
                            {scoreDelta < 0 ? <TrendingDown className="w-3 h-3" /> : scoreDelta > 0 ? <TrendingUp className="w-3 h-3" /> : null}
                            Simulazione {scoreDelta > 0 ? `+${scoreDelta}` : scoreDelta}
                          </span>
                        )}
                      </div>
                      <div className={`font-display text-2xl font-extrabold ${RISK_TEXT[shownKey]}`}>
                        Rischio {(shownRisk?.label || "").toLowerCase()}
                      </div>
                      <p className="text-sm text-muted leading-relaxed mt-1.5">{shownAssessment?.explanation}</p>
                    </div>
                  </div>

                </div>

                {/* Identità ricomposta: i frammenti, uniti, ricostruiscono la persona */}
                {result.attacker_dossier && result.attacker_dossier.text && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.07s" }}>
                    <div className="flex items-center gap-2 mb-2">
                      <Fingerprint className="w-4 h-4 text-accent" />
                      <h3 className="font-display font-bold">Identità ricomposta</h3>
                    </div>
                    <p className="text-sm leading-relaxed">{result.attacker_dossier.text}</p>
                    {result.attacker_dossier.missing.length > 0 && (
                      <p className="text-[13px] text-muted mt-3">Per completare il quadro mancherebbero: {result.attacker_dossier.missing.join(", ")}.</p>
                    )}
                  </div>
                )}

                {/* Mappa dell'aggregazione: i dati banali, combinati, abilitano attacchi.
                    Ogni combinazione è un vettore d'attacco distinto: contano tutte. */}
                {shownAssessment?.combos && shownAssessment.combos.length > 0 && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.02s" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <Share2 className={`w-4 h-4 ${RISK_TEXT[shownKey]}`} />
                      <h3 className="font-display font-bold">Mappa dell'aggregazione</h3>
                    </div>
                    <p className="text-sm text-muted mb-3">
                      Presi singolarmente questi dati sono innocui. È la loro <em>combinazione</em> ad abilitare
                      attacchi mirati{shownAssessment.combos.length > 1 ? ` — qui da pochi dati nascono ${shownAssessment.combos.length} vettori d'attacco distinti.` : "."}
                    </p>
                    <div className="max-w-sm mx-auto">
                      <ComboMap
                        allTypes={countedTypes}
                        combos={shownAssessment.combos}
                        riskKey={shownKey}
                        max={showAllCombos ? shownAssessment.combos.length : MAX_MAP_COMBOS}
                      />
                    </div>
                    <ul className="mt-3 space-y-1.5">
                      {(showAllCombos ? shownAssessment.combos : shownAssessment.combos.slice(0, MAX_MAP_COMBOS)).map((c, idx) => (
                        <li key={idx} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                          <span className={`grid place-items-center w-5 h-5 rounded-full text-[10px] font-bold ${RISK_BG[shownKey]} text-white shrink-0`}>
                            {idx + 1}
                          </span>
                          <span className="text-muted">{c.types.map(graphLabel).join(" + ")} →</span>
                          <span className={`font-semibold ${RISK_TEXT[shownKey]}`}>{comboLabel(c.label)}</span>
                          <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${RISK_PILL[shownKey]}`}>
                            +{c.points} pt
                          </span>
                        </li>
                      ))}
                      {shownAssessment.combos.length > MAX_MAP_COMBOS && (
                        <li className="pl-7">
                          <button
                            type="button"
                            onClick={() => setShowAllCombos((v) => !v)}
                            className="text-xs text-accent hover:underline"
                          >
                            {showAllCombos
                              ? "mostra meno"
                              : `+ altre ${shownAssessment.combos.length - MAX_MAP_COMBOS} combinazioni`}
                          </button>
                        </li>
                      )}
                    </ul>
                  </div>
                )}

                {/* Segnale di routine: un luogo/ente ripetuto rivela un'abitudine sfruttabile */}
                {shownAssessment?.repetitions && shownAssessment.repetitions.length > 0 && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.04s" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <Repeat className="w-4 h-4 text-accent" />
                      <h3 className="font-display font-bold">Segnale di routine</h3>
                    </div>
                    <p className="text-sm text-muted mb-4">
                      Non conta solo <em>quali</em> dati esponi, ma <em>quante volte</em>: una ripetizione rivela
                      un'abitudine su cui un attaccante può contare.
                    </p>
                    <ul className="space-y-2">
                      {shownAssessment.repetitions.map((r, idx) => {
                        const Icon = piiMeta(r.type).Icon;
                        return (
                          <li key={idx} className="flex items-center gap-3 rounded-xl border border-line bg-surface2 p-3">
                            <div className="grid place-items-center w-8 h-8 rounded-lg bg-surface text-muted shrink-0">
                              <Icon className="w-4 h-4" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <span className="font-mono text-sm capitalize">{r.text}</span>
                              <span className="text-sm text-muted"> · {r.label}</span>
                            </div>
                            <span className="text-xs font-mono text-muted shrink-0 tabular-nums" title="Occorrenze rilevate">
                              ×{r.count}
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}

                {/* Decodifica del codice fiscale: mostra i dati che il CF già contiene
                    (nascita, sesso, comune) — un "singolo" dato che è in realtà un aggregato. */}
                {(() => {
                  const decoded = piiList
                    .filter((p) => p.type === "FISCAL_CODE")
                    .map((p) => ({ code: p.text, d: decodeFiscalCode(p.text) }))
                    .filter((x) => x.d);
                  if (decoded.length === 0) return null;
                  return (
                    <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.05s" }}>
                      <div className="flex items-center gap-2 mb-1">
                        <Fingerprint className={`w-4 h-4 ${RISK_TEXT[shownKey]}`} />
                        <h3 className="font-display font-bold">Cosa si legge nel codice fiscale</h3>
                      </div>
                      <p className="text-sm text-muted mb-4">
                        Il codice fiscale non è un dato singolo: <em>contiene già</em> altri dati personali,
                        deducibili senza alcuna fonte esterna.
                      </p>
                      <ul className="space-y-3">
                        {decoded.map(({ code, d }, idx) => {
                          // Comune di nascita: preferisci il NOME decodificato dall'LLM
                          // (via fiscal_code_info); in assenza mostra il codice catastale.
                          const place = result.fiscal_code_info?.find(
                            (f) => f.code.toUpperCase() === code.toUpperCase()
                          )?.birthplace;
                          return (
                            <li key={idx} className="rounded-xl border border-line bg-surface2 p-3.5">
                              <div className="font-mono text-sm break-all mb-2">{code}</div>
                              <div className="flex flex-wrap gap-x-5 gap-y-1.5 text-sm">
                                <span className="flex items-center gap-1.5">
                                  <Calendar className="w-3.5 h-3.5 text-muted" />
                                  nato/a il <span className="font-semibold">{d!.date}</span>
                                </span>
                                <span className="flex items-center gap-1.5">
                                  <User className="w-3.5 h-3.5 text-muted" />
                                  sesso <span className="font-semibold">{d!.sex === "F" ? "femminile" : "maschile"}</span>
                                </span>
                                <span className="flex items-center gap-1.5">
                                  <MapPin className="w-3.5 h-3.5 text-muted" />
                                  comune di nascita{" "}
                                  {place ? (
                                    <span className="font-semibold">{place}</span>
                                  ) : (
                                    <>
                                      <span className="font-semibold font-mono">{d!.comune}</span>
                                      <span className="text-faint">(codice catastale)</span>
                                    </>
                                  )}
                                </span>
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  );
                })()}

                {/* Sintesi narrativa generata dall'AI (quali dati esposti, pattern, perché) */}
                {result.narrative_summary && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.03s" }}>
                    <div className="flex items-center gap-2 mb-2">
                      <Sparkles className="w-4 h-4 text-accent" />
                      <h3 className="font-display font-bold">Sintesi dell'esposizione</h3>
                    </div>
                    <p className="text-sm text-muted leading-relaxed">{result.narrative_summary}</p>
                  </div>
                )}

                {/* Bio ripulita: la diagnosi diventa rimedio — una versione pubblicabile
                    senza dati sensibili, con lo score ricalcolato. Solo in modalità bio. */}
                {source?.kind === "bio" && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.07s" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <ShieldCheck className="w-4 h-4 text-low" />
                      <h3 className="font-display font-bold">Versione sicura della bio</h3>
                    </div>
                    <p className="text-sm text-muted mb-4">
                      Una riscrittura che comunica lo stesso senza i dati sensibili — e di quanto scende il rischio.
                    </p>
                    {!sanitized ? (
                      <button
                        type="button"
                        onClick={sanitizeBio}
                        disabled={sanitizing}
                        className="inline-flex items-center gap-2 rounded-xl bg-accent text-accentink py-2.5 px-4 text-sm font-bold hover:opacity-90 transition-opacity disabled:opacity-60 shadow-soft"
                      >
                        {sanitizing ? <><RefreshCw className="w-4 h-4 animate-spin" /> Riscrittura…</> : <><Sparkles className="w-4 h-4" /> Genera versione sicura</>}
                      </button>
                    ) : (
                      <div className="space-y-4">
                        <div className="rounded-xl border border-low/40 bg-low/5 p-4">
                          <p className="text-sm leading-relaxed whitespace-pre-wrap">{sanitized.cleaned_text}</p>
                          <div className="mt-3 flex flex-col gap-1 text-[13px]">
                            {sanitized.removed_types.length > 0 && (
                              <p className="text-muted"><span className="font-semibold text-high">Rimossi:</span> {sanitized.removed_types.map((t) => piiMeta(t).label).join(", ")}</p>
                            )}
                            {sanitized.kept_types.length > 0 && (
                              <p className="text-muted"><span className="font-semibold">Mantenuti:</span> {sanitized.kept_types.map((t) => piiMeta(t).label).join(", ")}</p>
                            )}
                            {sanitized.removed_types.length === 0 && (
                              <p className="text-muted">La bio era già a basso rischio: nessun dato rimosso.</p>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-4 flex-wrap">
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-muted">Rischio:</span>
                            <span className={`font-display font-extrabold ${RISK_TEXT[riskInfo(result.risk_assessment.risk_level).key]}`}>
                              {result.risk_assessment.score}
                            </span>
                            <ArrowRight className="w-4 h-4 text-faint" />
                            <span className={`font-display font-extrabold text-xl ${RISK_TEXT[riskInfo(sanitized.risk_level).key]}`}>
                              {sanitized.score}
                            </span>
                            <SeverityPill level={sanitized.risk_level} />
                          </div>
                          <button
                            type="button"
                            onClick={() => navigator.clipboard?.writeText(sanitized.cleaned_text)}
                            className="inline-flex items-center gap-1.5 rounded-xl border border-line py-1.5 px-3 text-xs font-semibold text-muted hover:text-ink hover:bg-surface2 transition-colors"
                          >
                            Copia testo
                          </button>
                        </div>
                        <p className="text-[11px] text-faint">
                          Suggerimento automatico: rileggi sempre la versione riscritta prima di usarla.
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {/* Esempio didattico del messaggio d'attacco (on-demand, via Ollama).
                    Sta accanto alla bio sanitizzata: le due facce della stessa medaglia —
                    "come ti proteggi" e "cosa rischi". Card autonoma, così resta disponibile
                    anche nelle modalità profilo/immagine (dove la bio pulita non c'è). */}
                {threats.length > 0 && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.115s" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <Eye className="w-4 h-4 text-accent" />
                      <h3 className="font-display font-bold">Come apparirebbe un attacco</h3>
                    </div>
                    <p className="text-sm text-muted mb-4">
                      Un esempio del messaggio che potresti ricevere, costruito con i tuoi dati esposti
                      per il vettore più grave.
                    </p>
                    {attackExample === null ? (
                      <button type="button" onClick={fetchAttackExample} disabled={loadingExample}
                        className="inline-flex items-center gap-2 rounded-xl border border-line px-3 py-2 text-sm hover:border-accent transition-colors disabled:opacity-60">
                        {loadingExample ? <><RefreshCw className="w-4 h-4 animate-spin" /> Genero l'esempio…</> : <><Eye className="w-4 h-4" /> Vedi come apparirebbe un messaggio d'attacco</>}
                      </button>
                    ) : !attackExample.message ? (
                      <div className="flex items-center gap-3 flex-wrap">
                        <p className="text-[13px] text-muted">
                          {attackExample.reason === "not_configured"
                            ? "Generatore non configurato (variabili PII_LLM_* assenti nel backend)."
                            : `Il modello non ha risposto${attackExample.reason && attackExample.reason !== "no_response" ? ` — ${attackExample.reason}` : ""}.`}
                        </p>
                        {attackExample.reason !== "not_configured" && (
                          <button type="button" onClick={fetchAttackExample} disabled={loadingExample}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1 text-[13px] hover:border-accent transition-colors disabled:opacity-60">
                            <RefreshCw className={`w-3.5 h-3.5 ${loadingExample ? "animate-spin" : ""}`} /> Riprova
                          </button>
                        )}
                      </div>
                    ) : (
                      <div className="rounded-xl border border-high/40 bg-high/10 p-4">
                        <div className="flex items-center gap-2 mb-2 text-high text-xs font-bold uppercase tracking-wide">
                          <AlertTriangle className="w-3.5 h-3.5" /> Esempio didattico — non operativo
                        </div>
                        <p className="text-sm leading-relaxed whitespace-pre-wrap">{attackExample.message}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Dati personali rilevati — tabella pulita in stile reference */}
                <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.06s" }}>
                  <div className="flex items-center justify-between gap-3 mb-1">
                    <h3 className="font-display font-bold">Dati personali rilevati</h3>
                    <span className="text-xs text-muted">{piiList.length} totali</span>
                  </div>
                  {piiList.length > 0 && (
                    <p className="text-xs text-muted mb-4">
                      Il valore <span className="font-mono font-bold text-high">−N</span> indica di quanto
                      scenderebbe il rischio togliendo quel dato: parti dai più alti (i dati-perno che
                      sbloccano più attacchi). Usa la casella per escluderlo o riconteggiarlo.
                      I rilevamenti troppo incerti partono esclusi: confermali per includerli.
                    </p>
                  )}

                  {piiList.length > 0 ? (
                    <ul className="divide-y divide-line -my-1">
                      {piiList.map((e, idx) => {
                        const meta = piiMeta(e.type);
                        const Icon = meta.Icon;
                        const isCounted = !excluded.has(idx);
                        const isLowConf = e.score < CONFIDENCE_FLOOR;
                        // Leva: di quanto scenderebbe il rischio rimuovendo questo dato (da /api/leverage).
                        const delta = leverage?.items.find((it) => it.type === e.type && it.text === e.text)?.delta ?? 0;
                        return (
                          <li key={idx} className={`flex items-center gap-3 py-2.5 transition-opacity ${isCounted ? "" : "opacity-45"}`}>
                            <div className="grid place-items-center w-8 h-8 rounded-lg bg-surface2 text-muted shrink-0">
                              <Icon className="w-4 h-4" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-faint font-semibold">
                                {meta.label}
                                {isLowConf && (
                                  <span className="rounded-full border border-line px-1.5 py-px text-[9px] tracking-wider text-faint normal-case">
                                    incerta
                                  </span>
                                )}
                              </div>
                              {/* Signature: il dato compare sotto una barra di redazione che si ritrae */}
                              <div className="text-sm font-mono break-all">
                                <span key={`${result.analysis_id}-${idx}`} className="redact rounded-sm select-all">
                                  {e.text}
                                  <span
                                    className="redact-bar"
                                    style={{ animationDelay: `${0.12 + idx * 0.07}s` }}
                                    aria-hidden
                                  />
                                </span>
                              </div>
                            </div>
                            {isCounted && delta > 0 && (
                              <span
                                className="text-xs font-mono font-bold text-high shrink-0 tabular-nums"
                                title={`Rimuovendolo, il rischio scende di ${delta} punti`}
                              >
                                −{delta}
                              </span>
                            )}
                            <span
                              className="text-xs font-mono text-muted shrink-0 tabular-nums"
                              title="Confidenza del rilevamento"
                            >
                              {(e.score * 100).toFixed(0)}%
                            </span>
                            <button
                              type="button"
                              onClick={() => togglePii(idx)}
                              disabled={rescoring}
                              aria-pressed={isCounted}
                              aria-label={`${meta.label} ${e.text}: ${isCounted ? "escludi dal punteggio" : "conteggia nel punteggio"}`}
                              title={isCounted ? "Escludi dal punteggio" : "Conteggia nel punteggio"}
                              className={`grid place-items-center w-7 h-7 rounded-lg border shrink-0 transition-colors disabled:opacity-50 ${
                                isCounted ? "border-accent bg-accent/10 text-accent" : "border-line text-faint hover:text-ink hover:bg-surface2"
                              }`}
                            >
                              {isCounted ? <Check className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />}
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <div className="text-center py-8">
                      <ShieldCheck className="w-8 h-8 text-low mx-auto mb-2" />
                      <p className="text-sm font-semibold">Nessun dato personale leggibile</p>
                      <p className="text-sm text-muted mt-1">Il testo analizzato non espone contatti o identificativi diretti.</p>
                    </div>
                  )}
                </div>

                {/* Esposizione visiva SENSIBILE — categorizzata dal backend (minori/documenti/geo) */}
                {result.sensitive_visual && result.sensitive_visual.length > 0 && (
                  <div className="rise rounded-2xl border border-high/40 bg-high/10 shadow-soft p-6" style={{ animationDelay: "0.085s" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <AlertTriangle className="w-4 h-4 text-high" />
                      <h3 className="font-display font-bold text-high">Esposizione visiva sensibile</h3>
                    </div>
                    <p className="text-sm text-muted mb-4">Le immagini contengono elementi direttamente sensibili, rilevati dal riconoscimento visivo.</p>
                    <div className="flex flex-wrap gap-2">
                      {result.sensitive_visual.map((s, idx) => {
                        const CAT_LABEL: Record<string, string> = { MINORI: "Minore", DOCUMENTI: "Documento", GEO: "Geolocalizzazione" };
                        return (
                          <span
                            key={idx}
                            className="inline-flex items-center gap-1 rounded-full border border-high/40 bg-high/10 text-high font-semibold px-3 py-1 text-sm"
                            title={`Confidenza ${s.confidence.toFixed(0)}%`}
                          >
                            <AlertTriangle className="w-3 h-3" />
                            {(CAT_LABEL[s.category] || s.category)} — «{s.label}» {s.confidence.toFixed(0)}%
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Esposizione visiva — etichette Amazon Rekognition dalle immagini */}
                {result.image_labels && result.image_labels.length > 0 && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.09s" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <Eye className="w-4 h-4 text-accent" />
                      <h3 className="font-display font-bold">Esposizione visiva</h3>
                    </div>
                    <p className="text-sm text-muted mb-4">Contesto dedotto dalle immagini (luoghi, oggetti, scene) tramite riconoscimento visivo.</p>
                    <div className="flex flex-wrap gap-2">
                      {/* Rekognition restituisce decine di etichette, molte irrilevanti
                          (abiti, cibo, scene): si mostrano le più confidenti, con un tetto.
                          Qui NON si evidenziano le sensibili: le possiede il riquadro
                          "Esposizione visiva sensibile" qui sopra, che le categorizza e le
                          fonde con la stima dell'età. Marcarle anche qui significava dire
                          due volte la stessa cosa con due grafiche diverse. Questo blocco
                          risponde a "cosa mostrano le foto", quello sopra a "cosa espongono". */}
                      {(() => {
                        const CAP = 14;
                        const sorted = [...result.image_labels!].sort((a, b) => b.confidence - a.confidence);
                        const visible = showAllLabels ? sorted : sorted.slice(0, CAP);
                        return (
                          <>
                            {visible.map((l, idx) => (
                              <span
                                key={idx}
                                className="inline-flex items-center gap-1 rounded-full border border-line bg-surface2 px-3 py-1 text-sm"
                                title={`Confidenza ${l.confidence.toFixed(0)}%`}
                              >
                                {l.name}
                              </span>
                            ))}
                            {sorted.length > CAP && (
                              <button
                                type="button"
                                onClick={() => setShowAllLabels((v) => !v)}
                                className="rounded-full border border-line px-3 py-1 text-sm text-muted hover:text-ink hover:bg-surface2 transition-colors"
                              >
                                {showAllLabels ? "mostra meno" : `+${sorted.length - CAP} altre`}
                              </button>
                            )}
                          </>
                        );
                      })()}
                    </div>
                    {/* Collega il visivo al testo: quando una foto geolocalizzante rafforza un
                        luogo già esposto nel testo, l'aggregazione cross-canale è esplicita. */}
                    {piiList.some((p) => p.type === "LOCATION") && result.image_labels.some((l) => isGeoVisual(l.name)) && (
                      <p className="text-[13px] text-muted mt-4 flex items-start gap-1.5">
                        <Share2 className="w-3.5 h-3.5 shrink-0 mt-0.5 text-accent" />
                        Le immagini confermano visivamente l'esposizione geografica già presente nel testo: due segnali
                        deboli che, insieme, rendono più solida la ricostruzione dei luoghi frequentati.
                      </p>
                    )}
                  </div>
                )}

                {/* Vettori d'attacco */}
                {threats.length > 0 && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.12s" }}>
                    <h3 className="font-display font-bold mb-1">Vettori di Social Engineering</h3>
                    <p className="text-sm text-muted mb-4">Come i dati esposti potrebbero essere sfruttati per un attacco mirato.</p>
                    <div className="space-y-3">
                      {threats.map((t, idx) => (
                        <div key={idx} className="rounded-xl border border-line bg-surface2 p-4">
                          <div className="flex items-center justify-between gap-3 mb-1.5">
                            <span className="font-semibold">{t.threat_vector}</span>
                            <SeverityPill level={t.severity} />
                          </div>
                          <p className="text-sm text-muted leading-relaxed">{t.explanation}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              !isLoading &&
              !error && (
                <div className="rounded-2xl border border-line bg-surface shadow-soft p-10 text-center">
                  <div className="grid place-items-center w-12 h-12 rounded-2xl bg-accent/10 text-accent mx-auto mb-4">
                    <Search className="w-5 h-5" />
                  </div>
                  <h3 className="font-display font-bold">Nessuna analisi ancora</h3>
                  <p className="text-sm text-muted max-w-sm mx-auto mt-1.5 leading-relaxed">
                    {mode === "profile"
                      ? "Inserisci un profilo a sinistra — o scegli un profilo di esempio — e avvia l'analisi per vedere qui il verdetto, i dati esposti e i possibili attacchi."
                      : mode === "bio"
                      ? "Incolla il testo di una biografia a sinistra e avvia l'analisi: qui vedrai il verdetto, i dati personali esposti e i possibili attacchi."
                      : "Carica un'immagine a sinistra: qui vedrai il verdetto, i dati personali estratti dal testo visibile e i possibili attacchi."}
                  </p>
                </div>
              )
            )}
          </div>
        </div>
      </main>

      <footer className="border-t border-line">
        <div className="max-w-6xl mx-auto px-5 sm:px-8 py-6 flex flex-col sm:flex-row justify-between items-center gap-2 text-[13px] text-muted">
          <p>Sistemi Distribuiti e Cloud Computing — Università della Calabria</p>
          <p className="font-mono text-xs">Filippo Abbeduto · mat. 276572</p>
        </div>
      </footer>
    </div>
  );
}
