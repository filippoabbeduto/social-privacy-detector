import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Sun,
  Moon,
  Search,
  ArrowRight,
  RefreshCw,
  Trash2,
  ChevronRight,
  ChevronDown,
  Plus,
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
} from "lucide-react";

// ─── Profili di esempio: popolano il form per provare i diversi livelli di rischio ───
const DEMO_PROFILES = [
  {
    label: "Instagram — esposizione alta",
    url: "https://instagram.com/filippo_abbeduto_99",
    content:
      "Studente alla Sapienza di Roma! Scrivimi a filippo.abb@sapienza.it per gli appunti o chiamami al 333-1234567. Nato il 15/03/1999 a Cosenza. Codice fiscale: ABBFPP99C15D086X.",
  },
  {
    label: "TikTok — routine geografica",
    url: "https://tiktok.com/@marco_vibes99",
    content:
      "Studente UniCal a Cosenza. Nato il 22/06/2000. Giornata a Roma, sempre a Roma, amo Roma! Seguitemi su IG: @marco_vibes — collab: marco.vibes@gmail.com",
  },
  {
    label: "LinkedIn — dati professionali",
    url: "https://linkedin.com/in/andrea-bianchi-cloud",
    content:
      "Senior Cloud Engineer presso Accenture a Roma. Ex Deloitte Milano. Laurea Magistrale all'Università della Calabria. Contatto: andrea.bianchi@accenture.com | +39 347-9876543",
  },
  {
    label: "Facebook — dati personali",
    url: "https://facebook.com/giulia.ferretti.95",
    content:
      "Città: Napoli. Città natale: Cosenza. Studi: Università Federico II. Lavoro: Marketing Manager presso Enel. Compleanno: 10 agosto 1995. giulia.ferretti@enel.com",
  },
  {
    label: "Twitter/X — sviluppatore",
    url: "https://x.com/luca_dev_reply",
    content:
      "Full-stack developer @Reply Milano. Oggi workshop su Kubernetes al Politecnico di Milano! Per collaborazioni: luca.dev@reply.it — blog: https://lucadev.tech",
  },
  {
    label: "Profilo consapevole — rischio basso",
    url: "https://twitter.com/cyber_shield_unical",
    content:
      "Appassionato di OSINT e sicurezza informatica. Ricorda di limitare l'esposizione di informazioni identificabili sui tuoi canali pubblici!",
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
interface RiskAssessment {
  risk_level: string;
  explanation: string;
  score: number;
  motivations: string[];
}
interface AnalysisResult {
  analysis_id: string;
  social_url: string;
  status: string;
  detected_pii?: PIIEntity[];
  narrative_summary?: string;
  social_engineering_report?: SocialEngineeringThreat[];
  risk_assessment?: RiskAssessment;
  error?: string;
}

// Etichette leggibili + icona per ogni tipo di PII restituito dal backend.
const PII_META: Record<string, { label: string; Icon: React.ComponentType<{ className?: string }> }> = {
  NAME: { label: "Nome", Icon: User },
  EMAIL: { label: "Email", Icon: Mail },
  PHONE: { label: "Telefono", Icon: Phone },
  PHONE_NUMBER: { label: "Telefono", Icon: Phone },
  LOCATION: { label: "Luogo", Icon: MapPin },
  ADDRESS: { label: "Indirizzo", Icon: MapPin },
  DATE_OF_BIRTH: { label: "Data di nascita", Icon: Calendar },
  DATE: { label: "Data", Icon: Calendar },
  FISCAL_CODE: { label: "Codice fiscale", Icon: Fingerprint },
  IBAN: { label: "IBAN", Icon: Landmark },
  ORGANIZATION: { label: "Organizzazione", Icon: Building2 },
  USERNAME: { label: "Username", Icon: AtSign },
  URL: { label: "URL", Icon: Link2 },
};
const piiMeta = (type: string) => PII_META[type] || { label: type, Icon: Tag };

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

// Gauge radiale del punteggio (SVG, dati reali: score/100).
function ScoreGauge({ score, riskKey }: { score: number; riskKey: RiskKey }) {
  const R = 34;
  const C = 2 * Math.PI * R;
  const clamped = Math.min(100, Math.max(0, score));
  const offset = C * (1 - clamped / 100);
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
          className={`${RISK_TEXT[riskKey]} transition-[stroke-dashoffset] duration-700 ease-out`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-display text-2xl font-extrabold leading-none ${RISK_TEXT[riskKey]}`}>{clamped}</span>
        <span className="text-[10px] font-mono text-faint mt-0.5">/100</span>
      </div>
    </div>
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

export default function App() {
  // ─── Tema: legge quello già impostato dallo script inline in <head> (default chiaro) ───
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const cur = typeof document !== "undefined" ? document.documentElement.getAttribute("data-theme") : null;
    return cur === "dark" ? "dark" : "light";
  });
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("spd-theme", theme);
    } catch {
      /* localStorage non disponibile: il tema resta per la sessione */
    }
  }, [theme]);

  // ─── Stato form / analisi ───
  const [socialUrl, setSocialUrl] = useState("");
  const [scrapedContent, setScrapedContent] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [jobStatus, setJobStatus] = useState<string | null>(null);
  const [activeTemplate, setActiveTemplate] = useState<number | null>(null);
  // Input opzionali nascosti di default: si aprono al click dell'utente per
  // tenere il form pulito e focalizzato sull'unico campo obbligatorio (l'URL).
  const [showBio, setShowBio] = useState(false);
  const [showExamples, setShowExamples] = useState(false);
  // Modalità di analisi selezionabile dalla navbar: "profile" (URL + bio) oppure
  // "image" (upload di una foto, controllo pre-pubblicazione via OCR Textract).
  const [mode, setMode] = useState<"profile" | "image">("profile");
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
  }, []);

  const applyTemplate = (index: number) => {
    setSocialUrl(DEMO_PROFILES[index].url);
    setScrapedContent(DEMO_PROFILES[index].content);
    setActiveTemplate(index);
    setShowBio(true); // mostra il testo popolato dal template
    setError(null);
  };

  const startPolling = (analysisId: string) => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/analysis/${analysisId}`);
        if (!res.ok) throw new Error(`Polling error: ${res.status}`);
        const data: AnalysisResult = await res.json();
        setJobStatus(data.status);
        if (data.status === "COMPLETED") {
          clearInterval(pollingRef.current!);
          pollingRef.current = null;
          setResult(data);
          setIsLoading(false);
        } else if (data.status === "FAILED") {
          clearInterval(pollingRef.current!);
          pollingRef.current = null;
          setError(data.error || "Analisi non riuscita.");
          setIsLoading(false);
        }
      } catch (err) {
        console.error("Polling error:", err); // errori di rete temporanei: continua il polling
      }
    }, 3000);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!socialUrl.trim()) {
      setError("Inserisci l'indirizzo del profilo social da analizzare.");
      return;
    }
    setIsLoading(true);
    setError(null);
    setResult(null);
    setJobStatus("PENDING");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          social_url: socialUrl,
          scraped_content: scrapedContent.trim() ? scrapedContent : null,
        }),
      });
      if (!response.ok) throw new Error(`Il server ha risposto ${response.status}.`);
      const job = await response.json();
      startPolling(job.analysis_id);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Impossibile raggiungere il servizio di analisi. Riprova più tardi.");
      setIsLoading(false);
      setJobStatus(null);
    }
  };

  // Analisi da immagine: carica il file su /api/analyze-image (OCR Textract lato
  // backend), poi riusa lo stesso polling del flusso testuale.
  const handleImageUpload = async (file: File) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setJobStatus("PENDING");
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
      startPolling(job.analysis_id);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Caricamento immagine non riuscito.");
      setIsLoading(false);
      setJobStatus(null);
    }
  };

  const handleClear = () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    pollingRef.current = null;
    setSocialUrl("");
    setScrapedContent("");
    setError(null);
    setResult(null);
    setJobStatus(null);
    setActiveTemplate(null);
    setShowBio(false);
    setShowExamples(false);
    setIsLoading(false);
  };

  const risk = result?.risk_assessment ? riskInfo(result.risk_assessment.risk_level) : null;
  const piiList = result?.detected_pii || [];
  const threats = result?.social_engineering_report || [];

  return (
    <div className="min-h-screen bg-bg text-ink">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-line bg-bg/85 backdrop-blur">
        <div className="max-w-6xl mx-auto px-5 sm:px-8 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="grid place-items-center w-9 h-9 rounded-xl bg-accent text-accentink shadow-soft">
              <Shield className="w-5 h-5" />
            </div>
            <div className="leading-tight">
              <div className="text-[10px] font-mono uppercase tracking-widest text-faint">
                Università della Calabria · SDCC 25/26
              </div>
              <h1 className="font-display text-[17px] font-bold tracking-tight">Social Privacy Detector</h1>
            </div>
          </div>

          {/* Tab modalità di analisi: Profilo / Immagine */}
          <nav className="flex items-center gap-1 rounded-xl border border-line bg-surface p-1">
            <button
              type="button"
              onClick={() => { setMode("profile"); setError(null); }}
              className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors ${
                mode === "profile" ? "bg-accent text-accentink" : "text-muted hover:text-ink"
              }`}
            >
              Profilo
            </button>
            <button
              type="button"
              onClick={() => { setMode("image"); setError(null); }}
              className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors ${
                mode === "image" ? "bg-accent text-accentink" : "text-muted hover:text-ink"
              }`}
            >
              Immagine
            </button>
          </nav>

          <div className="flex items-center gap-2.5">
            <span className="hidden sm:flex items-center gap-1.5 text-xs text-muted border border-line rounded-full px-3 py-1.5 bg-surface">
              <span className="w-1.5 h-1.5 rounded-full bg-low" />
              AWS · us-east-1
            </span>
            <button
              type="button"
              onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
              aria-label={theme === "dark" ? "Passa al tema chiaro" : "Passa al tema scuro"}
              className="grid place-items-center w-9 h-9 rounded-xl border border-line bg-surface text-muted hover:text-ink transition-colors"
            >
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-5 sm:px-8 py-8 sm:py-10">
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
          <div className="lg:col-span-5 space-y-5">
            {mode === "profile" && (
            <div className="space-y-5">
            <form onSubmit={handleAnalyze} className="rounded-2xl border border-line bg-surface shadow-soft p-6 space-y-5">
              <div className="space-y-2">
                <label htmlFor="social-url" className="block text-sm font-semibold">
                  Profilo social <span className="text-faint font-normal">(obbligatorio)</span>
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
                    className="w-full rounded-xl border border-line bg-bg py-2.5 pl-10 pr-3 text-sm font-mono placeholder:text-faint focus:outline-none focus:border-accent transition-colors"
                  />
                </div>
              </div>

              {/* Testo/biografia manuale: opzionale, nascosto dietro un link */}
              {!showBio ? (
                <button
                  type="button"
                  onClick={() => setShowBio(true)}
                  className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-accent transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  Aggiungi bio o testo dei post <span className="text-faint">(facoltativo)</span>
                </button>
              ) : (
                <div className="space-y-2">
                  <button
                    type="button"
                    onClick={() => setShowBio(false)}
                    className="w-full flex items-center justify-between text-sm font-semibold hover:text-accent transition-colors"
                  >
                    <span>
                      Biografia o testo dei post <span className="text-faint font-normal">(facoltativo)</span>
                    </span>
                    <ChevronDown className="w-4 h-4 rotate-180 text-faint" />
                  </button>
                  <textarea
                    id="scraped-content"
                    aria-label="Biografia o testo dei post"
                    rows={6}
                    value={scrapedContent}
                    onChange={(e) => {
                      setScrapedContent(e.target.value);
                      setActiveTemplate(null);
                    }}
                    placeholder="Se lo lasci vuoto, il testo pubblico viene recuperato automaticamente dal profilo indicato."
                    className="w-full rounded-xl border border-line bg-bg p-3.5 text-sm leading-relaxed placeholder:text-faint focus:outline-none focus:border-accent transition-colors resize-y"
                  />
                </div>
              )}

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
                  disabled={isLoading}
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

            {/* Profili di esempio (collassabili, chiusi di default) */}
            <div className="rounded-2xl border border-line bg-surface shadow-soft p-6">
              <button
                type="button"
                onClick={() => setShowExamples((v) => !v)}
                className="w-full flex items-center justify-between text-[11px] uppercase tracking-wider text-muted font-semibold hover:text-ink transition-colors"
              >
                <span>Profili di esempio</span>
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
                <label
                  className={`flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed py-10 text-sm font-semibold transition-colors ${
                    isLoading
                      ? "border-line text-faint cursor-not-allowed"
                      : "border-line text-muted hover:text-ink hover:border-accent hover:bg-surface2 cursor-pointer"
                  }`}
                >
                  <ScanText className="w-6 h-6" />
                  Carica immagine
                  <span className="text-xs font-normal text-faint">PNG o JPEG · max 8 MB</span>
                  <input
                    type="file"
                    accept="image/*"
                    className="hidden"
                    disabled={isLoading}
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) handleImageUpload(f);
                      e.target.value = ""; // consente di ricaricare lo stesso file
                    }}
                  />
                </label>
              </div>
            )}

            {/* Motore (crediti onesti) */}
            <div className="rounded-2xl border border-line bg-surface shadow-soft p-6 text-sm">
              <span className="block text-[11px] uppercase tracking-wider text-muted font-semibold mb-3">
                Motore di analisi
              </span>
              <dl className="space-y-2 text-muted">
                <div className="flex justify-between gap-4">
                  <dt>Rilevamento dati personali</dt>
                  <dd className="text-ink font-mono text-xs">Amazon Comprehend</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt>Report minacce</dt>
                  <dd className="text-ink font-mono text-xs">Amazon Bedrock · Claude</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt>Persistenza</dt>
                  <dd className="text-ink font-mono text-xs">DynamoDB · S3</dd>
                </div>
              </dl>
            </div>
          </div>

          {/* ── Colonna destra: risultati ───────────────────────────────────── */}
          <div className="lg:col-span-7 space-y-5">
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
                {/* KPI Summary (stile reference) */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                  <StatCard Icon={Gauge} tone={risk.key} label="Punteggio" value={`${result.risk_assessment.score}`} sub="/ 100" />
                  <StatCard Icon={Eye} label="Dati esposti" value={piiList.length} sub={piiList.length === 1 ? "elemento" : "elementi"} />
                  <StatCard Icon={Target} label="Vettori d'attacco" value={threats.length} sub={threats.length === 1 ? "scenario" : "scenari"} />
                </div>

                {/* Verdetto: gauge + spiegazione */}
                <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6">
                  <div className="flex items-center gap-5">
                    <ScoreGauge score={result.risk_assessment.score} riskKey={risk.key} />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <ShieldAlert className={`w-4 h-4 ${RISK_TEXT[risk.key]}`} />
                        <span className="text-[11px] uppercase tracking-wider text-muted font-semibold">Verdetto</span>
                      </div>
                      <div className={`font-display text-2xl font-extrabold ${RISK_TEXT[risk.key]}`}>
                        Rischio {risk.label.toLowerCase()}
                      </div>
                      <p className="text-sm text-muted leading-relaxed mt-1.5">{result.risk_assessment.explanation}</p>
                    </div>
                  </div>

                  {result.risk_assessment.motivations?.length > 0 && (
                    <div className="mt-5 pt-5 border-t border-line">
                      <span className="block text-[11px] uppercase tracking-wider text-muted font-semibold mb-2.5">
                        Come si compone il punteggio
                      </span>
                      <ul className="space-y-1.5">
                        {result.risk_assessment.motivations.map((m, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-[13px] text-muted">
                            <ChevronRight className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${RISK_TEXT[risk.key]}`} />
                            <span>{m}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="mt-5 pt-4 border-t border-line text-[11px] font-mono text-faint break-all">
                    Profilo analizzato: <span className="text-muted">{result.social_url}</span>
                  </div>
                </div>

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

                {/* Dati personali rilevati — tabella pulita in stile reference */}
                <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.06s" }}>
                  <div className="flex items-center justify-between gap-3 mb-4">
                    <h3 className="font-display font-bold">Dati personali rilevati</h3>
                    <span className="text-xs text-muted">{piiList.length} totali</span>
                  </div>

                  {piiList.length > 0 ? (
                    <ul className="divide-y divide-line -my-1">
                      {piiList.map((e, idx) => {
                        const meta = piiMeta(e.type);
                        const Icon = meta.Icon;
                        return (
                          <li key={idx} className="flex items-center gap-3 py-2.5">
                            <div className="grid place-items-center w-8 h-8 rounded-lg bg-surface2 text-muted shrink-0">
                              <Icon className="w-4 h-4" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="text-[11px] uppercase tracking-wider text-faint font-semibold">{meta.label}</div>
                              <div className="text-sm font-mono truncate select-all">{e.text}</div>
                            </div>
                            <span
                              className="text-xs font-mono text-muted shrink-0 tabular-nums"
                              title="Confidenza del rilevamento"
                            >
                              {(e.score * 100).toFixed(0)}%
                            </span>
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

                {/* Vettori d'attacco */}
                {threats.length > 0 && (
                  <div className="rise rounded-2xl border border-line bg-surface shadow-soft p-6" style={{ animationDelay: "0.12s" }}>
                    <h3 className="font-display font-bold mb-1">Vettori di ingegneria sociale</h3>
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
                      : "Carica un'immagine a sinistra: qui vedrai il verdetto, i dati personali estratti dal testo visibile e i possibili attacchi."}
                  </p>
                </div>
              )
            )}
          </div>
        </div>
      </main>

      <footer className="border-t border-line mt-12">
        <div className="max-w-6xl mx-auto px-5 sm:px-8 py-6 flex flex-col sm:flex-row justify-between items-center gap-2 text-[13px] text-muted">
          <p>Sistemi Distribuiti e Cloud Computing — Università della Calabria</p>
          <p className="font-mono text-xs">Filippo Abbeduto · mat. 276572</p>
        </div>
      </footer>
    </div>
  );
}
