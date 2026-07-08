import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Sun,
  Moon,
  Search,
  RefreshCw,
  Trash2,
  ArrowRight,
  ChevronRight,
  AlertTriangle,
  ShieldCheck,
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

// Mappa il livello di rischio testuale ai token di colore semantici (gli unici saturi).
type RiskKey = "high" | "med" | "low";
const riskInfo = (level: string): { key: RiskKey; label: string } => {
  const l = (level || "").toUpperCase();
  if (l === "HIGH") return { key: "high", label: "Alto" };
  if (l === "MEDIUM") return { key: "med", label: "Medio" };
  return { key: "low", label: "Basso" };
};
const RISK_TEXT: Record<RiskKey, string> = { high: "text-high", med: "text-med", low: "text-low" };
const RISK_BG: Record<RiskKey, string> = { high: "bg-high", med: "bg-med", low: "bg-low" };
const RISK_TINT: Record<RiskKey, string> = {
  high: "bg-high/10 border-high/30",
  med: "bg-med/10 border-med/30",
  low: "bg-low/10 border-low/30",
};

export default function App() {
  // ─── Tema chiaro/scuro: legge quello già impostato dallo script inline in <head> ───
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const cur = typeof document !== "undefined" ? document.documentElement.getAttribute("data-theme") : null;
    return cur === "light" ? "light" : "dark";
  });
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("spd-theme", theme);
    } catch {
      /* localStorage non disponibile: ignora, il tema resta per la sessione */
    }
  }, [theme]);

  // ─── Stato del form e dell'analisi ───
  const [socialUrl, setSocialUrl] = useState("");
  const [scrapedContent, setScrapedContent] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [jobStatus, setJobStatus] = useState<string | null>(null);
  const [activeTemplate, setActiveTemplate] = useState<number | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
  }, []);

  const applyTemplate = (index: number) => {
    setSocialUrl(DEMO_PROFILES[index].url);
    setScrapedContent(DEMO_PROFILES[index].content);
    setActiveTemplate(index);
    setError(null);
  };

  // Polling dello stato del job ogni 3s finché COMPLETED o FAILED.
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
        console.error("Polling error:", err); // errori di rete temporanei: non fermare il polling
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

  const handleClear = () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    pollingRef.current = null;
    setSocialUrl("");
    setScrapedContent("");
    setError(null);
    setResult(null);
    setJobStatus(null);
    setActiveTemplate(null);
    setIsLoading(false);
  };

  return (
    <div className="min-h-screen bg-bg text-ink">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-line bg-bg/80 backdrop-blur">
        <div className="max-w-6xl mx-auto px-5 sm:px-8 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="grid place-items-center w-9 h-9 rounded-md bg-invert text-oninvert">
              <Shield className="w-5 h-5" />
            </div>
            <div className="leading-tight">
              <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest text-faint">
                <span>Università della Calabria</span>
                <span aria-hidden>·</span>
                <span>SDCC 25/26</span>
              </div>
              <h1 className="font-display text-[17px] font-bold tracking-tight">Social Privacy Detector</h1>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <span className="hidden sm:flex items-center gap-1.5 text-[11px] font-mono text-muted border border-line rounded-full px-2.5 py-1">
              <span className="w-1.5 h-1.5 rounded-full bg-low" />
              AWS · us-east-1
            </span>
            <button
              type="button"
              onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
              aria-label={theme === "dark" ? "Passa al tema chiaro" : "Passa al tema scuro"}
              className="grid place-items-center w-9 h-9 rounded-md border border-line text-muted hover:text-ink hover:bg-surface2 transition-colors"
            >
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-5 sm:px-8 py-10 sm:py-14">
        {/* ── Hero: la tesi + la signature (redazione che si rivela) ─────────── */}
        <section className="max-w-3xl mb-12">
          <span className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">
            Analisi dell'esposizione pubblica
          </span>
          <h2 className="font-display text-3xl sm:text-[42px] leading-[1.08] font-bold tracking-tight mt-3">
            Il tuo profilo pubblico
            <br className="hidden sm:block" /> dice più di quanto pensi.
          </h2>
          <p className="text-muted text-sm sm:text-base leading-relaxed mt-4">
            Da una biografia e pochi post, un estraneo può ricostruire chi sei, dove vivi e come contattarti.
            Questo strumento individua i dati personali <span className="text-ink">esposti</span>, stima i vettori
            di ingegneria sociale e assegna un punteggio di rischio.
          </p>

          <div className="mt-6 inline-flex items-center gap-3 font-mono text-sm border border-line rounded-lg bg-surface px-4 py-3">
            <span className="text-faint">visibile pubblicamente</span>
            <span className="text-faint" aria-hidden>→</span>
            <span className="redact rounded-sm">
              mario.rossi@email.it
              <span className="redact-bar" aria-hidden />
            </span>
          </div>
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* ── Colonna sinistra: input ─────────────────────────────────────── */}
          <div className="lg:col-span-5 space-y-6">
            <form onSubmit={handleAnalyze} className="rounded-xl border border-line bg-surface p-6 space-y-5">
              <div className="space-y-2">
                <label htmlFor="social-url" className="block text-sm font-medium">
                  Profilo social <span className="text-faint font-normal">(obbligatorio)</span>
                </label>
                <div className="relative">
                  <Search className="w-4 h-4 text-faint absolute left-3 top-1/2 -translate-y-1/2" />
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
                    className="w-full rounded-lg border border-line bg-bg py-2.5 pl-9 pr-3 text-sm font-mono placeholder:text-faint focus:outline-none focus:border-ink transition-colors"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="scraped-content" className="block text-sm font-medium">
                  Biografia o testo dei post <span className="text-faint font-normal">(facoltativo)</span>
                </label>
                <textarea
                  id="scraped-content"
                  rows={6}
                  value={scrapedContent}
                  onChange={(e) => {
                    setScrapedContent(e.target.value);
                    setActiveTemplate(null);
                  }}
                  placeholder="Se lo lasci vuoto, il testo pubblico viene recuperato automaticamente dal profilo indicato."
                  className="w-full rounded-lg border border-line bg-bg p-3 text-sm leading-relaxed placeholder:text-faint focus:outline-none focus:border-ink transition-colors resize-y"
                />
              </div>

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={handleClear}
                  disabled={isLoading}
                  className="w-1/3 rounded-lg border border-line py-2.5 text-sm font-medium text-muted hover:text-ink hover:bg-surface2 transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
                >
                  <Trash2 className="w-4 h-4" />
                  Pulisci
                </button>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-2/3 rounded-lg bg-invert text-oninvert py-2.5 text-sm font-semibold hover:opacity-90 transition-opacity flex items-center justify-center gap-2 disabled:opacity-50"
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

            {/* Profili di esempio */}
            <div className="rounded-xl border border-line bg-surface p-6">
              <span className="block text-[11px] font-mono uppercase tracking-widest text-muted mb-3">
                Profili di esempio
              </span>
              <div className="space-y-1.5">
                {DEMO_PROFILES.map((p, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => applyTemplate(idx)}
                    className={`w-full text-left rounded-lg px-3 py-2.5 text-sm border transition-colors flex items-center justify-between gap-2 ${
                      activeTemplate === idx
                        ? "border-ink bg-surface2"
                        : "border-line hover:bg-surface2"
                    }`}
                  >
                    <span>{p.label}</span>
                    <ArrowRight className="w-4 h-4 text-faint shrink-0" />
                  </button>
                ))}
              </div>
            </div>

            {/* Motore (crediti onesti, non dettagli interni) */}
            <div className="rounded-xl border border-line bg-surface p-6 text-sm">
              <span className="block text-[11px] font-mono uppercase tracking-widest text-muted mb-3">
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
          <div className="lg:col-span-7">
            {error && (
              <div className="rounded-xl border border-high/40 bg-high/10 p-5 flex gap-3 items-start mb-6" role="alert">
                <AlertTriangle className="w-5 h-5 text-high shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h3 className="text-sm font-semibold text-high">Analisi non riuscita</h3>
                  <p className="text-sm text-muted leading-relaxed">{error}</p>
                </div>
              </div>
            )}

            {isLoading && jobStatus && !result && (
              <div className="rounded-xl border border-line bg-surface p-8 text-center mb-6">
                <div className="relative w-14 h-14 mx-auto mb-5">
                  <div className="absolute inset-0 rounded-full border-2 border-line" />
                  <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-ink animate-spin" />
                  <Cpu className="w-5 h-5 absolute inset-0 m-auto text-muted" />
                </div>
                <h3 className="font-display font-semibold">
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
                        className={`text-[11px] font-mono rounded px-2 py-1 border ${
                          jobStatus === "PROCESSING" && idx <= 1
                            ? "border-ink text-ink"
                            : "border-line text-faint"
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

            {result && result.status === "COMPLETED" && result.risk_assessment ? (
              <div key={result.analysis_id} className="space-y-6">
                {(() => {
                  const r = riskInfo(result.risk_assessment!.risk_level);
                  const score = result.risk_assessment!.score;
                  return (
                    <div className={`rise rounded-xl border p-6 ${RISK_TINT[r.key]}`}>
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <span className="text-[11px] font-mono uppercase tracking-widest text-muted">
                            Verdetto
                          </span>
                          <div className="flex items-baseline gap-3 mt-1">
                            <span className={`font-display text-3xl font-bold ${RISK_TEXT[r.key]}`}>
                              Rischio {r.label.toLowerCase()}
                            </span>
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <div className="font-mono">
                            <span className={`text-3xl font-bold ${RISK_TEXT[r.key]}`}>{score}</span>
                            <span className="text-sm text-faint">/100</span>
                          </div>
                        </div>
                      </div>

                      {/* Barra semantica del punteggio con tacche a 35 e 70 */}
                      <div className="mt-5">
                        <div className="relative h-2 rounded-full bg-surface2 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${RISK_BG[r.key]} transition-[width] duration-700 ease-out`}
                            style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
                          />
                        </div>
                        <div className="relative mt-1.5 h-4 text-[10px] font-mono text-faint">
                          <span className="absolute left-0">0</span>
                          <span className="absolute -translate-x-1/2" style={{ left: "35%" }}>35</span>
                          <span className="absolute -translate-x-1/2" style={{ left: "70%" }}>70</span>
                          <span className="absolute right-0">100</span>
                        </div>
                      </div>

                      <p className="text-sm text-muted leading-relaxed mt-4">
                        {result.risk_assessment!.explanation}
                      </p>

                      {result.risk_assessment!.motivations?.length > 0 && (
                        <div className="mt-4 pt-4 border-t border-line">
                          <span className="block text-[11px] font-mono uppercase tracking-widest text-muted mb-2">
                            Come si compone il punteggio
                          </span>
                          <ul className="space-y-1.5">
                            {result.risk_assessment!.motivations.map((m, idx) => (
                              <li key={idx} className="flex items-start gap-2 text-[13px] font-mono text-muted">
                                <ChevronRight className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${RISK_TEXT[r.key]}`} />
                                <span>{m}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <div className="mt-4 pt-4 border-t border-line text-[11px] font-mono text-faint break-all">
                        Profilo analizzato: <span className="text-muted">{result.social_url}</span>
                      </div>
                    </div>
                  );
                })()}

                {/* Dati personali rilevati — con la signature "redazione rivelata" */}
                <div className="rise rounded-xl border border-line bg-surface p-6" style={{ animationDelay: "0.06s" }}>
                  <h3 className="font-display font-semibold mb-1">Dati personali rilevati</h3>
                  <p className="text-sm text-muted mb-4">
                    Ciò che è pubblicamente estraibile dal profilo. Ogni valore era nascosto: viene rivelato per
                    mostrarne l'esposizione.
                  </p>

                  {(result.detected_pii || []).length > 0 ? (
                    <ul className="divide-y divide-line">
                      {(result.detected_pii || []).map((e, idx) => {
                        const meta = piiMeta(e.type);
                        const Icon = meta.Icon;
                        return (
                          <li key={idx} className="flex items-center gap-3 py-2.5">
                            <Icon className="w-4 h-4 text-muted shrink-0" />
                            <div className="min-w-0 flex-1">
                              <div className="text-[11px] font-mono uppercase tracking-wider text-faint">
                                {meta.label}
                              </div>
                              <div className="text-sm font-mono truncate">
                                <span className="redact rounded-sm">
                                  {e.text}
                                  <span
                                    className="redact-bar"
                                    style={{ animationDelay: `${0.15 + idx * 0.08}s` }}
                                    aria-hidden
                                  />
                                </span>
                              </div>
                            </div>
                            <span className="text-xs font-mono text-muted shrink-0" title="Confidenza del rilevamento">
                              {(e.score * 100).toFixed(0)}%
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <div className="text-center py-8">
                      <ShieldCheck className="w-8 h-8 text-low mx-auto mb-2" />
                      <p className="text-sm font-medium">Nessun dato personale leggibile</p>
                      <p className="text-sm text-muted mt-1">
                        Il testo analizzato non espone contatti o identificativi diretti.
                      </p>
                    </div>
                  )}
                </div>

                {/* Vettori di ingegneria sociale */}
                {(result.social_engineering_report || []).length > 0 && (
                  <div className="rise rounded-xl border border-line bg-surface p-6" style={{ animationDelay: "0.12s" }}>
                    <h3 className="font-display font-semibold mb-1">Vettori di ingegneria sociale</h3>
                    <p className="text-sm text-muted mb-4">
                      Come i dati esposti potrebbero essere sfruttati per un attacco mirato.
                    </p>
                    <div className="space-y-3">
                      {(result.social_engineering_report || []).map((t, idx) => {
                        const r = riskInfo(t.severity);
                        return (
                          <div key={idx} className={`rounded-lg border p-4 ${RISK_TINT[r.key]}`}>
                            <div className="flex items-center justify-between gap-3 mb-1.5">
                              <span className="font-medium flex items-center gap-2">
                                <span className={`w-1.5 h-1.5 rounded-full ${RISK_BG[r.key]}`} />
                                {t.threat_vector}
                              </span>
                              <span className={`text-[10px] font-mono uppercase tracking-wider ${RISK_TEXT[r.key]}`}>
                                {r.label}
                              </span>
                            </div>
                            <p className="text-sm text-muted leading-relaxed">{t.explanation}</p>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              !isLoading &&
              !error && (
                <div className="rounded-xl border border-line bg-surface p-10 text-center">
                  <div className="grid place-items-center w-12 h-12 rounded-full border border-line mx-auto mb-4 text-muted">
                    <Search className="w-5 h-5" />
                  </div>
                  <h3 className="font-display font-semibold">Nessuna analisi ancora</h3>
                  <p className="text-sm text-muted max-w-sm mx-auto mt-1.5 leading-relaxed">
                    Inserisci un profilo a sinistra — o scegli un profilo di esempio — e avvia l'analisi per vedere
                    qui il verdetto, i dati esposti e i possibili attacchi.
                  </p>
                </div>
              )
            )}
          </div>
        </div>
      </main>

      <footer className="border-t border-line mt-16">
        <div className="max-w-6xl mx-auto px-5 sm:px-8 py-6 flex flex-col sm:flex-row justify-between items-center gap-2 text-[13px] text-muted">
          <p>
            Sistemi Distribuiti e Cloud Computing — Università della Calabria
          </p>
          <p className="font-mono text-xs">
            Filippo Abbeduto · mat. 276572
          </p>
        </div>
      </footer>
    </div>
  );
}
