import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Terminal,
  Cpu,
  AlertTriangle,
  CheckCircle2,
  Search,
  FileText,
  Layers,
  RefreshCw,
  ArrowRight,
  Trash2,
  Mail,
  Phone,
  MapPin,
  ExternalLink,
  BookOpen,
  Info,
  Server,
  Activity,
  ChevronRight
} from "lucide-react";

// Pre-configured templates to help the Unical Exam Commission quickly test different states
const DEMO_PROFILES = [
  {
    label: "📸 Instagram — Alto Rischio (PII esposte)",
    url: "https://instagram.com/filippo_abbeduto_99",
    content: "Studente alla Sapienza di Roma! Scrivimi a filippo.abb@sapienza.it per gli appunti o chiamami al 333-1234567. Nato il 15/03/1999 a Cosenza. Domani esame di Sistemi Distribuiti! 💻"
  },
  {
    label: "🎵 TikTok — Alto Rischio (Routine geografica)",
    url: "https://tiktok.com/@marco_vibes99",
    content: "Studente UniCal a Cosenza. Nato il 22/06/2000. Giornata a Roma, sempre a Roma, amo Roma! Poi Roma di nuovo. Seguitemi su IG: @marco_vibes — Contatto collab: marco.vibes@gmail.com"
  },
  {
    label: "💼 LinkedIn — Rischio Medio (Dati professionali)",
    url: "https://linkedin.com/in/andrea-bianchi-cloud",
    content: "Senior Cloud Engineer presso Accenture a Roma. Ex Deloitte Milano. Laurea Magistrale all'Università della Calabria. Contatto: andrea.bianchi@accenture.com | +39 347-9876543"
  },
  {
    label: "📘 Facebook — Rischio Medio (Dati personali)",
    url: "https://facebook.com/giulia.ferretti.95",
    content: "Città: Napoli. Città natale: Cosenza. Studi: Università Federico II. Lavoro: Marketing Manager presso Enel. Compleanno: 10 agosto 1995. giulia.ferretti@enel.com"
  },
  {
    label: "🐦 Twitter/X — Rischio Medio (Dev esposto)",
    url: "https://x.com/luca_dev_reply",
    content: "Full-stack developer @Reply Milano. Oggi workshop su Kubernetes al Politecnico di Milano! Per collaborazioni: luca.dev@reply.it — Il mio blog: https://lucadev.tech"
  },
  {
    label: "🛡️ Cyber-Aware (Basso Rischio)",
    url: "https://twitter.com/cyber_shield_unical",
    content: "Appassionato di OSINT e sicurezza informatica. Ricorda di limitare l'esposizione di informazioni identificabili sui tuoi canali pubblici!"
  }
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

export default function App() {
  // Input states
  const [socialUrl, setSocialUrl] = useState("");
  const [scrapedContent, setScrapedContent] = useState("");

  // API and UI states
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [jobStatus, setJobStatus] = useState<string | null>(null);

  // Polling ref — mantiene il timer per il cleanup
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Active selected template for visual feedback
  const [activeTemplate, setActiveTemplate] = useState<number | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  // Quick fill function
  const applyTemplate = (index: number) => {
    setSocialUrl(DEMO_PROFILES[index].url);
    setScrapedContent(DEMO_PROFILES[index].content);
    setActiveTemplate(index);
    setError(null);
  };

  // Polling: controlla lo stato del job ogni 3 secondi
  const startPolling = (analysisId: string) => {
    if (pollingRef.current) clearInterval(pollingRef.current);

    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/analysis/${analysisId}`);
        if (!res.ok) throw new Error(`Polling error: ${res.status}`);

        const data: AnalysisResult = await res.json();
        setJobStatus(data.status);

        if (data.status === "COMPLETED") {
          // Analisi completata — ferma il polling e mostra i risultati
          if (pollingRef.current) clearInterval(pollingRef.current);
          pollingRef.current = null;
          setResult(data);
          setIsLoading(false);
        } else if (data.status === "FAILED") {
          // Analisi fallita — ferma il polling e mostra l'errore
          if (pollingRef.current) clearInterval(pollingRef.current);
          pollingRef.current = null;
          setError(data.error || "Errore sconosciuto durante l'analisi.");
          setIsLoading(false);
        }
        // PENDING / PROCESSING → continua il polling
      } catch (err: any) {
        console.error("Polling error:", err);
        // Non fermare il polling per errori di rete temporanei
      }
    }, 3000);
  };

  // Main API submission logic (asincrona con polling)
  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!socialUrl.trim()) {
      setError("L'URL del profilo social è obbligatorio.");
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);
    setJobStatus("PENDING");

    try {
      // 1. Invia la richiesta — il backend risponde 202 con l'analysis_id
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          social_url: socialUrl,
          scraped_content: scrapedContent.trim() ? scrapedContent : null,
        }),
      });

      if (!response.ok) {
        throw new Error(`Errore del server: ${response.status} ${response.statusText}`);
      }

      const job = await response.json();

      // 2. Avvia il polling per controllare lo stato
      startPolling(job.analysis_id);

    } catch (err: any) {
      console.error(err);
      setError(
        err.message ||
        "Impossibile connettersi al backend FastAPI. Assicurati che Nginx e i container siano avviati."
      );
      setIsLoading(false);
      setJobStatus(null);
    }
  };

  // Reset Form
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

  // Helper to determine badge styling according to AWS risk assessment
  const getRiskStyles = (level: string) => {
    const uppercaseLevel = level.toUpperCase();
    if (uppercaseLevel === "HIGH") {
      return {
        badge: "bg-red-500/10 text-red-400 border-red-500/30",
        bg: "bg-red-950/20 border-red-900/30",
        accentText: "text-red-400",
        indicator: "bg-red-500",
        label: "ALTO RISCHIO ESPOSIZIONE"
      };
    } else if (uppercaseLevel === "MEDIUM") {
      return {
        badge: "bg-amber-500/10 text-amber-400 border-amber-500/30",
        bg: "bg-amber-950/20 border-amber-900/30",
        accentText: "text-amber-400",
        indicator: "bg-amber-500",
        label: "MEDIO RISCHIO ESPOSIZIONE"
      };
    } else {
      return {
        badge: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
        bg: "bg-emerald-950/20 border-emerald-900/30",
        accentText: "text-emerald-400",
        indicator: "bg-emerald-500",
        label: "BASSO RISCHIO ESPOSIZIONE"
      };
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-indigo-600 selection:text-white">

      {/* ==============================================================================
      # TOP HEADER BAR
      ============================================================================== */}
      <header className="border-b border-slate-900 bg-slate-950/60 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="bg-indigo-600 text-white p-2 rounded-lg shadow-lg shadow-indigo-600/30">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono tracking-wider bg-slate-950 border border-slate-800 text-slate-400 px-2 py-0.5 rounded-full font-semibold uppercase">
                  Università della Calabria
                </span>
                <span className="text-[10px] font-mono text-indigo-400 font-bold uppercase">
                  SDCC 25/26
                </span>
              </div>
              <h1 className="text-lg font-extrabold tracking-tight text-white">
                Social Privacy Detector
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            <div className="bg-slate-900 border border-slate-800 px-3 py-1.5 rounded flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-indigo-400" />
              <span>Nginx Proxy Integration</span>
            </div>
          </div>
        </div>
      </header>

      {/* ==============================================================================
      # MAIN BODY GRID
      ============================================================================== */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

        {/* Intro Context Banner */}
        <div className="bg-gradient-to-br from-indigo-950/40 via-slate-950 to-slate-950 border border-slate-900/80 rounded-xl p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-80 h-80 bg-indigo-600/5 rounded-full blur-3xl -z-10"></div>

          <div className="max-w-4xl space-y-3">
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 text-xs font-mono font-medium">
              SISTEMI DISTRIBUITI E CLOUD COMPUTING • PROGETTO D'ESAME
            </div>
            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
              Analisi dell'Esposizione Pubblica di Dati Personali sui Social Network
            </h2>
            <p className="text-slate-400 text-xs sm:text-sm leading-relaxed">
              Questa applicazione a microservizi rileva le informazioni personali esposte pubblicamente
              (PII) e stima eventuali vettori di attacco di ingegneria sociale.
              In produzione, la logica comunica direttamente con <strong>Amazon Web Services (AWS)</strong> via SDK Boto3
              (AWS Comprehend, Amazon Textract, Bedrock Runtime con LLM Claude e tabelle DynamoDB su EC2).
            </p>
          </div>
        </div>

        {/* Dashboard Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">

          {/* ============================== LEFT SIDE: CONTROL PANEL & FORM ============================== */}
          <div className="lg:col-span-5 space-y-6">

            {/* Quick-Test Templates Selector */}
            <div className="bg-slate-950 border border-slate-900 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                  Seleziona Template di Test
                </span>
                <span className="text-[10px] text-slate-500 font-mono">Unical Diagnostic</span>
              </div>
              <p className="text-[11px] text-slate-500">
                Usa un profilo preimpostato per popolare all'istante il form ed esaminare le diverse risposte del Mock AWS Comprehend/Bedrock.
              </p>

              <div className="space-y-1.5 pt-1">
                {DEMO_PROFILES.map((profile, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => applyTemplate(idx)}
                    className={`w-full text-left p-2.5 rounded text-xs font-mono transition-all border ${activeTemplate === idx
                        ? "bg-indigo-950/50 border-indigo-500 text-indigo-300"
                        : "bg-slate-900/50 border-slate-800 text-slate-300 hover:bg-slate-900"
                      }`}
                  >
                    <div className="flex justify-between items-center font-bold">
                      <span>{profile.label}</span>
                      <ArrowRight className="w-3.5 h-3.5 opacity-60" />
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Analysis Request Form */}
            <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-6 space-y-5">
              <div className="flex items-center gap-2.5 pb-3 border-b border-slate-900">
                <Cpu className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-sm uppercase tracking-wider font-mono">Configura Scansione</h3>
              </div>

              <form onSubmit={handleAnalyze} className="space-y-5">

                {/* 1. social_url field (mandatory) */}
                <div className="space-y-1.5">
                  <label htmlFor="social-url" className="text-xs font-bold text-slate-300 font-mono flex justify-between">
                    <span>SOCIAL URL (Obbligatorio)</span>
                    <span className="text-indigo-400 text-[10px]">*</span>
                  </label>
                  <div className="relative">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                    <input
                      id="social-url"
                      type="url"
                      required
                      value={socialUrl}
                      onChange={(e) => {
                        setSocialUrl(e.target.value);
                        setActiveTemplate(null);
                      }}
                      placeholder="https://instagram.com/filippo_abbeduto_27"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2.5 pl-10 pr-4 text-xs font-mono focus:outline-none focus:border-indigo-500 text-white placeholder-slate-600 transition-colors"
                    />
                  </div>
                </div>

                {/* 2. scraped_content field (optional) */}
                <div className="space-y-1.5">
                  <label htmlFor="scraped-content" className="text-xs font-bold text-slate-300 font-mono flex justify-between">
                    <span>BIO / CONTENUTO DEI POST (Opzionale)</span>
                    <span className="text-[10px] text-slate-550 font-normal">Regex Processor fallback</span>
                  </label>
                  <textarea
                    id="scraped-content"
                    rows={6}
                    value={scrapedContent}
                    onChange={(e) => {
                      setScrapedContent(e.target.value);
                      setActiveTemplate(null);
                    }}
                    placeholder="Se non inserito, il backend simulerà l'output di un scraper automatico (es. Apify)..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono focus:outline-none focus:border-indigo-500 text-white placeholder-slate-600 transition-colors resize-y leading-relaxed"
                  ></textarea>
                </div>

                {/* Form Buttons */}
                <div className="flex gap-3 pt-2">
                  <button
                    type="button"
                    onClick={handleClear}
                    disabled={isLoading}
                    className="w-1/3 bg-slate-950 hover:bg-slate-900 text-slate-400 hover:text-white border border-slate-800 rounded-lg py-2.5 text-xs font-bold font-mono transition-colors flex items-center justify-center gap-1.5 active:scale-95 disabled:opacity-50"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Clear
                  </button>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-2/3 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 text-white rounded-lg py-2.5 text-xs font-bold font-mono transition-all flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/10 active:scale-95 disabled:opacity-50"
                  >
                    {isLoading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin text-white" />
                        Analisi in corso...
                      </>
                    ) : (
                      <>
                        <RefreshCw className="w-3.5 h-3.5" />
                        Analizza Profilo
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>

            {/* Microservices Connection Info */}
            <div className="bg-slate-950 border border-slate-900 rounded-xl p-5 space-y-2.5 text-xs">
              <span className="font-mono text-[11px] font-bold text-slate-400 uppercase tracking-widest block">
                Docker Network Context
              </span>
              <div className="space-y-1.5 text-slate-400 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span>Routing Entrypoint:</span>
                  <span className="text-white">Nginx (Port 80)</span>
                </div>
                <div className="flex justify-between">
                  <span>Frontend Service:</span>
                  <span className="text-white">React SPA (Port 3000)</span>
                </div>
                <div className="flex justify-between">
                  <span>Backend API Service:</span>
                  <span className="text-white">FastAPI (Port 8000)</span>
                </div>
                <div className="flex justify-between">
                  <span>Mock AWS Engine:</span>
                  <span className="text-emerald-400 font-bold">Enabled (Offline)</span>
                </div>
              </div>
            </div>

          </div>

          {/* ============================== RIGHT SIDE: LIVE ANALYSIS RESULTS ============================== */}
          <div className="lg:col-span-7">

            {/* Error alerts */}
            {error && (
              <div className="bg-red-950/20 border-2 border-red-900/50 rounded-xl p-5 text-slate-100 flex gap-4 items-start animate-pulse mb-6">
                <AlertTriangle className="w-6 h-6 text-red-500 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="font-bold text-sm text-red-400 font-mono">Errore Comunione Microservizi</h4>
                  <p className="text-xs text-red-200 leading-relaxed">
                    {error}
                  </p>
                  <p className="text-[10px] text-slate-500 pt-2 font-mono">
                    Verificare che i container siano attivi digidando: <code>docker compose ps</code> nel terminale locale.
                  </p>
                </div>
              </div>
            )}

            {/* Async Job Status: PENDING / PROCESSING */}
            {isLoading && jobStatus && !result && (
              <div className="bg-gradient-to-br from-indigo-950/30 via-slate-950 to-slate-950 border border-indigo-900/40 rounded-xl p-8 text-center space-y-5 mb-6">
                <div className="relative w-16 h-16 mx-auto">
                  <div className="absolute inset-0 rounded-full border-2 border-indigo-500/20"></div>
                  <div className="absolute inset-0 rounded-full border-2 border-t-indigo-400 animate-spin"></div>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <Cpu className="w-6 h-6 text-indigo-400" />
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-sm font-bold font-mono text-white uppercase tracking-wider">
                    {jobStatus === "PENDING" ? "Analisi in Coda" : "Elaborazione in Corso"}
                  </h4>
                  <p className="text-xs text-slate-400 max-w-sm mx-auto leading-relaxed">
                    {jobStatus === "PENDING"
                      ? "Il job è stato accodato e verrà elaborato a breve dal worker cloud..."
                      : "Il worker sta analizzando il profilo: scraping, PII detection, risk scoring..."
                    }
                  </p>
                </div>

                {/* Status pills */}
                <div className="flex items-center justify-center gap-2 pt-2">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border ${
                    jobStatus === "PENDING"
                      ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                      : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full animate-pulse ${
                      jobStatus === "PENDING" ? "bg-amber-400" : "bg-emerald-400"
                    }`}></span>
                    {jobStatus}
                  </span>
                  <span className="text-[10px] font-mono text-slate-600">
                    Polling ogni 3s...
                  </span>
                </div>

                {/* Pipeline steps visualization */}
                <div className="flex items-center justify-center gap-1 pt-3">
                  {["Scraping", "PII Detection", "Risk Score", "Report"].map((step, idx) => (
                    <div key={step} className="flex items-center gap-1">
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${
                        jobStatus === "PROCESSING" && idx <= 1
                          ? "bg-indigo-500/10 text-indigo-400 border-indigo-500/30"
                          : "bg-slate-900 text-slate-600 border-slate-800"
                      }`}>
                        {step}
                      </span>
                      {idx < 3 && <ArrowRight className="w-2.5 h-2.5 text-slate-700" />}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Results Output */}
            {result && result.status === "COMPLETED" && result.risk_assessment ? (
              <div className="space-y-6">

                {/* 1. Global Risk Summary Card */}
                {(() => {
                  const styles = getRiskStyles(result.risk_assessment.risk_level);
                  return (
                    <div className={`border rounded-xl p-6 transition-all ${styles.bg}`}>

                      {/* Top Risk Header Row */}
                      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-4 border-b border-slate-900">
                        <div className="space-y-0.5">
                          <span className="text-[10px] font-mono tracking-widest text-slate-500 uppercase block">
                            AWS Risk Assessment Report
                          </span>
                          <h3 className="font-mono text-sm font-bold text-white flex items-center gap-2">
                            Report ID: <span className="text-slate-400 text-xs">{result.analysis_id.substring(0, 8)}...</span>
                          </h3>
                        </div>

                        <span className={`px-3 py-1 bg-slate-950 border rounded-md text-[10px] font-mono font-bold tracking-wider ${styles.badge}`}>
                          {styles.label}
                        </span>
                      </div>

                      {/* Level, score bar and justification explanation */}
                      <div className="pt-4 space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 text-2xl font-black font-mono tracking-tight text-white uppercase">
                            <span className={`w-3 h-3 rounded-full ${styles.indicator} animate-ping shrink-0`}></span>
                            <span className={styles.accentText}>{result.risk_assessment.risk_level} LEVEL</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Activity className={`w-4 h-4 ${styles.accentText}`} />
                            <span className={`text-2xl font-black font-mono ${styles.accentText}`}>
                              {result.risk_assessment.score}
                            </span>
                            <span className="text-xs font-mono text-slate-500">/100</span>
                          </div>
                        </div>

                        {/* Visual Score Bar */}
                        <div className="space-y-1.5">
                          <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all duration-1000 ease-out ${
                                result.risk_assessment.score >= 70
                                  ? "bg-gradient-to-r from-red-600 to-red-400"
                                  : result.risk_assessment.score >= 35
                                    ? "bg-gradient-to-r from-amber-600 to-amber-400"
                                    : "bg-gradient-to-r from-emerald-600 to-emerald-400"
                              }`}
                              style={{ width: `${result.risk_assessment.score}%` }}
                            ></div>
                          </div>
                          <div className="flex justify-between text-[9px] font-mono text-slate-600">
                            <span>0 — Sicuro</span>
                            <span>35 — Medio</span>
                            <span>70 — Alto</span>
                            <span>100</span>
                          </div>
                        </div>

                        <p className="text-slate-300 text-xs leading-relaxed font-sans">
                          {result.risk_assessment.explanation}
                        </p>

                        {/* Motivations Breakdown */}
                        {result.risk_assessment.motivations && result.risk_assessment.motivations.length > 0 && (
                          <div className="mt-2 pt-3 border-t border-slate-900/60 space-y-2">
                            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 block">
                              Breakdown Score — Contributi al Punteggio
                            </span>
                            <div className="space-y-1">
                              {result.risk_assessment.motivations.map((motivation, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-start gap-2 text-[11px] font-mono text-slate-400 bg-slate-950/50 rounded px-2.5 py-1.5 border border-slate-900/50"
                                >
                                  <ChevronRight className="w-3 h-3 text-indigo-500 shrink-0 mt-0.5" />
                                  <span>{motivation}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Social Target analyzed */}
                      <div className="mt-4 pt-3 border-t border-slate-900/60 flex flex-wrap gap-x-4 gap-y-2 text-[10px] font-mono text-slate-500">
                        <span>Target Social: <strong className="text-indigo-400">{result.social_url}</strong></span>
                        <span>Stato Richiesta: <strong className="text-emerald-400">{result.status}</strong></span>
                      </div>
                    </div>
                  );
                })()}

                {/* 2. Detected PII List (Simulating Comprehend or Textract matches via Python) */}
                <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-indigo-400" />
                      <h4 className="text-xs font-bold uppercase tracking-wider font-mono">Dati Sensibili Rilevati (PII)</h4>
                    </div>
                    <span className="text-[10px] font-mono bg-slate-950 text-indigo-400 border border-slate-800 px-2 py-0.5 rounded">
                      AWS Comprehend Mock
                    </span>
                  </div>

                  {(result.detected_pii || []).length > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500">
                            <th className="py-2 font-medium">Tipologia PII</th>
                            <th className="py-2 font-medium">Testo Individuato</th>
                            <th className="py-2 text-right font-medium">Confidence Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900/60">
                          {(result.detected_pii || []).map((entity, idx) => (
                            <tr key={idx} className="hover:bg-slate-900/30">
                              <td className="py-2.5 flex items-center gap-2">
                                {entity.type === "EMAIL" && <Mail className="w-3.5 h-3.5 text-indigo-400" />}
                                {entity.type === "PHONE_NUMBER" && <Phone className="w-3.5 h-3.5 text-indigo-400" />}
                                {entity.type === "LOCATION" && <MapPin className="w-3.5 h-3.5 text-indigo-400" />}
                                <span className="font-bold text-slate-200">{entity.type}</span>
                              </td>
                              <td className="py-2.5 text-slate-300 break-all select-all">
                                {entity.text}
                              </td>
                              <td className="py-2.5 text-right font-bold text-emerald-400">
                                {(entity.score * 100).toFixed(0)}%
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="p-6 bg-slate-950 border border-slate-900/80 rounded-lg text-center space-y-2">
                      <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
                      <h5 className="text-xs font-bold font-mono">Nessun dato personale individuato</h5>
                      <p className="text-[11px] text-slate-500">
                        L'algoritmo non ha isolato email o recapiti telefonici leggibili nel testo fornito.
                      </p>
                    </div>
                  )}
                </div>

                {/* 3. Threat Assessment Report Box (Simulating Claude-v2 on Bedrock APIs) */}
                <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <FileText className="w-4 h-4 text-indigo-400" />
                      <h4 className="text-xs font-bold uppercase tracking-wider font-mono">Rapporto Minacce Ingegneria Sociale</h4>
                    </div>
                    <span className="text-[10px] font-mono bg-slate-950 text-indigo-400 border border-slate-800 px-2 py-0.5 rounded">
                      Generative AI Claude
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Come richiesto per l'esame, l'AI esamina i pattern esposti e genera una simulazione dello spoofing basato sul contesto.
                  </p>

                  <div className="space-y-3.5">
                    {(result.social_engineering_report || []).map((threat, idx) => {
                      const isHigh = threat.severity.toUpperCase() === "HIGH";
                      const isMedium = threat.severity.toUpperCase() === "MEDIUM";
                      return (
                        <div
                          key={idx}
                          className={`rounded-lg p-4 border ${isHigh
                              ? "bg-red-950/10 border-red-950 text-red-200"
                              : isMedium
                                ? "bg-amber-955/10 border-amber-950 text-amber-200"
                                : "bg-slate-950 border-slate-900 text-slate-300"
                            }`}
                        >
                          <div className="flex justify-between items-center mb-1.5 font-mono">
                            <span className="text-xs font-bold tracking-tight text-white flex items-center gap-1.5">
                              <span className={`w-1.5 h-1.5 rounded-full ${isHigh ? "bg-red-500" : isMedium ? "bg-amber-500" : "bg-slate-500"}`}></span>
                              {threat.threat_vector}
                            </span>
                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${isHigh
                                ? "bg-red-500/10 text-red-400 border-red-500/30"
                                : isMedium
                                  ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                                  : "bg-slate-900 border-slate-800 text-slate-400"
                              }`}>
                              Gravità: {threat.severity}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">
                            {threat.explanation}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>

              </div>
            ) : (
              // Empty result state / instructions
              <div className="bg-slate-900/10 border border-slate-850 rounded-xl p-8 text-center space-y-4">
                <div className="w-12 h-12 rounded-full bg-slate-900/90 border border-slate-800 flex items-center justify-center text-slate-500 mx-auto">
                  <Terminal className="w-6 h-6" />
                </div>

                <div className="space-y-1 max-w-sm mx-auto">
                  <h4 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-300">
                    Nessuna scansione avviata
                  </h4>
                  <p className="text-xs text-slate-500 leading-relaxed">
                    Compila l'indirizzo social e il testo del profilo nel pannello di sinistra, oppure usa un template diagnostico ed esegui la scansione.
                  </p>
                </div>

                {/* Checklist to prompt correct project requirements for SDCC Oral Exam */}
                <div className="max-w-md mx-auto pt-4 border-t border-slate-900/80 text-left space-y-2 mt-4 text-[11px] text-slate-400 font-mono">
                  <span className="font-bold text-slate-300 block uppercase text-[10px] tracking-wider">
                    Checklist Requisiti d'Esame:
                  </span>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <span>Nginx porta 80 che rincanalizza sia React sia FastAPI</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <span>Integrazione OpenAPI Swagger via /api/docs</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <span>Analisi PII mockata asincrona via Python regex</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <span>Report sui rischi di ingegneria sociale preconfigurato</span>
                  </div>
                </div>
              </div>
            )}

          </div>
        </div>

      </main>

      {/* ==============================================================================
      # BOTTOM FOOTER INFO PART
      ============================================================================== */}
      <footer className="border-t border-slate-900 bg-slate-950 text-slate-500 py-8 mt-12 text-xs font-mono">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-center md:text-left">
            Progetto per l'esame di <strong className="text-slate-300">Sistemi Distribuiti e Cloud Computing</strong>.
          </p>
          <div className="flex items-center gap-4 text-slate-400">
            <span>Matricola: <strong>276572</strong></span>
            <span>Studente: <strong>Filippo Abbeduto</strong></span>
          </div>
        </div>
      </footer>

    </div>
  );
}
