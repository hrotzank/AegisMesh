import { useState } from "react";
import { motion } from "framer-motion";
import {
  Link2,
  ShieldAlert,
  ShieldCheck,
  Search,
  Globe,
  Clock,
  AlertTriangle,
  Sparkles,
  Copy,
  Check,
} from "lucide-react";

type RiskLevel = "Bajo" | "Medio" | "Alto" | "Crítico";

interface ScanFinding {
  severity: RiskLevel;
  title: string;
  detail: string;
}

interface LinkScanResult {
  url: string;
  domain: string;
  protocol: string;
  riskScore: number;
  riskLevel: RiskLevel;
  scannedAt: string;
  findings: ScanFinding[];
}

const SAMPLE_URLS = [
  "https://github.com/hrotzank/AegisMesh",
  "http://192.168.100.45:8080/login/verify-account",
  "http://secure-login.update-wallet.xyz/confirm?session=991",
];

const RISK_STYLES: Record<
  RiskLevel,
  { badge: string; bar: string; border: string; text: string }
> = {
  Bajo: {
    badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    bar: "bg-emerald-400",
    border: "border-emerald-500/30",
    text: "text-emerald-400",
  },
  Medio: {
    badge: "bg-sky-500/15 text-sky-400 border-sky-500/30",
    bar: "bg-sky-400",
    border: "border-sky-500/30",
    text: "text-sky-400",
  },
  Alto: {
    badge: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    bar: "bg-amber-400",
    border: "border-amber-500/30",
    text: "text-amber-400",
  },
  Crítico: {
    badge: "bg-rose-500/15 text-rose-400 border-rose-500/30",
    bar: "bg-rose-500",
    border: "border-rose-500/30",
    text: "text-rose-400",
  },
};

function fallbackLocalScan(rawUrl: string): LinkScanResult {
  const normalized = /^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`;
  let domain = "desconocido";
  let protocol = "HTTP";

  try {
    const parsed = new URL(normalized);
    domain = parsed.hostname;
    protocol = parsed.protocol.replace(":", "").toUpperCase();
  } catch {
    return {
      url: rawUrl,
      domain: "inválido",
      protocol: "N/A",
      riskScore: 88,
      riskLevel: "Crítico",
      scannedAt: new Date().toLocaleTimeString(),
      findings: [
        {
          severity: "Crítico",
          title: "Formato de URL inválido",
          detail: "No se pudo interpretar la estructura del enlace.",
        },
      ],
    };
  }

  let score = 12;
  const findings: ScanFinding[] = [];

  if (protocol !== "HTTPS") {
    score += 20;
    findings.push({
      severity: "Medio",
      title: "Conexión sin HTTPS",
      detail: "El enlace utiliza tráfico sin cifrar.",
    });
  }
  if (/login|verify|update|account|wallet|confirm|free/i.test(normalized)) {
    score += 28;
    findings.push({
      severity: "Alto",
      title: "Indicadores léxicos de phishing",
      detail: "Se detectaron palabras clave asociadas a robo de credenciales.",
    });
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    score += 35;
    findings.push({
      severity: "Alto",
      title: "IP literal como host",
      detail: "El enlace apunta directamente a una dirección IP.",
    });
  }

  const finalScore = Math.min(score, 98);
  const riskLevel: RiskLevel =
    finalScore >= 75
      ? "Crítico"
      : finalScore >= 50
      ? "Alto"
      : finalScore >= 25
      ? "Medio"
      : "Bajo";

  if (findings.length === 0) {
    findings.push({
      severity: "Bajo",
      title: "Sin anomalías evidentes",
      detail: "El análisis local no detectó patrones sospechosos.",
    });
  }

  return {
    url: rawUrl,
    domain,
    protocol,
    riskScore: finalScore,
    riskLevel,
    scannedAt: new Date().toLocaleTimeString(),
    findings,
  };
}

export function LinkScanner() {
  const [urlInput, setUrlInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LinkScanResult | null>(null);
  const [history, setHistory] = useState<LinkScanResult[]>([]);
  const [copied, setCopied] = useState(false);
  const [apiMode, setApiMode] = useState<"backend" | "fallback">("backend");

  const apiBase = `http://${window.location.hostname || "localhost"}:8000`;

  async function handleScan(targetUrl?: string) {
    const clean = (targetUrl ?? urlInput).trim();
    if (!clean) return;

    if (targetUrl) setUrlInput(targetUrl);
    setLoading(true);

    try {
      const response = await fetch(`${apiBase}/api/scan/link`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: clean }),
      });

      if (!response.ok) throw new Error("API error");
      const data: LinkScanResult = await response.json();
      setApiMode("backend");
      setResult(data);
      setHistory((prev) => [data, ...prev.slice(0, 5)]);
    } catch {
      const localData = fallbackLocalScan(clean);
      setApiMode("fallback");
      setResult(localData);
      setHistory((prev) => [localData, ...prev.slice(0, 5)]);
    } finally {
      setLoading(false);
    }
  }

  function handleCopyReport() {
    if (!result) return;
    const summary = `[AegisMesh Link Scanner] URL: ${result.url} | Riesgo: ${result.riskLevel} (${result.riskScore}/100) | Dominio: ${result.domain}`;
    navigator.clipboard.writeText(summary);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  const activeStyle = result ? RISK_STYLES[result.riskLevel] : RISK_STYLES.Bajo;

  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
            <Link2 className="h-4 w-4" />
            <span>Módulo de Inspección de URLs</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold text-slate-100">Link Scanner</h1>
          <p className="mt-1 text-sm text-slate-400">
            Análisis heurístico de enlaces, detección de homógrafos, acortadores y patrones de phishing.
          </p>
        </div>

        <div className="inline-flex items-center gap-2 self-start rounded-lg border border-slate-800 bg-[#0d1424]/90 px-3 py-1.5 text-xs font-mono text-slate-300">
          <span
            className={`h-2 w-2 rounded-full ${
              apiMode === "backend" ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
            }`}
          />
          <span>
            {apiMode === "backend" ? "FastAPI Engine Conectado" : "Modo Heurístico Local"}
          </span>
        </div>
      </div>

      {/* Barra de escaneo */}
      <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="flex flex-col gap-3 sm:flex-row"
        >
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Ingresa una URL para analizar (ej. https://ejemplo.com/login)"
              className="w-full rounded-lg border border-slate-700/80 bg-[#080d18] py-2.5 pl-10 pr-4 text-sm font-mono text-slate-100 placeholder-slate-500 outline-none transition focus:border-cyan-400/70"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !urlInput.trim()}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Sparkles className="h-4 w-4" />
            <span>{loading ? "Analizando..." : "Analizar Enlace"}</span>
          </button>
        </form>

        {/* Pruebas rápidas */}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-500">Pruebas rápidas:</span>
          {SAMPLE_URLS.map((sample) => (
            <button
              key={sample}
              type="button"
              onClick={() => handleScan(sample)}
              className="max-w-[260px] truncate rounded-md border border-slate-800 bg-[#080d18] px-2.5 py-1 text-xs font-mono text-slate-300 transition hover:border-cyan-500/40 hover:text-cyan-300"
            >
              {sample}
            </button>
          ))}
        </div>
      </div>

      {/* Resultado y historial */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Panel principal de resultados */}
        <div className="lg:col-span-2">
          {result ? (
            <motion.div
              key={result.url + result.scannedAt}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={`rounded-xl border ${activeStyle.border} bg-[#0d1424]/90 p-5 backdrop-blur-md space-y-5`}
            >
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800/80 pb-4">
                <div className="min-w-0 flex-1 pr-2">
                  <div className="flex items-center gap-2">
                    {result.riskLevel === "Bajo" ? (
                      <ShieldCheck className="h-5 w-5 shrink-0 text-emerald-400" />
                    ) : (
                      <ShieldAlert className={`h-5 w-5 shrink-0 ${activeStyle.text}`} />
                    )}
                    <h2 className="truncate font-mono text-base font-semibold text-slate-100">
                      {result.domain}
                    </h2>
                  </div>
                  <p className="mt-1 truncate font-mono text-xs text-slate-400">{result.url}</p>
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  <span
                    className={`rounded-md border px-3 py-1 text-xs font-mono font-semibold ${activeStyle.badge}`}
                  >
                    Riesgo {result.riskLevel} · {result.riskScore}/100
                  </span>
                  <button
                    type="button"
                    onClick={handleCopyReport}
                    title="Copiar resumen"
                    className="rounded-lg border border-slate-800 bg-[#080d18] p-2 text-slate-300 transition hover:border-slate-700 hover:text-cyan-400"
                  >
                    {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {/* Barra de score */}
              <div>
                <div className="mb-1.5 flex justify-between text-xs font-mono text-slate-400">
                  <span>Índice de amenaza</span>
                  <span className={activeStyle.text}>{result.riskScore}%</span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${result.riskScore}%` }}
                    transition={{ duration: 0.45 }}
                    className={`h-full rounded-full ${activeStyle.bar}`}
                  />
                </div>
              </div>

              {/* Metadatos técnicos */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-slate-800/80 bg-[#080d18] p-3">
                  <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                    <Globe className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Protocolo</span>
                  </div>
                  <p className="mt-1 font-mono text-sm font-semibold text-slate-100">
                    {result.protocol}
                  </p>
                </div>

                <div className="rounded-lg border border-slate-800/80 bg-[#080d18] p-3">
                  <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                    <AlertTriangle className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Hallazgos</span>
                  </div>
                  <p className="mt-1 font-mono text-sm font-semibold text-slate-100">
                    {result.findings.length}
                  </p>
                </div>

                <div className="rounded-lg border border-slate-800/80 bg-[#080d18] p-3">
                  <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                    <Clock className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Analizado</span>
                  </div>
                  <p className="mt-1 font-mono text-sm font-semibold text-slate-100">
                    {result.scannedAt}
                  </p>
                </div>
              </div>

              {/* Lista de hallazgos */}
              <div className="space-y-2.5">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Detalle de indicadores
                </h3>
                {result.findings.map((item, idx) => {
                  const itemStyle = RISK_STYLES[item.severity];
                  return (
                    <div
                      key={idx}
                      className="flex items-start justify-between gap-4 rounded-lg border border-slate-800/80 bg-[#080d18] px-4 py-3"
                    >
                      <div className="min-w-0 flex-1 pr-2">
                        <p className="text-sm font-medium text-slate-100">{item.title}</p>
                        <p className="mt-0.5 text-xs text-slate-400">{item.detail}</p>
                      </div>
                      <span
                        className={`shrink-0 rounded-md border px-2.5 py-0.5 text-xs font-mono font-semibold ${itemStyle.badge}`}
                      >
                        {item.severity}
                      </span>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          ) : (
            <div className="flex h-full min-h-[260px] flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-[#0d1424]/40 p-8 text-center">
              <Link2 className="h-9 w-9 text-cyan-400/70" />
              <p className="mt-3 text-sm font-medium text-slate-200">
                Listo para inspeccionar enlaces sospechosos
              </p>
              <p className="mt-1 max-w-md text-xs text-slate-400">
                Pega cualquier URL arriba o selecciona una de las pruebas rápidas para evaluar su nivel de riesgo.
              </p>
            </div>
          )}
        </div>

        {/* Panel derecho: historial de la sesión */}
        <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md">
          <h3 className="text-sm font-semibold text-slate-100">Escaneos de esta sesión</h3>
          <p className="mt-0.5 text-xs text-slate-400">Últimas URLs evaluadas</p>

          <div className="mt-4 space-y-2.5">
            {history.length === 0 ? (
              <p className="rounded-lg border border-slate-800/70 bg-[#080d18] px-3 py-6 text-center text-xs text-slate-500">
                Aún no se han realizado análisis en esta sesión.
              </p>
            ) : (
              history.map((entry, index) => {
                const st = RISK_STYLES[entry.riskLevel];
                return (
                  <button
                    key={`${entry.url}-${index}`}
                    type="button"
                    onClick={() => setResult(entry)}
                    className="flex w-full items-center justify-between gap-3 rounded-lg border border-slate-800/80 bg-[#080d18] px-3.5 py-2.5 text-left transition hover:border-cyan-500/40"
                  >
                    <div className="min-w-0 flex-1 pr-1">
                      <p className="truncate font-mono text-xs font-medium text-slate-200">
                        {entry.domain}
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
                        {entry.scannedAt}
                      </p>
                    </div>
                    <span
                      className={`shrink-0 rounded px-2 py-0.5 text-[11px] font-mono font-semibold border ${st.badge}`}
                    >
                      {entry.riskLevel}
                    </span>
                  </button>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}