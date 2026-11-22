import { useState, type ChangeEvent } from "react";
import { motion } from "framer-motion";
import {
  FileSearch,
  Upload,
  ShieldAlert,
  ShieldCheck,
  FileCode2,
  HardDrive,
  Hash,
  Clock,
  Copy,
  Check,
} from "lucide-react";

type RiskLevel = "Bajo" | "Medio" | "Alto" | "Crítico";

interface ScanFinding {
  severity: RiskLevel;
  title: string;
  detail: string;
}

interface FileScanResult {
  filename: string;
  extension: string;
  sizeBytes: number;
  sha256: string;
  mimeType: string;
  riskScore: number;
  riskLevel: RiskLevel;
  scannedAt: string;
  findings: ScanFinding[];
}

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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, idx);
  return `${val.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

async function computeSha256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fallbackFileScan(
  filename: string,
  sizeBytes: number,
  sha256: string,
  mimeType: string
): FileScanResult {
  const lower = filename.toLowerCase();
  const parts = lower.split(".").filter(Boolean);
  const ext = parts.length >= 2 ? `.${parts[parts.length - 1]}` : "sin extensión";

  let score = 12;
  const findings: ScanFinding[] = [];

  if (/\.(pdf|docx?|xlsx?|png|jpg|txt)\.(exe|bat|cmd|ps1|vbs|scr)$/i.test(lower)) {
    score += 38;
    findings.push({
      severity: "Crítico",
      title: "Doble extensión sospechosa",
      detail: "El nombre sugiere un archivo ejecutable camuflado.",
    });
  }
  if (/\.(exe|dll|bat|cmd|ps1|vbs|scr|apk|jar|msi)$/i.test(ext)) {
    score += 30;
    findings.push({
      severity: "Alto",
      title: `Extensión de alto riesgo (${ext})`,
      detail: "Archivo ejecutable, script o paquete instalable.",
    });
  }
  if (sizeBytes === 0) {
    score += 15;
    findings.push({
      severity: "Medio",
      title: "Archivo vacío",
      detail: "El archivo pesa 0 bytes.",
    });
  }

  const finalScore = Math.min(score, 99);
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
      title: "Sin anomalías detectadas",
      detail: "La inspección local no encontró patrones de riesgo.",
    });
  }

  return {
    filename,
    extension: ext,
    sizeBytes,
    sha256,
    mimeType: mimeType || "application/octet-stream",
    riskScore: finalScore,
    riskLevel,
    scannedAt: new Date().toLocaleTimeString(),
    findings,
  };
}

export function FileScanner() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<FileScanResult | null>(null);
  const [history, setHistory] = useState<FileScanResult[]>([]);
  const [copiedHash, setCopiedHash] = useState(false);
  const [apiMode, setApiMode] = useState<"backend" | "fallback">("backend");

  const apiBase = `http://${window.location.hostname || "localhost"}:8000`;

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;

    setLoading(true);
    try {
      const sha256 = await computeSha256(file);
      const payload = {
        filename: file.name,
        size_bytes: file.size,
        sha256,
        mime_type: file.type || "application/octet-stream",
      };

      const res = await fetch(`${apiBase}/api/scan/file`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error("API error");
      const data: FileScanResult = await res.json();
      setApiMode("backend");
      setResult(data);
      setHistory((prev) => [data, ...prev.slice(0, 5)]);
    } catch {
      const sha256 = await computeSha256(file).catch(() => "no-disponible");
      const localData = fallbackFileScan(file.name, file.size, sha256, file.type);
      setApiMode("fallback");
      setResult(localData);
      setHistory((prev) => [localData, ...prev.slice(0, 5)]);
    } finally {
      setLoading(false);
      event.target.value = "";
    }
  }

  function handleCopyHash() {
    if (!result?.sha256) return;
    navigator.clipboard.writeText(result.sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 1800);
  }

  const activeStyle = result ? RISK_STYLES[result.riskLevel] : RISK_STYLES.Bajo;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-cyan-400">
            <FileSearch className="h-4 w-4" />
            <span>Módulo de Análisis de Archivos</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold text-slate-100">File Scanner</h1>
          <p className="mt-1 text-sm text-slate-400">
            Cálculo de hash SHA-256, detección de dobles extensiones, ejecutables y metadatos de riesgo.
          </p>
        </div>

        <div className="inline-flex items-center gap-2 self-start rounded-lg border border-slate-800 bg-[#0d1424]/90 px-3 py-1.5 font-mono text-xs text-slate-300">
          <span
            className={`h-2 w-2 rounded-full ${
              apiMode === "backend" ? "animate-pulse bg-emerald-400" : "bg-amber-400"
            }`}
          />
          <span>
            {apiMode === "backend" ? "FastAPI Engine Conectado" : "Modo Heurístico Local"}
          </span>
        </div>
      </div>

      <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/90 bg-[#0d1424]/80 p-7 text-center transition hover:border-cyan-400/60 hover:bg-[#0d1424]">
        <Upload className="h-8 w-8 text-cyan-400" />
        <span className="mt-3 text-sm font-semibold text-slate-100">
          {loading ? "Calculando SHA-256 y analizando archivo..." : "Selecciona un archivo para inspeccionar"}
        </span>
        <span className="mt-1 font-mono text-xs text-slate-400">
          El hash SHA-256 se calcula localmente en tu navegador antes de evaluar el riesgo
        </span>
        <input type="file" onChange={handleFileChange} disabled={loading} className="hidden" />
      </label>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          {result ? (
            <motion.div
              key={result.sha256 + result.scannedAt}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={`space-y-5 rounded-xl border ${activeStyle.border} bg-[#0d1424]/90 p-5 backdrop-blur-md`}
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
                      {result.filename}
                    </h2>
                  </div>
                  <p className="mt-1 truncate font-mono text-xs text-slate-400">
                    MIME: {result.mimeType}
                  </p>
                </div>

                <span
                  className={`shrink-0 rounded-md border px-3 py-1 font-mono text-xs font-semibold ${activeStyle.badge}`}
                >
                  Riesgo {result.riskLevel} · {result.riskScore}/100
                </span>
              </div>

              <div>
                <div className="mb-1.5 flex justify-between font-mono text-xs text-slate-400">
                  <span>Puntuación heurística de archivo</span>
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

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-slate-800/80 bg-[#080d18] p-3">
                  <div className="flex items-center gap-1.5 font-mono text-xs text-slate-400">
                    <FileCode2 className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Extensión</span>
                  </div>
                  <p className="mt-1 font-mono text-sm font-semibold text-slate-100">
                    {result.extension}
                  </p>
                </div>

                <div className="rounded-lg border border-slate-800/80 bg-[#080d18] p-3">
                  <div className="flex items-center gap-1.5 font-mono text-xs text-slate-400">
                    <HardDrive className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Tamaño</span>
                  </div>
                  <p className="mt-1 font-mono text-sm font-semibold text-slate-100">
                    {formatBytes(result.sizeBytes)}
                  </p>
                </div>

                <div className="rounded-lg border border-slate-800/80 bg-[#080d18] p-3">
                  <div className="flex items-center gap-1.5 font-mono text-xs text-slate-400">
                    <Clock className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Analizado</span>
                  </div>
                  <p className="mt-1 font-mono text-sm font-semibold text-slate-100">
                    {result.scannedAt}
                  </p>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800/80 bg-[#080d18] p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 font-mono text-xs text-slate-400">
                    <Hash className="h-3.5 w-3.5 text-cyan-400" />
                    <span>SHA-256</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleCopyHash}
                    className="inline-flex items-center gap-1 rounded border border-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-300 transition hover:text-cyan-400"
                  >
                    {copiedHash ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" />
                        <span>Copiado</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copiar</span>
                      </>
                    )}
                  </button>
                </div>
                <p className="mt-1.5 break-all font-mono text-xs text-cyan-300">{result.sha256}</p>
              </div>

              <div className="space-y-2.5">
                <h3 className="font-mono text-xs uppercase tracking-wider text-slate-400">
                  Indicadores evaluados
                </h3>
                {result.findings.map((item, idx) => {
                  const st = RISK_STYLES[item.severity];
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
                        className={`shrink-0 rounded-md border px-2.5 py-0.5 font-mono text-xs font-semibold ${st.badge}`}
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
              <FileSearch className="h-9 w-9 text-cyan-400/70" />
              <p className="mt-3 text-sm font-medium text-slate-200">
                Ningún archivo analizado todavía
              </p>
              <p className="mt-1 max-w-md text-xs text-slate-400">
                Selecciona cualquier archivo arriba para generar su hash SHA-256 y revisar extensiones, tamaño y riesgo.
              </p>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md">
          <h3 className="text-sm font-semibold text-slate-100">Archivos de esta sesión</h3>
          <p className="mt-0.5 text-xs text-slate-400">Últimos archivos inspeccionados</p>

          <div className="mt-4 space-y-2.5">
            {history.length === 0 ? (
              <p className="rounded-lg border border-slate-800/70 bg-[#080d18] px-3 py-6 text-center text-xs text-slate-500">
                Aún no se han escaneado archivos.
              </p>
            ) : (
              history.map((entry, index) => {
                const st = RISK_STYLES[entry.riskLevel];
                return (
                  <button
                    key={`${entry.sha256}-${index}`}
                    type="button"
                    onClick={() => setResult(entry)}
                    className="flex w-full items-center justify-between gap-3 rounded-lg border border-slate-800/80 bg-[#080d18] px-3.5 py-2.5 text-left transition hover:border-cyan-500/40"
                  >
                    <div className="min-w-0 flex-1 pr-1">
                      <p className="truncate font-mono text-xs font-medium text-slate-200">
                        {entry.filename}
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
                        {formatBytes(entry.sizeBytes)} · {entry.scannedAt}
                      </p>
                    </div>
                    <span
                      className={`shrink-0 rounded border px-2 py-0.5 font-mono text-[11px] font-semibold ${st.badge}`}
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