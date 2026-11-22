import { useState, type ChangeEvent } from "react";
import { motion } from "framer-motion";
import {
  Smartphone,
  Upload,
  ShieldAlert,
  ShieldCheck,
  Binary,
  Layers,
  Cpu,
  Clock,
  Copy,
  Check,
  AlertTriangle,
  FolderArchive,
  Info,
} from "lucide-react";

type RiskLevel = "Bajo" | "Medio" | "Alto" | "Crítico";

interface ScanFinding {
  severity: RiskLevel;
  title: string;
  detail: string;
}

interface ApkScanResult {
  filename: string;
  sizeBytes: number;
  sha256: string;
  totalEntries: number;
  dexCount: number;
  nativeLibCount: number;
  hasManifest: boolean;
  permissionsAnalyzed: string[];
  riskScore: number;
  riskLevel: RiskLevel;
  scannedAt: string;
  findings: ScanFinding[];
}

interface CommonPermission {
  id: string;
  name: string;
  severity: RiskLevel;
  description: string;
}

const COMMON_PERMISSIONS: CommonPermission[] = [
  {
    id: "BIND_ACCESSIBILITY_SERVICE",
    name: "Accessibility Service",
    severity: "Crítico",
    description: "Control de interfaz, lectura de pantalla y captura de teclas (keylogger).",
  },
  {
    id: "SYSTEM_ALERT_WINDOW",
    name: "System Overlay",
    severity: "Crítico",
    description: "Ventana flotante sobre otras aplicaciones para captura de credenciales.",
  },
  {
    id: "REQUEST_INSTALL_PACKAGES",
    name: "Install Packages",
    severity: "Alto",
    description: "Descarga e instalación silenciosa de otros paquetes APK.",
  },
  {
    id: "READ_SMS",
    name: "Read SMS",
    severity: "Alto",
    description: "Lectura de mensajes SMS (interceptación de códigos OTP/2FA).",
  },
  {
    id: "SEND_SMS",
    name: "Send SMS",
    severity: "Alto",
    description: "Envío no autorizado de SMS a servicios de tarificación.",
  },
  {
    id: "RECEIVE_SMS",
    name: "Receive SMS",
    severity: "Alto",
    description: "Recepción e interceptación de mensajes entrantes.",
  },
  {
    id: "RECORD_AUDIO",
    name: "Record Audio",
    severity: "Alto",
    description: "Activación del micrófono en segundo plano.",
  },
  {
    id: "ACCESS_FINE_LOCATION",
    name: "Fine Location",
    severity: "Medio",
    description: "Ubicación GPS precisa y continua del terminal móvil.",
  },
  {
    id: "READ_CONTACTS",
    name: "Read Contacts",
    severity: "Medio",
    description: "Extracción y filtrado de la agenda de contactos.",
  },
  {
    id: "INTERNET",
    name: "Internet Access",
    severity: "Bajo",
    description: "Comunicaciones de red salientes hacia servidores remotos.",
  },
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

// Extractor ligero de nombres de archivo del catálogo Central Directory del formato ZIP/APK
async function extractZipEntries(file: File): Promise<string[]> {
  try {
    const buffer = await file.arrayBuffer();
    const data = new DataView(buffer);
    const len = data.byteLength;
    const entries: string[] = [];

    // Buscar la firma End of Central Directory (0x06054b50) desde el final
    let eocdOffset = -1;
    for (let i = len - 22; i >= Math.max(0, len - 65557); i--) {
      if (data.getUint32(i, true) === 0x06054b50) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset !== -1) {
      const cdOffset = data.getUint32(eocdOffset + 16, true);
      const totalEntriesCount = data.getUint16(eocdOffset + 10, true);
      let ptr = cdOffset;
      const decoder = new TextDecoder("utf-8");

      for (let i = 0; i < totalEntriesCount && ptr + 46 <= len; i++) {
        if (data.getUint32(ptr, true) !== 0x02014b50) break;
        const nameLen = data.getUint16(ptr + 28, true);
        const extraLen = data.getUint16(ptr + 30, true);
        const commentLen = data.getUint16(ptr + 32, true);

        if (ptr + 46 + nameLen <= len) {
          const nameBytes = new Uint8Array(buffer, ptr + 46, nameLen);
          entries.push(decoder.decode(nameBytes));
        }
        ptr += 46 + nameLen + extraLen + commentLen;
      }
    } else {
      // Fallback: escanear cabeceras locales de archivo (0x04034b50)
      let ptr = 0;
      const decoder = new TextDecoder("utf-8");
      while (ptr + 30 <= len) {
        if (data.getUint32(ptr, true) === 0x04034b50) {
          const nameLen = data.getUint16(ptr + 26, true);
          const extraLen = data.getUint16(ptr + 28, true);
          if (ptr + 30 + nameLen <= len) {
            const nameBytes = new Uint8Array(buffer, ptr + 30, nameLen);
            entries.push(decoder.decode(nameBytes));
          }
          ptr += 30 + nameLen + extraLen;
        } else {
          ptr++;
        }
        if (entries.length > 5000) break;
      }
    }

    return entries;
  } catch {
    return [];
  }
}

function fallbackApkScan(
  filename: string,
  sizeBytes: number,
  sha256: string,
  entries: string[],
  selectedPermissions: string[]
): ApkScanResult {
  const lowerName = filename.toLowerCase();
  const lowerEntries = entries.map((e) => e.toLowerCase());
  const hasManifest = lowerEntries.some((e) => e.endsWith("androidmanifest.xml"));
  const dexFiles = lowerEntries.filter((e) => e.endsWith(".dex"));
  const nativeLibs = lowerEntries.filter((e) => e.startsWith("lib/") && e.endsWith(".so"));

  let score = 10;
  const findings: ScanFinding[] = [];

  if (!lowerName.endswith(".apk")) {
    score += 25;
    findings.push({
      severity: "Alto",
      title: "Extensión no estándar",
      detail: "El archivo analizado no finaliza en extensión .apk.",
    });
  }

  if (entries.length > 0) {
    if (!hasManifest) {
      score += 30;
      findings.push({
        severity: "Alto",
        title: "Ausencia de AndroidManifest.xml",
        detail: "No se identificó el manifiesto principal del paquete Android.",
      });
    }

    if (dexFiles.length === 0) {
      score += 25;
      findings.push({
        severity: "Alto",
        title: "Sin bytecode Dalvik (.dex)",
        detail: "No se encontraron clases compiladas Dalvik (classes.dex).",
      });
    } else if (dexFiles.length > 4) {
      score += 15;
      findings.push({
        severity: "Medio",
        title: `Estructura multi-DEX (${dexFiles.length} archivos .dex)`,
        detail: "Paquete con múltiples artefactos DEX compilados.",
      });
    }

    if (nativeLibs.length > 0) {
      score += 10;
      findings.push({
        severity: "Medio",
        title: `Librerías nativas compiladas (${nativeLibs.length} archivos .so)`,
        detail: "Contiene código C/C++ compilado para arquitectura Android.",
      });
    }
  }

  let permScore = 0;
  selectedPermissions.forEach((p) => {
    const match = COMMON_PERMISSIONS.find((cp) => cp.id === p);
    if (match) {
      permScore += match.severity === "Crítico" ? 30 : match.severity === "Alto" ? 22 : 10;
      findings.push({
        severity: match.severity,
        title: `Permiso evaluado: ${match.name}`,
        detail: match.description,
      });
    }
  });

  if (
    selectedPermissions.includes("BIND_ACCESSIBILITY_SERVICE") &&
    (selectedPermissions.includes("SYSTEM_ALERT_WINDOW") || selectedPermissions.includes("READ_SMS"))
  ) {
    permScore += 20;
    findings.push({
      severity: "Crítico",
      title: "Vector de ataque combinado (Accessibility + Overlay/SMS)",
      detail: "Patrón heurístico compatible con troyanos bancarios y keyloggers móviles.",
    });
  }

  score += Math.min(permScore, 55);
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
      title: "Sin indicadores de riesgo severos",
      detail: "La configuración estructural y permisos no presentaron anomalías críticas.",
    });
  }

  return {
    filename,
    sizeBytes,
    sha256,
    totalEntries: entries.length,
    dexCount: dexFiles.length,
    nativeLibCount: nativeLibs.length,
    hasManifest,
    permissionsAnalyzed: selectedPermissions,
    riskScore: finalScore,
    riskLevel,
    scannedAt: new Date().toLocaleTimeString(),
    findings,
  };
}

export function ApkAnalyzer() {
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([
    "INTERNET",
    "BIND_ACCESSIBILITY_SERVICE",
    "SYSTEM_ALERT_WINDOW",
  ]);
  const [result, setResult] = useState<ApkScanResult | null>(null);
  const [history, setHistory] = useState<ApkScanResult[]>([]);
  const [copiedHash, setCopiedHash] = useState(false);
  const [apiMode, setApiMode] = useState<"backend" | "fallback">("backend");

  const apiBase = `http://${window.location.hostname || "localhost"}:8000`;

  function togglePermission(id: string) {
    setSelectedPermissions((prev) =>
      prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id]
    );
  }

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    await analyzeApk(file, selectedPermissions);
    event.target.value = "";
  }

  async function analyzeApk(file: File, permissions: string[]) {
    setLoading(true);
    try {
      const sha256 = await computeSha256(file);
      const entries = await extractZipEntries(file);

      const payload = {
        filename: file.name,
        size_bytes: file.size,
        sha256,
        entries,
        selected_permissions: permissions,
      };

      const res = await fetch(`${apiBase}/api/scan/apk`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error("API error");
      const data: ApkScanResult = await res.json();
      setApiMode("backend");
      setResult(data);
      setHistory((prev) => [data, ...prev.slice(0, 4)]);
    } catch {
      const sha256 = await computeSha256(file).catch(() => "no-disponible");
      const entries = await extractZipEntries(file).catch(() => []);
      const localData = fallbackApkScan(file.name, file.size, sha256, entries, permissions);
      setApiMode("fallback");
      setResult(localData);
      setHistory((prev) => [localData, ...prev.slice(0, 4)]);
    } finally {
      setLoading(false);
    }
  }

  function handleReanalyze() {
    if (selectedFile) {
      analyzeApk(selectedFile, selectedPermissions);
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
      {/* Encabezado */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-cyan-400">
            <Smartphone className="h-4 w-4" />
            <span>Módulo de Análisis de Aplicaciones Móviles</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-100">
            APK Analyzer & Permisos Android
          </h1>
          <p className="text-xs text-slate-400">
            Inspección estática de paquetes APK, manifiesto, Dalvik DEX, librerías nativas y correlación de permisos sensibles.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-xs ${
              apiMode === "backend"
                ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
                : "border-amber-500/30 bg-amber-500/10 text-amber-300"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                apiMode === "backend" ? "bg-cyan-400 animate-pulse" : "bg-amber-400"
              }`}
            />
            {apiMode === "backend" ? "API FastAPI Conectada" : "Motor Heurístico Local"}
          </span>
        </div>
      </div>

      {/* Grid Bento Principal */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Panel Izquierdo: Carga de APK y Selector de Permisos */}
        <div className="space-y-5 lg:col-span-1">
          {/* Tarjeta Dropzone */}
          <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Upload className="h-4 w-4 text-cyan-400" />
              Cargar Paquete Android (.apk)
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              Selecciona o arrastra un paquete para calcular hash y extraer el catálogo interno.
            </p>

            <label className="mt-4 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-700/80 bg-slate-900/50 p-6 text-center transition-all hover:border-cyan-500/50 hover:bg-slate-900/80 cursor-pointer">
              <input
                type="file"
                accept=".apk,application/vnd.android.package-archive"
                onChange={handleFileChange}
                disabled={loading}
                className="hidden"
              />
              <motion.div
                animate={loading ? { rotate: 360 } : {}}
                transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                className="rounded-xl bg-cyan-500/10 border border-cyan-400/20 p-3 text-cyan-400"
              >
                {loading ? (
                  <Layers className="h-6 w-6" />
                ) : (
                  <Smartphone className="h-6 w-6" />
                )}
              </motion.div>
              <p className="mt-3 text-xs font-medium text-slate-200">
                {loading ? "Analizando estructura APK..." : "Haz clic o arrastra un archivo .apk"}
              </p>
              <p className="text-[11px] text-slate-500 mt-0.5">
                {selectedFile ? selectedFile.name : "Archivos soportados: APK, ZIP empaquetado"}
              </p>
            </label>
          </div>

          {/* Tarjeta Selector de Permisos Android */}
          <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-amber-400" />
                Permisos a Correlacionar
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {selectedPermissions.length} activos
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-400">
              Marca o desmarca los permisos para evaluar la superficie de ataque móvil.
            </p>

            <div className="mt-3 space-y-2 max-h-72 overflow-y-auto pr-1">
              {COMMON_PERMISSIONS.map((perm) => {
                const checked = selectedPermissions.includes(perm.id);
                return (
                  <button
                    key={perm.id}
                    type="button"
                    onClick={() => togglePermission(perm.id)}
                    className={`w-full flex items-start gap-2.5 p-2 rounded-lg border text-left transition-all text-xs ${
                      checked
                        ? "border-cyan-500/40 bg-cyan-500/10 text-slate-100"
                        : "border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => {}}
                      className="mt-0.5 accent-cyan-400 cursor-pointer"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-mono font-medium text-slate-200 truncate">
                          {perm.name}
                        </span>
                        <span
                          className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${
                            RISK_STYLES[perm.severity].badge
                          }`}
                        >
                          {perm.severity}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 line-clamp-1 mt-0.5">
                        {perm.description}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>

            {selectedFile && (
              <button
                type="button"
                onClick={handleReanalyze}
                disabled={loading}
                className="mt-3 w-full py-2 rounded-lg bg-cyan-500/15 border border-cyan-400/30 text-cyan-300 text-xs font-mono font-semibold hover:bg-cyan-500/25 transition-colors disabled:opacity-50"
              >
                Reanalizar con permisos seleccionados
              </button>
            )}
          </div>
        </div>

        {/* Panel Central / Derecho: Resultados del Análisis */}
        <div className="space-y-5 lg:col-span-2">
          {result ? (
            <>
              {/* Tarjeta de Riesgo y Resumen Superior */}
              <div
                className={`rounded-xl border ${activeStyle.border} bg-[#0d1424]/90 p-5 backdrop-blur-md space-y-4`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                  <div className="min-w-0">
                    <p className="font-mono text-xs uppercase text-slate-400">
                      Paquete Analizado
                    </p>
                    <h3 className="text-lg font-bold text-slate-100 truncate">
                      {result.filename}
                    </h3>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <p className="text-[11px] font-mono text-slate-400">Nivel de Riesgo</p>
                      <span
                        className={`inline-block text-xs font-bold font-mono px-2.5 py-0.5 rounded border ${activeStyle.badge}`}
                      >
                        {result.riskLevel}
                      </span>
                    </div>
                    <div className="text-2xl font-black font-mono text-slate-100">
                      {result.riskScore}
                      <span className="text-xs font-normal text-slate-500">/99</span>
                    </div>
                  </div>
                </div>

                {/* Barra de Progreso de Riesgo */}
                <div className="space-y-1.5">
                  <div className="flex justify-between text-[11px] font-mono text-slate-400">
                    <span>Índice Heurístico de Amenaza</span>
                    <span>{result.riskScore}%</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800/90 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${result.riskScore}%` }}
                      transition={{ duration: 0.6, ease: "easeOut" }}
                      className={`h-full ${activeStyle.bar}`}
                    />
                  </div>
                </div>

                {/* Metadatos SHA-256 */}
                <div className="flex items-center justify-between gap-2 rounded-lg bg-slate-900/70 border border-slate-800/80 p-2.5 text-xs font-mono">
                  <div className="flex items-center gap-2 min-w-0 truncate">
                    <Binary className="h-4 w-4 text-cyan-400 shrink-0" />
                    <span className="text-slate-400 shrink-0">SHA-256:</span>
                    <span className="text-slate-200 truncate">{result.sha256}</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleCopyHash}
                    className="flex items-center gap-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:text-white shrink-0 transition-colors"
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
              </div>

              {/* Bento de Métricas del Paquete */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Entradas ZIP</span>
                    <FolderArchive className="h-3.5 w-3.5 text-cyan-400" />
                  </div>
                  <p className="mt-2 text-xl font-bold font-mono text-slate-100">
                    {result.totalEntries}
                  </p>
                  <p className="text-[10px] text-slate-500">Catálogo interno</p>
                </div>

                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Archivos .DEX</span>
                    <Layers className="h-3.5 w-3.5 text-sky-400" />
                  </div>
                  <p className="mt-2 text-xl font-bold font-mono text-slate-100">
                    {result.dexCount}
                  </p>
                  <p className="text-[10px] text-slate-500">
                    {result.dexCount > 1 ? "Multi-DEX" : "Dalvik standard"}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Librerías .SO</span>
                    <Cpu className="h-3.5 w-3.5 text-amber-400" />
                  </div>
                  <p className="mt-2 text-xl font-bold font-mono text-slate-100">
                    {result.nativeLibCount}
                  </p>
                  <p className="text-[10px] text-slate-500">
                    {result.nativeLibCount > 0 ? "Código C/C++" : "Sin código nativo"}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Manifest XML</span>
                    <Info className="h-3.5 w-3.5 text-emerald-400" />
                  </div>
                  <p className="mt-2 text-xl font-bold font-mono text-slate-100">
                    {result.hasManifest ? "Presente" : "No detectado"}
                  </p>
                  <p className="text-[10px] text-slate-500">
                    {formatBytes(result.sizeBytes)}
                  </p>
                </div>
              </div>

              {/* Hallazgos y Correlación */}
              <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md space-y-3">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-cyan-400" />
                  Hallazgos de Seguridad e Indicadores ({result.findings.length})
                </h3>

                <div className="space-y-2.5">
                  {result.findings.map((finding, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-slate-800/90 bg-slate-900/60 p-3 space-y-1"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-slate-200">
                          {finding.title}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            RISK_STYLES[finding.severity].badge
                          }`}
                        >
                          {finding.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {finding.detail}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            /* Estado Inicial sin archivo */
            <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-12 text-center backdrop-blur-md">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400">
                <Smartphone className="h-7 w-7" />
              </div>
              <h3 className="mt-4 text-base font-semibold text-slate-200">
                Esperando Paquete APK
              </h3>
              <p className="mx-auto mt-1 max-w-md text-xs text-slate-400">
                Carga un archivo .apk en el panel izquierdo para inspeccionar sus clases DEX, manifiesto, librerías nativas y el impacto de permisos de accesibilidad o monitoreo.
              </p>
            </div>
          )}

          {/* Historial de la Sesión */}
          {history.length > 0 && (
            <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-4 backdrop-blur-md space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-cyan-400" />
                  Historial de Paquetes en Sesión
                </span>
                <span>{history.length} analizados</span>
              </div>

              <div className="divide-y divide-slate-800/60">
                {history.map((item, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between py-2 text-xs"
                  >
                    <div className="min-w-0 pr-2">
                      <p className="font-mono text-slate-200 truncate">{item.filename}</p>
                      <p className="text-[10px] text-slate-500 font-mono">
                        {formatBytes(item.sizeBytes)} • {item.dexCount} DEX • {item.scannedAt}
                      </p>
                    </div>
                    <span
                      className={`font-mono text-[10px] px-2 py-0.5 rounded border ${
                        RISK_STYLES[item.riskLevel].badge
                      }`}
                    >
                      {item.riskLevel} ({item.riskScore})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
