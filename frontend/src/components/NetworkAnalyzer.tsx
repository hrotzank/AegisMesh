import { useState, type FormEvent } from "react";
import { motion } from "framer-motion";
import {
  Network,
  Search,
  ShieldAlert,
  ShieldCheck,
  Server,
  Globe,
  Radio,
  Clock,
  AlertTriangle,
  Lock,
  Unlock,
  Sliders,
  ChevronRight,
  RotateCcw,
} from "lucide-react";

type RiskLevel = "Bajo" | "Medio" | "Alto" | "Crítico";

interface ScanFinding {
  severity: RiskLevel;
  title: string;
  detail: string;
}

interface PortDetail {
  port: number;
  service: string;
  severity: RiskLevel;
}

interface NetworkScanResult {
  target: string;
  resolvedHost: string;
  targetType: string;
  networkScope: string;
  openOrCheckedPorts: PortDetail[];
  riskScore: number;
  riskLevel: RiskLevel;
  scannedAt: string;
  findings: ScanFinding[];
}

interface CommonPortPreset {
  port: number;
  service: string;
  category: "Web" | "Admin" | "Datos" | "Legacy";
}

const COMMON_PORTS: CommonPortPreset[] = [
  { port: 21, service: "FTP", category: "Legacy" },
  { port: 22, service: "SSH", category: "Admin" },
  { port: 23, service: "Telnet", category: "Legacy" },
  { port: 25, service: "SMTP", category: "Admin" },
  { port: 53, service: "DNS", category: "Admin" },
  { port: 80, service: "HTTP", category: "Web" },
  { port: 443, service: "HTTPS", category: "Web" },
  { port: 445, service: "SMB", category: "Legacy" },
  { port: 3306, service: "MySQL", category: "Datos" },
  { port: 3389, service: "RDP", category: "Admin" },
  { port: 5432, service: "PostgreSQL", category: "Datos" },
  { port: 8080, service: "HTTP-Alt", category: "Web" },
];

const SAMPLE_TARGETS = [
  { label: "Gateway LAN", target: "192.168.100.1", ports: [22, 80, 443] },
  { label: "Subred Interna", target: "192.168.100.0/24", ports: [80, 443, 8080] },
  { label: "Host Público (Nmap)", target: "scanme.nmap.org", ports: [22, 80] },
  { label: "Servidor Crítico Expuesto", target: "203.0.113.10", ports: [21, 23, 445, 3389] },
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

const SCOPE_BADGES: Record<string, string> = {
  "Red Privada / LAN": "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
  "Loopback / Localhost": "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
  "Link-Local": "bg-slate-500/10 text-slate-300 border-slate-500/30",
  "Internet Pública": "bg-amber-500/10 text-amber-300 border-amber-500/30",
};

function fallbackNetworkScan(target: string, ports: number[]): NetworkScanResult {
  const cleanTarget = target.trim().replace(/^https?:\/\//, "");
  const isCidr = cleanTarget.includes("/");
  const isPrivate =
    cleanTarget.startsWith("192.168.") ||
    cleanTarget.startsWith("10.") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanTarget);
  const isLoopback = cleanTarget.startsWith("127.") || cleanTarget.toLowerCase() === "localhost";

  const networkScope = isLoopback
    ? "Loopback / Localhost"
    : isPrivate
    ? "Red Privada / LAN"
    : "Internet Pública";

  const targetType = isCidr
    ? "Subred CIDR IPv4"
    : /^\d{1,3}(\.\d{1,3}){3}$/.test(cleanTarget)
    ? "Dirección IPv4"
    : "Dominio / FQDN";

  let score = 10;
  const findings: ScanFinding[] = [];

  if (networkScope === "Internet Pública") {
    score += 15;
    findings.push({
      severity: "Medio",
      title: "Exposición en Internet Pública",
      detail: "El objetivo se encuentra en direccionamiento público global accesible desde la red abierta.",
    });
  } else {
    findings.push({
      severity: "Bajo",
      title: `Ámbito protegido (${networkScope})`,
      detail: "Objetivo en segmento interno o interfaz loopback aislada tras enrutamiento perimetral.",
    });
  }

  const portsDetail: PortDetail[] = [];
  let portScore = 0;

  ports.forEach((p) => {
    const match = COMMON_PORTS.find((cp) => cp.port === p);
    const service = match ? match.service : `Puerto ${p}`;
    let severity: RiskLevel = "Bajo";

    if ([21, 23, 445, 6379, 27017].includes(p)) {
      severity = "Crítico";
      portScore += networkScope === "Internet Pública" ? 35 : 25;
      findings.push({
        severity: "Crítico",
        title: `Servicio vulnerable (${service} :${p})`,
        detail: "Protocolo sin cifrado o de alto riesgo con vulnerabilidades frecuentes de explotación.",
      });
    } else if ([3389, 1433, 3306, 5432].includes(p)) {
      severity = "Alto";
      portScore += networkScope === "Internet Pública" ? 28 : 18;
      findings.push({
        severity: "Alto",
        title: `Servicio de administración o datos (${service} :${p})`,
        detail: "Acceso sensible expuesto que requiere autenticación estricta o VPN previa.",
      });
    } else if ([22, 25, 53, 80, 8080].includes(p)) {
      severity = "Medio";
      portScore += 12;
      findings.push({
        severity: "Medio",
        title: `Servicio estándar (${service} :${p})`,
        detail: "Puerto en evaluación de superficie de ataque.",
      });
    } else {
      severity = "Bajo";
      portScore += 5;
    }

    portsDetail.push({ port: p, service, severity });
  });

  score += Math.min(portScore, 55);
  const finalScore = Math.min(score, 99);
  const riskLevel: RiskLevel =
    finalScore >= 75
      ? "Crítico"
      : finalScore >= 50
      ? "Alto"
      : finalScore >= 25
      ? "Medio"
      : "Bajo";

  return {
    target,
    resolvedHost: cleanTarget,
    targetType,
    networkScope,
    openOrCheckedPorts: portsDetail,
    riskScore: finalScore,
    riskLevel,
    scannedAt: new Date().toLocaleTimeString(),
    findings,
  };
}

export function NetworkAnalyzer() {
  const [targetInput, setTargetInput] = useState("192.168.100.1");
  const [selectedPorts, setSelectedPorts] = useState<number[]>([22, 80, 443, 3389, 8080]);
  const [customPortInput, setCustomPortInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NetworkScanResult | null>(null);
  const [history, setHistory] = useState<NetworkScanResult[]>([]);
  const [apiMode, setApiMode] = useState<"backend" | "fallback">("backend");

  const apiBase = `http://${window.location.hostname || "localhost"}:8000`;

  function togglePort(port: number) {
    setSelectedPorts((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port].sort((a, b) => a - b)
    );
  }

  function handleAddCustomPort(e: FormEvent) {
    e.preventDefault();
    const val = parseInt(customPortInput.trim(), 10);
    if (!isNaN(val) && val >= 1 && val <= 65535 && !selectedPorts.includes(val)) {
      setSelectedPorts((prev) => [...prev, val].sort((a, b) => a - b));
      setCustomPortInput("");
    }
  }

  function applyPreset(presetTarget: string, presetPorts: number[]) {
    setTargetInput(presetTarget);
    setSelectedPorts(presetPorts);
  }

  async function handleScan(e?: FormEvent) {
    if (e) e.preventDefault();
    const target = targetInput.trim();
    if (!target) return;

    setLoading(true);
    try {
      const payload = {
        target,
        ports: selectedPorts,
      };

      const res = await fetch(`${apiBase}/api/scan/network`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error("API error");
      const data: NetworkScanResult = await res.json();
      setApiMode("backend");
      setResult(data);
      setHistory((prev) => [data, ...prev.slice(0, 4)]);
    } catch {
      const localData = fallbackNetworkScan(target, selectedPorts);
      setApiMode("fallback");
      setResult(localData);
      setHistory((prev) => [localData, ...prev.slice(0, 4)]);
    } finally {
      setLoading(false);
    }
  }

  const activeStyle = result ? RISK_STYLES[result.riskLevel] : RISK_STYLES.Bajo;

  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-cyan-400">
            <Network className="h-4 w-4" />
            <span>Módulo de Exploración y Superficie de Red</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-100">
            Network Analyzer & Escáner de Puertos
          </h1>
          <p className="text-xs text-slate-400">
            Inspección de direccionamiento IP, subredes CIDR, dominios, ámbito de red y auditoría de superficie expuesta.
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
        {/* Panel Izquierdo: Configuración del Objetivo y Puertos */}
        <div className="space-y-5 lg:col-span-1">
          {/* Tarjeta Formulario de Entrada */}
          <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md space-y-4">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Search className="h-4 w-4 text-cyan-400" />
              Objetivo de Análisis
            </h2>

            <form onSubmit={handleScan} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  IP, SUBRED O DOMINIO
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    placeholder="ej. 192.168.1.1 o dominio.com"
                    className="w-full rounded-lg border border-slate-700/80 bg-slate-900/80 px-3 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
                  />
                </div>
              </div>

              {/* Botones de prueba rápida */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-mono uppercase text-slate-500">
                  Presets Rápidos:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {SAMPLE_TARGETS.map((sample) => (
                    <button
                      key={sample.label}
                      type="button"
                      onClick={() => applyPreset(sample.target, sample.ports)}
                      className="rounded border border-slate-800 bg-slate-900/60 px-2 py-0.5 text-[10px] font-mono text-slate-300 hover:border-cyan-500/40 hover:text-cyan-300 transition-colors"
                    >
                      {sample.label}
                    </button>
                  ))}
                </div>
              </div>

              <button
                type="submit"
                disabled={loading || !targetInput.trim()}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-500/20 border border-cyan-400/40 py-2.5 text-xs font-mono font-semibold text-cyan-300 hover:bg-cyan-500/30 transition-all disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <RotateCcw className="h-3.5 w-3.5 animate-spin" />
                    <span>Analizando Superficie...</span>
                  </>
                ) : (
                  <>
                    <Radio className="h-3.5 w-3.5" />
                    <span>Iniciar Auditoría de Red</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Tarjeta Selector de Puertos */}
          <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Sliders className="h-4 w-4 text-cyan-400" />
                Puertos a Evaluar
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {selectedPorts.length} puertos
              </span>
            </div>

            <div className="grid grid-cols-3 gap-1.5">
              {COMMON_PORTS.map((item) => {
                const active = selectedPorts.includes(item.port);
                return (
                  <button
                    key={item.port}
                    type="button"
                    onClick={() => togglePort(item.port)}
                    className={`flex flex-col items-center justify-center p-2 rounded-lg border text-center transition-all ${
                      active
                        ? "border-cyan-500/40 bg-cyan-500/12 text-cyan-300 shadow-sm"
                        : "border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    <span className="text-xs font-mono font-bold">{item.port}</span>
                    <span className="text-[10px] text-slate-400 truncate max-w-full">
                      {item.service}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Agregar Puerto Personalizado */}
            <form onSubmit={handleAddCustomPort} className="flex gap-2 pt-1">
              <input
                type="number"
                min="1"
                max="65535"
                value={customPortInput}
                onChange={(e) => setCustomPortInput(e.target.value)}
                placeholder="Puerto (ej. 8443)"
                className="flex-1 rounded-lg border border-slate-700/80 bg-slate-900/80 px-2.5 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
              />
              <button
                type="submit"
                disabled={!customPortInput.trim()}
                className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-mono font-medium text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-40"
              >
                + Añadir
              </button>
            </form>
          </div>
        </div>

        {/* Panel Central / Derecho: Resultados y Métricas */}
        <div className="space-y-5 lg:col-span-2">
          {result ? (
            <>
              {/* Tarjeta Superior de Resumen y Riesgo */}
              <div
                className={`rounded-xl border ${activeStyle.border} bg-[#0d1424]/90 p-5 backdrop-blur-md space-y-4`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs uppercase text-slate-400">
                        {result.targetType}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          SCOPE_BADGES[result.networkScope] ||
                          "bg-slate-800 text-slate-300 border-slate-700"
                        }`}
                      >
                        {result.networkScope}
                      </span>
                    </div>
                    <h3 className="mt-1 text-xl font-bold font-mono text-slate-100 truncate">
                      {result.target}
                    </h3>
                  </div>

                  <div className="flex items-center gap-3 self-end sm:self-auto">
                    <div className="text-right">
                      <p className="text-[11px] font-mono text-slate-400">Riesgo Global</p>
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
                    <span>Índice de Exposición Perimetral</span>
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
              </div>

              {/* Bento de Métricas Rápidas */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Host Resuelto</span>
                    <Globe className="h-3.5 w-3.5 text-cyan-400" />
                  </div>
                  <p className="mt-2 text-sm font-bold font-mono text-slate-100 truncate">
                    {result.resolvedHost}
                  </p>
                  <p className="text-[10px] text-slate-500">{result.targetType}</p>
                </div>

                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Ámbito de Red</span>
                    <Server className="h-3.5 w-3.5 text-emerald-400" />
                  </div>
                  <p className="mt-2 text-sm font-bold text-slate-100 truncate">
                    {result.networkScope}
                  </p>
                  <p className="text-[10px] text-slate-500">Clasificación RFC</p>
                </div>

                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Puertos Auditados</span>
                    <Radio className="h-3.5 w-3.5 text-sky-400" />
                  </div>
                  <p className="mt-2 text-xl font-bold font-mono text-slate-100">
                    {result.openOrCheckedPorts.length}
                  </p>
                  <p className="text-[10px] text-slate-500">Superficie auditada</p>
                </div>

                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-3.5 backdrop-blur-md">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs">Hora Análisis</span>
                    <Clock className="h-3.5 w-3.5 text-amber-400" />
                  </div>
                  <p className="mt-2 text-xs font-bold font-mono text-slate-100">
                    {result.scannedAt}
                  </p>
                  <p className="text-[10px] text-slate-500">Registro temporal</p>
                </div>
              </div>

              {/* Lista Detallada de Puertos Analizados */}
              <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md space-y-3">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Server className="h-4 w-4 text-cyan-400" />
                  Servicios y Puertos Analizados
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                  {result.openOrCheckedPorts.map((p) => {
                    const portStyle = RISK_STYLES[p.severity];
                    return (
                      <div
                        key={p.port}
                        className="flex items-center justify-between p-2.5 rounded-lg border border-slate-800 bg-slate-900/50 text-xs"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          {p.severity === "Crítico" || p.severity === "Alto" ? (
                            <Unlock className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                          ) : (
                            <Lock className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                          )}
                          <div className="truncate">
                            <span className="font-mono font-bold text-slate-200">
                              :{p.port}
                            </span>
                            <span className="text-[11px] text-slate-400 ml-1.5 truncate">
                              {p.service}
                            </span>
                          </div>
                        </div>
                        <span
                          className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${portStyle.badge}`}
                        >
                          {p.severity}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Hallazgos y Diagnósticos */}
              <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-5 backdrop-blur-md space-y-3">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-cyan-400" />
                  Hallazgos de Seguridad de Red ({result.findings.length})
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
            /* Estado Inicial */
            <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-12 text-center backdrop-blur-md">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400">
                <Network className="h-7 w-7" />
              </div>
              <h3 className="mt-4 text-base font-semibold text-slate-200">
                Esperando Objetivo de Red
              </h3>
              <p className="mx-auto mt-1 max-w-md text-xs text-slate-400">
                Indica una dirección IP, subred CIDR o dominio en el panel izquierdo y selecciona los puertos TCP a verificar para auditar la superficie expuesta y el nivel de riesgo.
              </p>
            </div>
          )}

          {/* Historial de la Sesión */}
          {history.length > 0 && (
            <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-4 backdrop-blur-md space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-cyan-400" />
                  Historial de Auditorías de Red
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
                      <p className="font-mono text-slate-200 truncate">{item.target}</p>
                      <p className="text-[10px] text-slate-500 font-mono">
                        {item.networkScope} • {item.openOrCheckedPorts.length} puertos • {item.scannedAt}
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
