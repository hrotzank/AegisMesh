import { motion } from "framer-motion";
import {
  ShieldAlert,
  Activity,
  Server,
  Smartphone,
  CheckCircle2,
  AlertTriangle,
  Radio,
} from "lucide-react";

interface MetricCard {
  label: string;
  value: string;
  delta: string;
  accent: "cyan" | "emerald" | "amber" | "rose";
}

const METRICS: MetricCard[] = [
  {
    label: "Eventos Analizados",
    value: "14,820",
    delta: "+12.4% hoy",
    accent: "cyan",
  },
  {
    label: "Nodos Activos (PC/Móvil)",
    value: "28",
    delta: "100% en línea",
    accent: "emerald",
  },
  {
    label: "Amenazas Bloqueadas",
    value: "194",
    delta: "Phishing / Malware",
    accent: "amber",
  },
  {
    label: "Alertas Críticas",
    value: "3",
    delta: "Requieren revisión",
    accent: "rose",
  },
];

const ACCENT_STYLES: Record<
  MetricCard["accent"],
  { border: string; text: string; badge: string; dot: string }
> = {
  cyan: {
    border: "border-cyan-500/30 hover:border-cyan-400/60",
    text: "text-cyan-400",
    badge: "bg-cyan-500/10 text-cyan-300 border-cyan-500/25",
    dot: "bg-cyan-400",
  },
  emerald: {
    border: "border-emerald-500/30 hover:border-emerald-400/60",
    text: "text-emerald-400",
    badge: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25",
    dot: "bg-emerald-400",
  },
  amber: {
    border: "border-amber-500/30 hover:border-amber-400/60",
    text: "text-amber-400",
    badge: "bg-amber-500/10 text-amber-300 border-amber-500/25",
    dot: "bg-amber-400",
  },
  rose: {
    border: "border-rose-500/30 hover:border-rose-400/60",
    text: "text-rose-400",
    badge: "bg-rose-500/10 text-rose-300 border-rose-500/25",
    dot: "bg-rose-400",
  },
};

const CONNECTED_NODES = [
  { name: "Host-Workstation-01", os: "Linux / Desktop", status: "Seguro", load: "24%" },
  { name: "Mobile-Sensor-Android", os: "APK Telemetry", status: "Monitoreo", load: "38%" },
  { name: "Edge-Gateway-Node", os: "Network Probe", status: "Alerta", load: "71%" },
  { name: "Lab-Audit-VM", os: "Security Node", status: "Seguro", load: "19%" },
];

const RECENT_ALERTS = [
  {
    id: "ALT-904",
    title: "Enlace sospechoso detectado en Link Scanner",
    target: "login-verify-update[.]com",
    level: "Alto",
    time: "Hace 2 min",
  },
  {
    id: "ALT-903",
    title: "Permisos sensibles en paquete APK analizado",
    target: "update_service_v2.apk",
    level: "Medio",
    time: "Hace 11 min",
  },
  {
    id: "ALT-902",
    title: "Patrón de tráfico anómalo correlacionado",
    target: "192.168.1.44 -> :4444",
    level: "Crítico",
    time: "Hace 26 min",
  },
];

export function Dashboard() {
  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4"
      >
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-widest">
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            <span>Telemetría SOC en Tiempo Real</span>
          </div>
          <h2 className="mt-1 text-xl font-bold text-slate-100">
            Dashboard Operativo de Seguridad
          </h2>
        </div>

        <motion.div
          animate={{ opacity: [0.7, 1, 0.7] }}
          transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }}
          className="px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-400/30 text-xs font-mono text-cyan-300"
        >
          AEGISMESH CORE // ONLINE
        </motion.div>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {METRICS.map((item, idx) => {
          const style = ACCENT_STYLES[item.accent];
          return (
            <motion.div
              key={item.label}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.08, duration: 0.35 }}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
              className={`rounded-xl bg-[#0f172a]/90 border ${style.border} p-4 shadow-lg transition-colors`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400 font-medium">
                  {item.label}
                </span>
                <span className={`w-2 h-2 rounded-full ${style.dot} animate-pulse`} />
              </div>

              <div className={`mt-3 text-2xl font-bold font-mono ${style.text}`}>
                {item.value}
              </div>

              <div className="mt-2">
                <span
                  className={`inline-block text-[11px] font-mono px-2 py-0.5 rounded border ${style.badge}`}
                >
                  {item.delta}
                </span>
              </div>
            </motion.div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.22, duration: 0.4 }}
          className="lg:col-span-2 rounded-xl bg-[#0f172a]/90 border border-slate-800/90 p-5 space-y-5"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Flujo de Riesgo y Actividad Continua
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Ventana: 24h
            </span>
          </div>

          <div className="relative h-44 rounded-lg bg-[#090e1a] border border-slate-800/80 p-3 overflow-hidden flex items-center">
            <motion.div
              animate={{ x: ["0%", "-50%"] }}
              transition={{ duration: 7, repeat: Infinity, ease: "linear" }}
              className="flex w-[200%] h-full items-center"
            >
              <svg
                viewBox="0 0 600 160"
                className="w-1/2 h-full shrink-0"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient id="aegismeshWaveA" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#22d3ee" />
                    <stop offset="55%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#f59e0b" />
                  </linearGradient>
                </defs>
                <path
                  d="M 0 115 C 80 105, 130 55, 210 78 C 290 100, 340 35, 430 62 C 500 82, 550 48, 600 54"
                  fill="none"
                  stroke="url(#aegismeshWaveA)"
                  strokeWidth="3"
                  strokeLinecap="round"
                />
                <circle cx="430" cy="62" r="5" fill="#f59e0b" />
              </svg>

              <svg
                viewBox="0 0 600 160"
                className="w-1/2 h-full shrink-0"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient id="aegismeshWaveB" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#22d3ee" />
                    <stop offset="55%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#f59e0b" />
                  </linearGradient>
                </defs>
                <path
                  d="M 0 54 C 70 72, 140 112, 220 84 C 300 55, 360 108, 450 70 C 515 44, 560 95, 600 115"
                  fill="none"
                  stroke="url(#aegismeshWaveB)"
                  strokeWidth="3"
                  strokeLinecap="round"
                />
                <circle cx="450" cy="70" r="5" fill="#22d3ee" />
              </svg>
            </motion.div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {CONNECTED_NODES.map((node, index) => (
              <motion.div
                key={node.name}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 + index * 0.07, duration: 0.3 }}
                whileHover={{ scale: 1.015 }}
                className="flex items-center justify-between p-3 rounded-lg bg-[#0b1222] border border-slate-800/80"
              >
                <div className="flex items-center gap-3 min-w-0">
                  {node.os.includes("APK") ? (
                    <Smartphone className="w-4 h-4 text-cyan-400 shrink-0" />
                  ) : (
                    <Server className="w-4 h-4 text-emerald-400 shrink-0" />
                  )}
                  <div className="truncate">
                    <p className="text-xs font-semibold text-slate-200 truncate">
                      {node.name}
                    </p>
                    <p className="text-[11px] text-slate-500 truncate">{node.os}</p>
                  </div>
                </div>

                <div className="text-right shrink-0 ml-2">
                  <span
                    className={`inline-flex items-center gap-1 text-[11px] font-mono ${
                      node.status === "Alerta"
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }`}
                  >
                    {node.status === "Alerta" ? (
                      <AlertTriangle className="w-3 h-3" />
                    ) : (
                      <CheckCircle2 className="w-3 h-3" />
                    )}
                    {node.status}
                  </span>
                  <p className="text-[10px] font-mono text-slate-400">
                    Carga {node.load}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.28, duration: 0.4 }}
          className="rounded-xl bg-[#0f172a]/90 border border-slate-800/90 p-5 space-y-4"
        >
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Alertas y Eventos Recientes
            </h3>
          </div>

          <div className="space-y-3">
            {RECENT_ALERTS.map((alert, idx) => (
              <motion.div
                key={alert.id}
                initial={{ opacity: 0, x: 14 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.35 + idx * 0.1, duration: 0.32 }}
                whileHover={{ x: -3 }}
                className="p-3 rounded-lg bg-[#0b1222] border border-slate-800/80 space-y-1.5"
              >
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-cyan-400">{alert.id}</span>
                  <span
                    className={
                      alert.level === "Crítico"
                        ? "text-rose-400"
                        : alert.level === "Alto"
                        ? "text-amber-400"
                        : "text-sky-400"
                    }
                  >
                    {alert.level}
                  </span>
                </div>
                <p className="text-xs font-medium text-slate-200">{alert.title}</p>
                <p className="text-[11px] font-mono text-slate-400 truncate">
                  {alert.target}
                </p>
                <p className="text-[10px] text-slate-500">{alert.time}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}