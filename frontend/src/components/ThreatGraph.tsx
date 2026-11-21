import { useMemo, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { motion } from "framer-motion";
import { Share2, ShieldAlert, Crosshair } from "lucide-react";

interface GraphNode {
  id: string;
  label: string;
  type: "host" | "threat" | "ioc";
  risk: "Bajo" | "Medio" | "Alto" | "Crítico";
  val: number;
}

interface GraphLink {
  source: string;
  target: string;
  relation: string;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

const RISK_COLORS: Record<GraphNode["risk"], string> = {
  Bajo: "#34d399",
  Medio: "#38bdf8",
  Alto: "#f59e0b",
  Crítico: "#fb7185",
};

export function ThreatGraph() {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const graphData = useMemo<GraphData>(
    () => ({
      nodes: [
        {
          id: "node-workstation",
          label: "Host-Workstation-01",
          type: "host",
          risk: "Medio",
          val: 10,
        },
        {
          id: "node-android",
          label: "Mobile-Sensor-Android",
          type: "host",
          risk: "Bajo",
          val: 8,
        },
        {
          id: "ioc-domain",
          label: "login-verify-update[.]com",
          type: "ioc",
          risk: "Alto",
          val: 9,
        },
        {
          id: "threat-phishing",
          label: "Campaña Phishing Credenciales",
          type: "threat",
          risk: "Crítico",
          val: 12,
        },
        {
          id: "ioc-ip",
          label: "192.168.1.44:4444",
          type: "ioc",
          risk: "Crítico",
          val: 9,
        },
        {
          id: "ioc-apk",
          label: "update_service_v2.apk",
          type: "ioc",
          risk: "Alto",
          val: 8,
        },
      ],
      links: [
        {
          source: "node-workstation",
          target: "ioc-domain",
          relation: "Consulta DNS sospechosa",
        },
        {
          source: "ioc-domain",
          target: "threat-phishing",
          relation: "Asociado a campaña",
        },
        {
          source: "node-workstation",
          target: "ioc-ip",
          relation: "Conexión saliente anómala",
        },
        {
          source: "ioc-ip",
          target: "threat-phishing",
          relation: "Infraestructura C2",
        },
        {
          source: "node-android",
          target: "ioc-apk",
          relation: "Paquete detectado",
        },
      ],
    }),
    []
  );

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
            <Share2 className="w-3.5 h-3.5 animate-pulse" />
            <span>Correlación Topológica de Amenazas</span>
          </div>
          <h2 className="mt-1 text-xl font-bold text-slate-100">
            Threat Graph Interactivo
          </h2>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-[#0f172a] border border-slate-800 px-3 py-1.5 rounded-lg">
          <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
          <span>Haz clic en un nodo para inspeccionar</span>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.35 }}
          className="lg:col-span-2 h-[440px] rounded-xl bg-[#090e1a] border border-slate-800/90 overflow-hidden relative"
        >
          <ForceGraph2D
            graphData={graphData}
            backgroundColor="#090e1a"
            nodeLabel={(node) => {
              const n = node as GraphNode;
              return `${n.label} (${n.risk})`;
            }}
            nodeColor={(node) => {
              const n = node as GraphNode;
              return RISK_COLORS[n.risk] ?? "#22d3ee";
            }}
            linkColor={() => "rgba(56, 189, 248, 0.32)"}
            linkDirectionalParticles={2}
            linkDirectionalParticleWidth={2.2}
            linkDirectionalParticleSpeed={0.006}
            onNodeClick={(node) => setSelectedNode(node as GraphNode)}
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 14 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.35 }}
          className="rounded-xl bg-[#0f172a]/90 border border-slate-800/90 p-5 space-y-4"
        >
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Detalle del Nodo Seleccionado
            </h3>
          </div>

          {selectedNode ? (
            <div className="space-y-3 rounded-lg bg-[#0b1222] border border-slate-800/80 p-4">
              <p className="text-xs font-mono uppercase text-cyan-400">
                Tipo: {selectedNode.type}
              </p>
              <h4 className="text-base font-bold text-slate-100">
                {selectedNode.label}
              </h4>
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs font-mono">
                <span className="text-slate-400">Nivel de riesgo</span>
                <span
                  style={{ color: RISK_COLORS[selectedNode.risk] }}
                  className="font-semibold"
                >
                  {selectedNode.risk}
                </span>
              </div>
            </div>
          ) : (
            <div className="rounded-lg bg-[#0b1222] border border-slate-800/80 p-4 text-xs text-slate-400 leading-relaxed">
              Selecciona cualquier nodo del grafo para ver su tipo de entidad,
              indicador y nivel de riesgo dentro de la malla de análisis.
            </div>
          )}

          <div className="space-y-2 pt-2 border-t border-slate-800/80">
            <p className="text-[11px] font-mono uppercase tracking-wider text-slate-500">
              Leyenda de Riesgo
            </p>
            {(Object.keys(RISK_COLORS) as GraphNode["risk"][]).map((level) => (
              <div
                key={level}
                className="flex items-center justify-between text-xs font-mono"
              >
                <span className="text-slate-300">{level}</span>
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: RISK_COLORS[level] }}
                />
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}