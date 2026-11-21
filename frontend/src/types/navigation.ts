export type SectionId =
  | "dashboard"
  | "history"
  | "link-scanner"
  | "file-scanner"
  | "apk-analyzer"
  | "network-analyzer"
  | "threat-intelligence"
  | "threat-correlation"
  | "threat-graph"
  | "risk-engine"
  | "ai-analyst"
  | "reports"
  | "settings"
  | "security-permissions";

export interface NavItem {
  id: SectionId;
  label: string;
  badge?: string;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

export const AEGISMESH_NAV_GROUPS: NavGroup[] = [
  {
    title: "GENERAL",
    items: [
      { id: "dashboard", label: "Dashboard", badge: "LIVE" },
      { id: "history", label: "Historial de análisis" },
    ],
  },
  {
    title: "ANÁLISIS",
    items: [
      { id: "link-scanner", label: "Link Scanner" },
      { id: "file-scanner", label: "File Scanner" },
      { id: "apk-analyzer", label: "APK Analyzer" },
      { id: "network-analyzer", label: "Network Analyzer" },
    ],
  },
  {
    title: "INTELIGENCIA",
    items: [
      { id: "threat-intelligence", label: "Threat Intelligence" },
      { id: "threat-correlation", label: "Threat Correlation" },
      { id: "threat-graph", label: "Threat Graph" },
    ],
  },
  {
    title: "ANÁLISIS AVANZADO",
    items: [
      { id: "risk-engine", label: "Risk Engine" },
      { id: "ai-analyst", label: "AI Analyst" },
      { id: "reports", label: "Reports" },
    ],
  },
  {
    title: "SISTEMA",
    items: [
      { id: "settings", label: "Configuración" },
      { id: "security-permissions", label: "Seguridad y permisos" },
    ],
  },
];