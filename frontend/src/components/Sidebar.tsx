import { motion } from "framer-motion";
import {
  Activity,
  History,
  Link2,
  FileSearch,
  Smartphone,
  Network,
  ShieldAlert,
  GitMerge,
  Share2,
  Gauge,
  Bot,
  FileText,
  Settings,
  Lock,
  ShieldCheck,
} from "lucide-react";
import { AEGISMESH_NAV_GROUPS, SectionId } from "../types/navigation";

interface SidebarProps {
  activeSection: SectionId;
  onSelectSection: (section: SectionId) => void;
}

const SECTION_ICONS: Record<SectionId, typeof Activity> = {
  dashboard: Activity,
  history: History,
  "link-scanner": Link2,
  "file-scanner": FileSearch,
  "apk-analyzer": Smartphone,
  "network-analyzer": Network,
  "threat-intelligence": ShieldAlert,
  "threat-correlation": GitMerge,
  "threat-graph": Share2,
  "risk-engine": Gauge,
  "ai-analyst": Bot,
  reports: FileText,
  settings: Settings,
  "security-permissions": Lock,
};

export function Sidebar({ activeSection, onSelectSection }: SidebarProps) {
  return (
    <motion.aside
      initial={{ x: -24, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="w-72 shrink-0 border-r border-slate-800/80 bg-[#0b1120]/95 backdrop-blur-md flex flex-col justify-between select-none"
    >
      <div className="p-4 space-y-6 overflow-y-auto">
        <div className="flex items-center gap-3 px-2 py-1">
          <motion.div
            animate={{
              boxShadow: [
                "0 0 0px rgba(34, 211, 238, 0.0)",
                "0 0 18px rgba(34, 211, 238, 0.28)",
                "0 0 0px rgba(34, 211, 238, 0.0)",
              ],
            }}
            transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }}
            className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400"
          >
            <ShieldCheck className="w-5 h-5" />
          </motion.div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-slate-100">
              AegisMesh
            </h1>
            <p className="text-[10px] font-mono tracking-[0.2em] text-cyan-400/90 uppercase">
              SECURITY PLATFORM
            </p>
          </div>
        </div>

        <nav className="space-y-5">
          {AEGISMESH_NAV_GROUPS.map((group, groupIndex) => (
            <motion.div
              key={group.title}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.06 * groupIndex, duration: 0.28 }}
              className="space-y-1.5"
            >
              <p className="px-3 text-[11px] font-semibold tracking-[0.14em] text-slate-500 uppercase">
                {group.title}
              </p>

              <ul className="space-y-1">
                {group.items.map((item) => {
                  const Icon = SECTION_ICONS[item.id];
                  const isActive = activeSection === item.id;

                  return (
                    <li key={item.id} className="relative">
                      <motion.button
                        type="button"
                        onClick={() => onSelectSection(item.id)}
                        whileHover={{ x: 3 }}
                        whileTap={{ scale: 0.985 }}
                        className={`relative w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                          isActive
                            ? "text-cyan-300"
                            : "text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        {isActive && (
                          <motion.span
                            layoutId="aegismesh-active-nav"
                            transition={{
                              type: "spring",
                              stiffness: 420,
                              damping: 32,
                            }}
                            className="absolute inset-0 rounded-lg bg-cyan-500/12 border border-cyan-400/30"
                          />
                        )}

                        <span className="relative z-10 flex items-center gap-2.5 truncate">
                          <Icon
                            className={`w-4 h-4 shrink-0 ${
                              isActive ? "text-cyan-400" : "text-slate-500"
                            }`}
                          />
                          <span className="truncate">{item.label}</span>
                        </span>

                        {item.badge && (
                          <span className="relative z-10 flex items-center gap-1.5 text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            {item.badge}
                          </span>
                        )}
                      </motion.button>
                    </li>
                  );
                })}
              </ul>
            </motion.div>
          ))}
        </nav>
      </div>

      <div className="p-3 border-t border-slate-800/80 bg-[#080d18]/80">
        <div className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-slate-900/70 border border-slate-800/80 text-[11px] font-mono">
          <span className="text-slate-400">HOST MODE</span>
          <span className="text-cyan-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            LOCAL ACTIVE
          </span>
        </div>
      </div>
    </motion.aside>
  );
}