import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Sidebar } from "./components/Sidebar";
import { Dashboard } from "./components/Dashboard";
import { ThreatGraph } from "./components/ThreatGraph";
import { LinkScanner } from "./components/LinkScanner";
import { SectionId } from "./types/navigation";

export default function App() {
  const [activeSection, setActiveSection] = useState<SectionId>("dashboard");

  return (
    <div className="flex min-h-screen bg-[#090d16] text-slate-100">
      <Sidebar activeSection={activeSection} onSelectSection={setActiveSection} />

      <main className="min-w-0 flex-1 p-4 sm:p-6 lg:p-8">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeSection}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.2 }}
          >
            {activeSection === "dashboard" && <Dashboard />}
            {activeSection === "link-scanner" && <LinkScanner />}
            {activeSection === "threat-correlation" && <ThreatGraph />}

            {activeSection !== "dashboard" &&
              activeSection !== "link-scanner" &&
              activeSection !== "threat-correlation" && (
                <div className="rounded-xl border border-slate-800/90 bg-[#0d1424]/85 p-6 backdrop-blur-md">
                  <p className="text-xs font-mono uppercase tracking-wider text-cyan-400">
                    Módulo en preparación
                  </p>
                  <h2 className="mt-2 text-xl font-bold text-slate-100">{activeSection}</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Estructura lista para integrar la lógica y visualización de este módulo.
                  </p>
                </div>
              )}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}