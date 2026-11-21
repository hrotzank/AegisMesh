import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Sidebar } from "./components/Sidebar";
import { Dashboard } from "./components/Dashboard";
import { SectionId } from "./types/navigation";

export default function App() {
  const [activeSection, setActiveSection] = useState<SectionId>("dashboard");

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex overflow-hidden">
      <Sidebar
        activeSection={activeSection}
        onSelectSection={setActiveSection}
      />

      <main className="flex-1 overflow-y-auto p-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeSection}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
          >
            {activeSection === "dashboard" ? (
              <Dashboard />
            ) : (
              <div className="rounded-xl bg-[#0f172a]/90 border border-slate-800/90 p-6 space-y-2">
                <p className="text-xs font-mono uppercase tracking-widest text-cyan-400">
                  Módulo en preparación
                </p>
                <h2 className="text-xl font-bold text-slate-100">
                  {activeSection}
                </h2>
                <p className="text-sm text-slate-400">
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