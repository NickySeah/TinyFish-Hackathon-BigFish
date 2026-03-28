import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { ChevronDown } from "lucide-react";
import type { SiteMetadata } from "@/lib/types";

interface MetadataTableProps {
  metadata: SiteMetadata;
}

function formatValue(key: string, value: unknown): { text: string; color?: string } {
  if (value === undefined || value === null) return { text: "N/A", color: "text-muted-foreground/40" };
  if (typeof value === "boolean") {
    return value
      ? { text: "Yes", color: "text-danger" }
      : { text: "No", color: "text-safe" };
  }
  const str = String(value);
  // Color hints based on content
  if (key === "domainAge") {
    const days = parseInt(str);
    if (!isNaN(days) && days < 30) return { text: str, color: "text-danger" };
    if (!isNaN(days) && days < 180) return { text: str, color: "text-warning" };
  }
  if (key === "redirectCount") {
    const count = parseInt(str);
    if (!isNaN(count) && count >= 3) return { text: str, color: "text-danger" };
    if (!isNaN(count) && count >= 1) return { text: str, color: "text-warning" };
    return { text: str, color: "text-safe" };
  }
  return { text: str };
}

const LABELS: Record<string, string> = {
  domainAge: "Domain Age",
  registrar: "Registrar",
  sslInfo: "SSL Certificate",
  ipAddress: "IP Address",
  redirectCount: "Redirects",
  hasLoginForm: "Login Form Detected",
};

export default function MetadataTable({ metadata }: MetadataTableProps) {
  const [open, setOpen] = useState(false);
  const entries = Object.entries(metadata).filter(
    ([, val]) => val !== undefined
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.6 }}
      className="bg-card/60 backdrop-blur-sm rounded-lg border border-border/60 overflow-hidden"
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full px-5 py-3.5 flex items-center justify-between cursor-pointer hover:bg-secondary/30 transition-colors"
      >
        <h3 className="font-heading text-sm font-bold text-foreground">
          Site Metadata
        </h3>
        <ChevronDown
          className={`w-4 h-4 text-muted-foreground transition-transform duration-200 ${
            open ? "rotate-180" : ""
          }`}
        />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="overflow-hidden border-t border-border/40"
          >
            <div className="divide-y divide-border/30">
              {entries.map(([key, value]) => {
                const { text, color } = formatValue(key, value);
                return (
                  <div
                    key={key}
                    className="flex items-center justify-between px-5 py-3 hover:bg-secondary/30 transition-colors"
                  >
                    <span className="text-muted-foreground text-sm">
                      {LABELS[key] || key}
                    </span>
                    <span
                      className={`font-mono text-sm ${color || "text-foreground"}`}
                    >
                      {text}
                    </span>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
