import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import { History, Trash2, ExternalLink, AlertTriangle, ShieldCheck, ShieldAlert, Clock } from "lucide-react";
import { getScanHistory, clearScanHistory } from "@/lib/scanHistory";
import type { ScanHistoryEntry } from "@/lib/types";

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function verdictColor(verdict?: string) {
  switch (verdict) {
    case "SAFE": return "text-safe";
    case "SUSPICIOUS": return "text-warning";
    case "MALICIOUS": return "text-danger";
    default: return "text-muted-foreground";
  }
}

function VerdictIcon({ verdict }: { verdict?: string }) {
  switch (verdict) {
    case "SAFE": return <ShieldCheck className="w-3.5 h-3.5" />;
    case "SUSPICIOUS": return <AlertTriangle className="w-3.5 h-3.5" />;
    case "MALICIOUS": return <ShieldAlert className="w-3.5 h-3.5" />;
    default: return <Clock className="w-3.5 h-3.5" />;
  }
}

export default function ScanHistoryDropdown() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [loadingId] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const toggleOpen = () => {
    const next = !open;
    if (next) setHistory(getScanHistory());
    setOpen(next);
  };

  // Click outside
  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  const handleEntryClick = (entry: ScanHistoryEntry) => {
    setOpen(false);
    // Navigate to home with the URL pre-filled so user can re-scan
    navigate("/", { state: { prefillUrl: entry.url, prefillSource: entry.source } });
  };

  const handleClear = () => {
    clearScanHistory();
    setHistory([]);
  };

  return (
    <div ref={containerRef} className="relative">
      {/* Trigger */}
      <button
        onClick={toggleOpen}
        className="relative flex items-center justify-center w-9 h-9 rounded-lg text-muted-foreground hover:text-foreground hover:bg-secondary/60 transition-colors cursor-pointer"
        aria-label="Recent scans"
      >
        <History className="w-[18px] h-[18px]" />
        {getScanHistory().length > 0 && (
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-primary" />
        )}
      </button>

      {/* Dropdown */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.97 }}
            transition={{ duration: 0.15 }}
            className="absolute right-0 top-full mt-2 w-80 bg-card border border-border/60 rounded-xl shadow-2xl shadow-black/40 overflow-hidden z-50"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border/40">
              <span className="font-heading text-xs font-bold tracking-wide text-foreground uppercase">
                Recent Scans
              </span>
              {history.length > 0 && (
                <button
                  onClick={handleClear}
                  className="flex items-center gap-1.5 text-[11px] text-muted-foreground hover:text-danger transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3 h-3" />
                  Clear
                </button>
              )}
            </div>

            {/* List */}
            <div className="max-h-[320px] overflow-y-auto">
              {history.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-10 text-muted-foreground/50">
                  <History className="w-6 h-6 mb-2" />
                  <span className="text-xs font-mono">No recent scans</span>
                </div>
              ) : (
                history.map((entry, i) => (
                  <motion.button
                    key={entry.scanId}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.03, duration: 0.2 }}
                    onClick={() => handleEntryClick(entry)}
                    disabled={loadingId === entry.scanId}
                    className="w-full flex items-center gap-3 px-4 py-3 hover:bg-secondary/40 transition-colors text-left group cursor-pointer disabled:opacity-50"
                  >
                    {/* Verdict icon */}
                    <div className={`shrink-0 ${verdictColor(entry.finalVerdict)}`}>
                      <VerdictIcon verdict={entry.finalVerdict} />
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <ExternalLink className="w-3 h-3 text-muted-foreground/40 shrink-0" />
                        <span className="font-mono text-xs text-foreground truncate">
                          {entry.url.replace(/^https?:\/\//, "").slice(0, 35)}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[10px] text-muted-foreground/60">{entry.source}</span>
                        {entry.confidenceScore != null && (
                          <span className={`text-[10px] font-mono ${verdictColor(entry.finalVerdict)}`}>
                            {entry.confidenceScore}%
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Time */}
                    <span className="shrink-0 text-[10px] font-mono text-muted-foreground/50">
                      {timeAgo(entry.scannedAt)}
                    </span>
                  </motion.button>
                ))
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
