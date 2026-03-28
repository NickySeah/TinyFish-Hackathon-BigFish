import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { ChevronDown, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";
import type { VirusTotalResult } from "@/lib/types";
import { extractVTOverview } from "@/lib/types";

interface MetadataTableProps {
  virusTotal: VirusTotalResult;
}

function statColor(key: string, value: number): string | undefined {
  if (key === "malicious" && value > 0) return "text-danger";
  if (key === "suspicious" && value > 0) return "text-warning";
  if (key === "harmless" && value > 0) return "text-safe";
  return undefined;
}

function Row({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div className="flex items-center justify-between px-5 py-3 hover:bg-secondary/30 transition-colors">
      <span className="text-muted-foreground text-sm">{label}</span>
      <span className={`font-mono text-sm ${color || "text-foreground"}`}>{value}</span>
    </div>
  );
}

export default function MetadataTable({ virusTotal }: MetadataTableProps) {
  const [open, setOpen] = useState(false);
  const vt = extractVTOverview(virusTotal);

  // Determine a quick summary line for the header
  const malCount = vt.stats?.malicious ?? 0;
  const totalEngines = vt.stats
    ? vt.stats.malicious + vt.stats.suspicious + vt.stats.harmless + vt.stats.undetected + vt.stats.timeout
    : 0;
  const SummaryIcon = malCount > 0 ? ShieldX : totalEngines > 0 ? ShieldCheck : ShieldAlert;
  const summaryColor = malCount > 0 ? "text-danger" : "text-safe";

  // Deduplicate categories — pick unique values
  const categoryValues = vt.categories ? [...new Set(Object.values(vt.categories))] : [];

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
        <div className="flex items-center gap-3">
          <SummaryIcon className={`w-4 h-4 ${summaryColor}`} />
          <h3 className="font-heading text-sm font-bold text-foreground">
            VirusTotal Report
          </h3>
          {totalEngines > 0 && (
            <span className={`font-mono text-xs ${summaryColor}`}>
              {malCount}/{totalEngines} engines flagged
            </span>
          )}
        </div>
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
              {!vt.stats ? (
                <div className="px-5 py-3 text-muted-foreground/50 text-sm">
                  No VirusTotal data available
                </div>
              ) : (
                <>
                  {/* Detection stats */}
                  <div className="px-5 py-3">
                    <span className="text-muted-foreground text-[11px] font-mono uppercase tracking-widest">Detection Stats</span>
                  </div>
                  <Row label="Malicious" value={vt.stats.malicious} color={statColor("malicious", vt.stats.malicious)} />
                  <Row label="Suspicious" value={vt.stats.suspicious} color={statColor("suspicious", vt.stats.suspicious)} />
                  <Row label="Harmless" value={vt.stats.harmless} color={statColor("harmless", vt.stats.harmless)} />
                  <Row label="Undetected" value={vt.stats.undetected} />

                  {/* Site info */}
                  <div className="px-5 py-3">
                    <span className="text-muted-foreground text-[11px] font-mono uppercase tracking-widest">Site Info</span>
                  </div>
                  {vt.title && <Row label="Page Title" value={vt.title} />}
                  {vt.lastFinalUrl && (
                    <Row
                      label="Final URL"
                      value={
                        <span className="truncate max-w-[250px] inline-block align-bottom" title={vt.lastFinalUrl}>
                          {vt.lastFinalUrl}
                        </span>
                      }
                    />
                  )}
                  {vt.httpResponseCode != null && (
                    <Row
                      label="HTTP Status"
                      value={vt.httpResponseCode}
                      color={vt.httpResponseCode >= 400 ? "text-danger" : undefined}
                    />
                  )}
                  {categoryValues.length > 0 && (
                    <Row label="Categories" value={categoryValues.join(", ")} />
                  )}

                  {/* Reputation & community */}
                  <div className="px-5 py-3">
                    <span className="text-muted-foreground text-[11px] font-mono uppercase tracking-widest">Community</span>
                  </div>
                  {vt.reputation != null && (
                    <Row
                      label="Reputation Score"
                      value={vt.reputation}
                      color={vt.reputation < 0 ? "text-danger" : vt.reputation > 0 ? "text-safe" : undefined}
                    />
                  )}
                  {vt.totalVotes && (
                    <>
                      <Row label="Community \u2191 Harmless" value={vt.totalVotes.harmless} color="text-safe" />
                      <Row label="Community \u2193 Malicious" value={vt.totalVotes.malicious} color={vt.totalVotes.malicious > 0 ? "text-danger" : undefined} />
                    </>
                  )}
                  {vt.timesSubmitted != null && (
                    <Row label="Times Submitted" value={vt.timesSubmitted.toLocaleString()} />
                  )}

                  {/* Threat names (if any) */}
                  {vt.threatNames.length > 0 && (
                    <>
                      <div className="px-5 py-3">
                        <span className="text-muted-foreground text-[11px] font-mono uppercase tracking-widest">Threats</span>
                      </div>
                      <Row label="Threat Names" value={vt.threatNames.join(", ")} color="text-danger" />
                    </>
                  )}
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
