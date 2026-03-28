import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { ChevronDown, ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, Globe, Users, Lock } from "lucide-react";
import type { VirusTotalResult } from "@/lib/types";
import { extractVTOverview } from "@/lib/types";

interface MetadataTableProps {
  virusTotal: VirusTotalResult;
}

function Row({ label, value, color, icon: Icon }: { label: string; value: React.ReactNode; color?: string; icon?: React.ComponentType<{ className?: string }> }) {
  return (
    <div className="flex items-center justify-between px-5 py-3 hover:bg-secondary/30 transition-colors">
      <div className="flex items-center gap-2">
        {Icon && <Icon className={`w-3.5 h-3.5 ${color || "text-muted-foreground"}`} />}
        <span className="text-muted-foreground text-sm">{label}</span>
      </div>
      <span className={`font-mono text-sm ${color || "text-foreground"}`}>{value}</span>
    </div>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div className="px-5 py-2.5 bg-secondary/20">
      <span className="text-muted-foreground text-[11px] font-mono uppercase tracking-widest">{title}</span>
    </div>
  );
}

function formatDate(epoch: number): string {
  return new Date(epoch * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function domainAge(epoch: number): string {
  const now = globalThis.Date.now() / 1000;
  const days = Math.floor((now - epoch) / 86400);
  if (days < 30) return `${days} days (very new)`;
  if (days < 365) return `${Math.floor(days / 30)} months`;
  const years = Math.floor(days / 365);
  return `${years} year${years > 1 ? "s" : ""}`;
}

function isNewDomainCheck(epoch: number | null): boolean {
  if (epoch == null) return false;
  return (globalThis.Date.now() / 1000 - epoch) < 30 * 86400;
}

export default function MetadataTable({ virusTotal }: MetadataTableProps) {
  const [open, setOpen] = useState(false);
  const vt = extractVTOverview(virusTotal);

  const malCount = vt.stats?.malicious ?? 0;
  const susCount = vt.stats?.suspicious ?? 0;
  const safeCount = vt.stats?.harmless ?? 0;
  const totalEngines = vt.stats
    ? vt.stats.malicious + vt.stats.suspicious + vt.stats.harmless + vt.stats.undetected + vt.stats.timeout
    : 0;

  const flagged = malCount + susCount;
  const SummaryIcon = malCount > 0 ? ShieldX : flagged > 0 ? ShieldAlert : totalEngines > 0 ? ShieldCheck : ShieldAlert;
  const summaryColor = malCount > 0 ? "text-danger" : flagged > 0 ? "text-warning" : "text-safe";

  const categoryValues = vt.categories ? [...new Set(Object.values(vt.categories))] : [];

  // Is the domain brand new? (< 30 days)
  const isNewDomain = isNewDomainCheck(vt.creationDate);

  // Did the URL redirect somewhere else?
  const redirected = vt.lastFinalUrl && vt.lastFinalUrl !== virusTotal.url;

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
              {flagged}/{totalEngines} engines flagged
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
                  {/* Threat alerts — only if something bad was found */}
                  {vt.threatNames.length > 0 && (
                    <div className="px-5 py-3 bg-danger/5 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-danger mt-0.5 shrink-0" />
                      <div>
                        <p className="text-danger text-sm font-semibold">Known Threats Detected</p>
                        <p className="text-danger/80 text-xs mt-0.5">{vt.threatNames.join(", ")}</p>
                      </div>
                    </div>
                  )}
                  {isNewDomain && (
                    <div className="px-5 py-3 bg-warning/5 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-warning mt-0.5 shrink-0" />
                      <div>
                        <p className="text-warning text-sm font-semibold">Very New Domain</p>
                        <p className="text-warning/80 text-xs mt-0.5">
                          This domain was registered less than 30 days ago. Phishing sites are often short-lived.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Security scanners */}
                  <SectionHeader title="Security Scanners" />
                  <Row label="Flagged as dangerous" value={`${malCount} of ${totalEngines} engines`} color={malCount > 0 ? "text-danger" : "text-safe"} icon={ShieldX} />
                  {susCount > 0 && (
                    <Row label="Flagged as suspicious" value={`${susCount} engines`} color="text-warning" icon={ShieldAlert} />
                  )}
                  <Row label="Confirmed safe" value={`${safeCount} engines`} color="text-safe" icon={ShieldCheck} />

                  {/* Where does this link go? */}
                  <SectionHeader title="Where Does This Link Go?" />
                  {vt.title && <Row label="Page title" value={vt.title} icon={Globe} />}
                  {redirected && (
                    <Row
                      label="Redirects to"
                      value={
                        <span className="truncate max-w-[250px] inline-block align-bottom text-warning" title={vt.lastFinalUrl!}>
                          {vt.lastFinalUrl}
                        </span>
                      }
                      color="text-warning"
                      icon={AlertTriangle}
                    />
                  )}
                  {categoryValues.length > 0 && (
                    <Row label="Site category" value={categoryValues.join(", ")} icon={Globe} />
                  )}

                  {/* Trust & history */}
                  <SectionHeader title="Trust & History" />
                  {vt.creationDate != null && (
                    <Row
                      label="Domain age"
                      value={domainAge(vt.creationDate)}
                      color={isNewDomain ? "text-warning" : "text-safe"}
                      icon={Globe}
                    />
                  )}
                  {vt.certificate && (
                    <Row
                      label="SSL certificate"
                      value={`Issued by ${vt.certificate.issuer}`}
                      icon={Lock}
                    />
                  )}
                  {vt.totalVotes && (vt.totalVotes.harmless > 0 || vt.totalVotes.malicious > 0) && (
                    <Row
                      label="Community votes"
                      value={`${vt.totalVotes.harmless} safe \u00B7 ${vt.totalVotes.malicious} dangerous`}
                      color={vt.totalVotes.malicious > vt.totalVotes.harmless ? "text-danger" : "text-safe"}
                      icon={Users}
                    />
                  )}
                  {vt.timesSubmitted != null && vt.timesSubmitted > 1 && (
                    <Row
                      label="Times reported"
                      value={`${vt.timesSubmitted.toLocaleString()} submissions`}
                      icon={Users}
                    />
                  )}
                  {vt.registrar && (
                    <Row label="Registered through" value={vt.registrar} icon={Globe} />
                  )}
                  {vt.lastAnalysisDate != null && (
                    <Row label="Last scanned" value={formatDate(vt.lastAnalysisDate)} icon={ShieldCheck} />
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
