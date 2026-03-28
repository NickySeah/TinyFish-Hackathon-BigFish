import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import { toast } from "sonner";
import { Fish, Globe, Search, Loader2, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { analyzeUrl } from "@/lib/api";
import { addScanToHistory } from "@/lib/scanHistory";

const SOURCES = [
  "Email",
  "SMS / Text Message",
  "Social Media",
  "Messaging App",
  "Search Engine",
  "Website / Ad",
  "Other",
];

const SCAN_STAGES = [
  { key: "connecting", label: "Connecting to target..." },
  { key: "scraping", label: "Scraping page content..." },
  { key: "analyzing", label: "Analyzing with AI..." },
  { key: "generating", label: "Generating report..." },
];

function stageIndex(stage: string): number {
  const idx = SCAN_STAGES.findIndex((s) => s.key === stage);
  return idx >= 0 ? idx : 0;
}

function isValidUrl(str: string): boolean {
  try {
    const url = new URL(str.startsWith("http") ? str : `https://${str}`);
    return url.hostname.includes(".");
  } catch {
    return false;
  }
}

export default function HomePage() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [source, setSource] = useState("");
  const [sourceDetail, setSourceDetail] = useState("");
  const [errors, setErrors] = useState<{ url?: string; source?: string }>({});
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState(0);
  const [streamingUrl, setStreamingUrl] = useState<string | null>(null);
  const [iframeLoaded, setIframeLoaded] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const streamFallbackTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const validate = () => {
    const newErrors: { url?: string; source?: string } = {};
    if (!url.trim()) {
      newErrors.url = "Please enter a URL to analyze";
    } else if (!isValidUrl(url.trim())) {
      newErrors.url = "Please enter a valid URL";
    }
    if (!source) {
      newErrors.source = "Please select where you found this link";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    setIsScanning(true);
    setScanStage(0);
    setStreamingUrl(null);
    setIframeLoaded(false);
    setScanComplete(false);

    // Fallback: if no streaming URL arrives within 5s, stay with spinner
    streamFallbackTimer.current = setTimeout(() => {
      // no-op — spinner stays visible if streamingUrl is null
    }, 5000);

    const normalizedUrl = url.trim().startsWith("http")
      ? url.trim()
      : `https://${url.trim()}`;

    try {
      const result = await analyzeUrl(
        {
          url: normalizedUrl,
          source,
          sourceDetail: source === "Other" ? sourceDetail : undefined,
        },
        {
          onStreamUrl: (sUrl) => {
            if (streamFallbackTimer.current) clearTimeout(streamFallbackTimer.current);
            setStreamingUrl(sUrl);
          },
          onStatus: (stage) => {
            setScanStage(stageIndex(stage));
          },
          onResult: (res) => {
            // Save to history
            addScanToHistory({
              scanId: res.scanId || `scan-${Date.now()}`,
              url: res.url,
              source,
              scannedAt: res.analyzedAt,
              finalVerdict: res.finalVerdict,
              confidenceScore: res.confidenceScore,
            });

            setScanComplete(true);
            // Brief delay to show "complete" state before navigating
            setTimeout(() => {
              navigate("/results", { state: res });
            }, 800);
          },
        }
      );

      // If onResult callback didn't fire (shouldn't happen, but safety)
      if (!result) return;
    } catch (err) {
      if (streamFallbackTimer.current) clearTimeout(streamFallbackTimer.current);
      setIsScanning(false);
      setStreamingUrl(null);
      toast.error(
        err instanceof Error ? err.message : "Analysis failed. Please try again."
      );
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-6 py-16 md:py-24">
      <AnimatePresence mode="wait">
        {!isScanning ? (
          <motion.div
            key="form"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, scale: 0.98 }}
            transition={{ duration: 0.3 }}
          >
            {/* Hero */}
            <motion.div
              className="text-center mb-16"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: "easeOut" }}
            >
              <motion.div
                className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-primary/10 border border-primary/20 mb-8 relative"
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ duration: 0.5, delay: 0.1 }}
              >
                <Fish className="w-10 h-10 text-primary" />
                <div className="absolute inset-0 rounded-2xl blur-2xl bg-primary/20 -z-10" />
              </motion.div>

              <motion.h1
                className="font-heading text-5xl md:text-7xl font-bold tracking-tight mb-4"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15, duration: 0.6 }}
              >
                <span className="bg-gradient-to-r from-primary via-accent to-[oklch(0.8_0.15_60)] bg-clip-text text-transparent">
                  TinyPhish
                </span>
              </motion.h1>

              <motion.p
                className="text-muted-foreground text-lg md:text-xl font-mono tracking-wide"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.3, duration: 0.6 }}
              >
                Detect &middot; Analyze &middot; Protect
              </motion.p>

              <motion.p
                className="text-muted-foreground/70 text-sm mt-4 max-w-md mx-auto"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.45, duration: 0.6 }}
              >
                Paste a suspicious link below and our AI-powered engine will analyze
                it for phishing indicators in seconds.
              </motion.p>
            </motion.div>

            {/* Form */}
            <motion.form
              onSubmit={handleSubmit}
              className="max-w-lg mx-auto space-y-5"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4, duration: 0.5 }}
            >
              {/* URL Input */}
              <div className="space-y-1.5">
                <div className="relative">
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                  <Input
                    type="text"
                    placeholder="Paste suspicious link here..."
                    value={url}
                    onChange={(e) => {
                      setUrl(e.target.value);
                      if (errors.url) setErrors((prev) => ({ ...prev, url: undefined }));
                    }}
                    className={`pl-10 h-12 bg-secondary/50 border-border/60 font-mono text-sm placeholder:text-muted-foreground/50 focus-visible:ring-primary/50 focus-visible:border-primary/50 transition-all ${
                      errors.url ? "border-danger ring-1 ring-danger/30" : ""
                    }`}
                  />
                </div>
                {errors.url && (
                  <motion.p
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-danger text-xs pl-1"
                  >
                    {errors.url}
                  </motion.p>
                )}
              </div>

              {/* Source Select */}
              <div className="space-y-1.5">
                <Select
                  value={source}
                  onValueChange={(val) => {
                    setSource(val ?? "");
                    if (errors.source) setErrors((prev) => ({ ...prev, source: undefined }));
                  }}
                >
                  <SelectTrigger
                    className={`h-12 bg-secondary/50 border-border/60 text-sm focus:ring-primary/50 focus:border-primary/50 transition-all ${
                      !source ? "text-muted-foreground/50" : ""
                    } ${errors.source ? "border-danger ring-1 ring-danger/30" : ""}`}
                  >
                    <SelectValue placeholder="Where did you find this link?" />
                  </SelectTrigger>
                  <SelectContent className="bg-card border-border">
                    {SOURCES.map((s) => (
                      <SelectItem key={s} value={s} className="text-sm">
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.source && (
                  <motion.p
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-danger text-xs pl-1"
                  >
                    {errors.source}
                  </motion.p>
                )}
              </div>

              {/* Other Source Detail */}
              <AnimatePresence>
                {source === "Other" && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <Input
                      type="text"
                      placeholder="Describe where you found this link..."
                      value={sourceDetail}
                      onChange={(e) => setSourceDetail(e.target.value)}
                      className="h-12 bg-secondary/50 border-border/60 text-sm placeholder:text-muted-foreground/50 focus-visible:ring-primary/50 focus-visible:border-primary/50"
                    />
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Submit */}
              <Button
                type="submit"
                className="w-full h-12 text-sm font-semibold bg-primary hover:bg-primary/90 text-primary-foreground cursor-pointer transition-all hover:shadow-[0_0_24px_-4px] hover:shadow-primary/40"
              >
                <Search className="w-4 h-4 mr-2" />
                Analyze Link
              </Button>
            </motion.form>
          </motion.div>
        ) : (
          /* Scanning State — Live Browser + Progress */
          <motion.div
            key="scanning"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex flex-col items-center justify-center min-h-[60vh]"
          >
            {/* Live Browser Stream */}
            {streamingUrl ? (
              <motion.div
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.4 }}
                className="w-full max-w-3xl mb-8"
              >
                {/* Browser chrome frame */}
                <div className="rounded-xl border border-border/60 overflow-hidden bg-card/30 shadow-2xl shadow-black/30">
                  {/* Top bar */}
                  <div className="flex items-center justify-between px-4 py-2.5 bg-secondary/40 border-b border-border/40">
                    <div className="flex items-center gap-2">
                      <div className="flex gap-1.5">
                        <span className="w-3 h-3 rounded-full bg-danger/60" />
                        <span className="w-3 h-3 rounded-full bg-warning/60" />
                        <span className="w-3 h-3 rounded-full bg-safe/60" />
                      </div>
                      <span className="font-mono text-[11px] text-muted-foreground/60 ml-2 truncate max-w-xs">
                        {url.length > 50 ? url.slice(0, 50) + "..." : url}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <motion.span
                        className="w-2 h-2 rounded-full bg-red-500"
                        animate={{ opacity: scanComplete ? 0 : [1, 0.3, 1] }}
                        transition={{ duration: 1.2, repeat: Infinity }}
                      />
                      <span className="font-mono text-[10px] font-bold tracking-widest text-red-400 uppercase">
                        {scanComplete ? "Done" : "Live"}
                      </span>
                    </div>
                  </div>

                  {/* Iframe container */}
                  <div className="relative w-full" style={{ aspectRatio: "16/9" }}>
                    {/* Skeleton placeholder */}
                    {!iframeLoaded && (
                      <div className="absolute inset-0 bg-secondary/30 animate-pulse flex items-center justify-center">
                        <Loader2 className="w-8 h-8 text-primary/40 animate-spin" />
                      </div>
                    )}

                    <iframe
                      src={streamingUrl}
                      title="TinyFish Live Browser"
                      className="w-full h-full border-0"
                      sandbox="allow-scripts allow-same-origin"
                      onLoad={() => setIframeLoaded(true)}
                    />

                    {/* "Analysis Complete" overlay */}
                    <AnimatePresence>
                      {scanComplete && (
                        <motion.div
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          className="absolute inset-0 bg-background/80 backdrop-blur-sm flex flex-col items-center justify-center"
                        >
                          <CheckCircle2 className="w-10 h-10 text-safe mb-3" />
                          <span className="font-heading text-sm font-bold text-foreground">
                            Analysis Complete
                          </span>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
              </motion.div>
            ) : (
              /* Fallback spinner when no streaming URL */
              <motion.div
                className="relative w-24 h-24 mb-10"
                animate={{ rotate: 360 }}
                transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
              >
                <div className="absolute inset-0 rounded-full border-2 border-primary/20" />
                <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-primary" />
                <div className="absolute inset-2 rounded-full border-2 border-transparent border-t-cyan" />
                <div className="absolute inset-0 blur-xl bg-primary/20 rounded-full" />
              </motion.div>
            )}

            {/* Progress stages */}
            <div className="font-mono text-sm space-y-3 text-left max-w-xs">
              {SCAN_STAGES.map((stage, i) => (
                <motion.div
                  key={stage.key}
                  initial={{ opacity: 0, x: -10 }}
                  animate={
                    i <= scanStage
                      ? { opacity: 1, x: 0 }
                      : { opacity: 0, x: -10 }
                  }
                  transition={{ duration: 0.3, delay: i <= scanStage ? 0.1 : 0 }}
                  className="flex items-center gap-3"
                >
                  {i < scanStage ? (
                    <span className="text-safe text-xs">&#10003;</span>
                  ) : i === scanStage ? (
                    <Loader2 className="w-3 h-3 text-primary animate-spin" />
                  ) : (
                    <span className="w-3 h-3" />
                  )}
                  <span
                    className={
                      i < scanStage
                        ? "text-muted-foreground/60"
                        : i === scanStage
                          ? "text-foreground"
                          : "text-muted-foreground/30"
                    }
                  >
                    {stage.label}
                  </span>
                </motion.div>
              ))}
            </div>

            <motion.p
              className="text-muted-foreground/50 text-xs mt-8 font-mono"
              animate={{ opacity: [0.3, 0.7, 0.3] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              analyzing {url.length > 40 ? url.slice(0, 40) + "..." : url}
            </motion.p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
