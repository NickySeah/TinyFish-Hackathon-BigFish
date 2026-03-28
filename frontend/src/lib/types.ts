// --- Form Input (frontend-only, not sent to backend) ---

export interface AnalysisRequest {
  url: string;
  source: string;
  sourceDetail?: string;
}

// --- TinyFish SSE Event Types ---

export interface TinyFishStartedEvent {
  type: "STARTED";
  run_id: string;
  timestamp: string;
}

export interface TinyFishStreamingUrlEvent {
  type: "STREAMING_URL";
  run_id: string;
  streaming_url: string;
  timestamp: string;
}

export interface TinyFishProgressEvent {
  type: "PROGRESS";
  run_id: string;
  purpose: string;
  timestamp: string;
}

export interface TinyFishCompleteEvent {
  type: "COMPLETE";
  run_id: string;
  status: string;
  result: Record<string, unknown>;
  timestamp: string;
}

export interface TinyFishErrorEvent {
  type: "ERROR";
  message: string;
}

export type TinyFishEvent =
  | TinyFishStartedEvent
  | TinyFishStreamingUrlEvent
  | TinyFishProgressEvent
  | TinyFishCompleteEvent
  | TinyFishErrorEvent;

// --- VirusTotal Types ---

export interface VTAnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
}

export interface VirusTotalResult {
  url: string;
  data: Record<string, unknown>;
}

// --- OpenAI / Phishing Analysis Types (matches backend models) ---

export interface PhishingIndicator {
  category: string;
  detail: string;
}

export interface PhishingAnalysis {
  confidence_score: number; // 0.0 – 1.0
  is_phishing: boolean;
  explanation: string;
  indicators: PhishingIndicator[];
}

export interface OpenAIResult {
  url: string;
  analysis: PhishingAnalysis;
  data: Record<string, unknown>;
}

// --- Merged Scan Result ---

export type FinalVerdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";

export interface MergedScanResult {
  url: string;
  scannedAt: string;
  scrapedContent: string;
  streamingUrl?: string;
  virusTotal: VirusTotalResult;
  openai: OpenAIResult;
}

// --- Helpers ---

function vtAttrs(vt: VirusTotalResult): Record<string, unknown> | null {
  const attrs = (vt.data as Record<string, unknown>)?.attributes as
    | Record<string, unknown>
    | undefined;
  return attrs ?? null;
}

export function extractVTStats(vt: VirusTotalResult): VTAnalysisStats | null {
  const stats = vtAttrs(vt)?.last_analysis_stats as VTAnalysisStats | undefined;
  return stats ?? null;
}

export interface VTOverview {
  stats: VTAnalysisStats | null;
  reputation: number | null;
  totalVotes: { harmless: number; malicious: number } | null;
  title: string | null;
  lastFinalUrl: string | null;
  httpResponseCode: number | null;
  categories: Record<string, string> | null;
  threatNames: string[];
  timesSubmitted: number | null;
}

export function extractVTOverview(vt: VirusTotalResult): VTOverview {
  const a = vtAttrs(vt);
  return {
    stats: extractVTStats(vt),
    reputation: (a?.reputation as number) ?? null,
    totalVotes: (a?.total_votes as { harmless: number; malicious: number }) ?? null,
    title: (a?.title as string) ?? null,
    lastFinalUrl: (a?.last_final_url as string) ?? null,
    httpResponseCode: (a?.last_http_response_code as number) ?? null,
    categories: (a?.categories as Record<string, string>) ?? null,
    threatNames: (a?.threat_names as string[]) ?? [],
    timesSubmitted: (a?.times_submitted as number) ?? null,
  };
}

export function deriveVerdict(result: MergedScanResult): FinalVerdict {
  const score = result.openai.analysis.confidence_score;
  const vtStats = extractVTStats(result.virusTotal);
  const vtMalicious = vtStats?.malicious ?? 0;

  if (score >= 0.6 || vtMalicious >= 3) return "MALICIOUS";
  if (score >= 0.3 || vtMalicious >= 1) return "SUSPICIOUS";
  return "SAFE";
}

export function overallScore(result: MergedScanResult): number {
  return Math.round(result.openai.analysis.confidence_score * 100);
}

// --- Scan History ---

export interface ScanHistoryEntry {
  scanId: string;
  url: string;
  source: string;
  scannedAt: string;
  finalVerdict?: FinalVerdict;
  confidenceScore?: number; // 0–100
}
