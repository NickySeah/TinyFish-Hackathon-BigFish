export interface AnalysisRequest {
  url: string;
  source: string;
  sourceDetail?: string;
}

export interface RiskCategory {
  name: string;
  level: "safe" | "warning" | "danger";
  description: string;
}

export interface SiteMetadata {
  domainAge?: string;
  registrar?: string;
  sslInfo?: string;
  ipAddress?: string;
  redirectCount?: number;
  hasLoginForm?: boolean;
}

export interface AnalysisResult {
  scanId?: string;
  confidenceScore: number;
  riskCategories: RiskCategory[];
  metadata: SiteMetadata;
  aiSummary: string;
  url: string;
  analyzedAt: string;
  finalVerdict?: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "PENDING" | "ERROR";
}

// --- SSE Event Types (from FastAPI StreamingResponse) ---

export interface StreamUrlEvent {
  type: "stream_url";
  streamingUrl: string;
}

export interface StatusEvent {
  type: "status";
  stage: string;
}

export interface ResultEvent {
  type: "result";
  data: AnalysisResult;
}

export type ScanEvent = StreamUrlEvent | StatusEvent | ResultEvent;

// --- Scan History ---

export interface ScanHistoryEntry {
  scanId: string;
  url: string;
  source: string;
  scannedAt: string;
  finalVerdict?: string;
  confidenceScore?: number;
}
