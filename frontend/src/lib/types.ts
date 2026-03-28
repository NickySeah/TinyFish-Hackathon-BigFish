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
  confidenceScore: number;
  riskCategories: RiskCategory[];
  metadata: SiteMetadata;
  aiSummary: string;
  url: string;
  analyzedAt: string;
}
