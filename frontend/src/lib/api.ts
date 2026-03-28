import type { AnalysisRequest, AnalysisResult, ScanEvent } from "./types";

const MOCK_RESULT: AnalysisResult = {
  scanId: "mock-scan-001",
  url: "https://secure-banklogin.xyz/verify",
  confidenceScore: 82,
  analyzedAt: new Date().toISOString(),
  finalVerdict: "MALICIOUS",
  riskCategories: [
    {
      name: "Domain Registration",
      level: "danger",
      description:
        "Domain registered 3 days ago through a privacy proxy service. Newly registered domains are a strong indicator of phishing campaigns.",
    },
    {
      name: "SSL Certificate",
      level: "warning",
      description:
        "Uses a free Let's Encrypt certificate issued the same day as domain registration. While valid, this pattern is common in phishing.",
    },
    {
      name: "Page Content",
      level: "danger",
      description:
        "Page contains a login form that mimics a major bank's branding. Form action submits credentials to a third-party endpoint.",
    },
    {
      name: "URL Structure",
      level: "warning",
      description:
        "URL uses security-related keywords ('secure', 'verify') to appear legitimate. The actual domain does not match any known bank.",
    },
    {
      name: "Redirect Chain",
      level: "danger",
      description:
        "Site performs 3 redirects before reaching the final page, likely to evade URL blocklists and obfuscate the true destination.",
    },
    {
      name: "External Resources",
      level: "safe",
      description:
        "No suspicious external scripts or tracking pixels detected beyond standard analytics.",
    },
  ],
  metadata: {
    domainAge: "3 days",
    registrar: "NameCheap Inc. (Privacy Proxy)",
    sslInfo: "Let's Encrypt — issued 2026-03-25",
    ipAddress: "185.234.72.19",
    redirectCount: 3,
    hasLoginForm: true,
  },
  aiSummary:
    "This website exhibits multiple high-confidence indicators of a phishing attack. The domain was registered just 3 days ago through a privacy proxy, making it difficult to trace the owner. The page closely replicates the login interface of a major financial institution, including logos, color schemes, and form layouts. Critically, the login form submits credentials to an external server unrelated to any legitimate banking service. The site uses aggressive redirect chains (3 hops) to avoid detection by URL filtering systems. While the SSL certificate is technically valid, the combination of a newly-registered domain, credential harvesting form, and redirect obfuscation creates an extremely high phishing confidence score. Users should not enter any personal information on this site.",
};

export interface AnalyzeCallbacks {
  onStreamUrl?: (url: string) => void;
  onStatus?: (stage: string) => void;
  onResult?: (result: AnalysisResult) => void;
}

export async function analyzeUrl(
  request: AnalysisRequest,
  callbacks?: AnalyzeCallbacks
): Promise<AnalysisResult> {
  const apiUrl = import.meta.env.VITE_API_URL;

  if (!apiUrl) {
    // Mock mode: simulate SSE event sequence
    return mockAnalyzeUrl(request, callbacks);
  }

  const response = await fetch(`${apiUrl}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(
      response.status === 429
        ? "Too many requests. Please wait a moment and try again."
        : `Analysis failed (${response.status})`
    );
  }

  // Read SSE stream from FastAPI StreamingResponse
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("No response stream available");
  }

  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult: AnalysisResult | null = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    // Parse SSE lines: "data: {...}\n\n"
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || !trimmed.startsWith("data: ")) continue;

      const jsonStr = trimmed.slice(6);
      if (jsonStr === "[DONE]") continue;

      try {
        const event = JSON.parse(jsonStr) as ScanEvent;

        switch (event.type) {
          case "stream_url":
            callbacks?.onStreamUrl?.(event.streamingUrl);
            break;
          case "status":
            callbacks?.onStatus?.(event.stage);
            break;
          case "result":
            finalResult = event.data;
            callbacks?.onResult?.(event.data);
            break;
        }
      } catch {
        // Skip malformed lines
      }
    }
  }

  if (!finalResult) {
    throw new Error("Analysis completed without returning results");
  }

  return finalResult;
}

async function mockAnalyzeUrl(
  request: AnalysisRequest,
  callbacks?: AnalyzeCallbacks
): Promise<AnalysisResult> {
  // Simulate stream_url arriving quickly
  await new Promise((r) => setTimeout(r, 400));
  callbacks?.onStreamUrl?.("https://stream.tinyfish.app/mock-session");

  // Simulate status updates
  const stages = ["connecting", "scraping", "analyzing", "generating"];
  for (const stage of stages) {
    await new Promise((r) => setTimeout(r, 700));
    callbacks?.onStatus?.(stage);
  }

  const result: AnalysisResult = {
    ...MOCK_RESULT,
    url: request.url,
    scanId: `mock-${Date.now()}`,
    analyzedAt: new Date().toISOString(),
  };

  callbacks?.onResult?.(result);
  return result;
}

export async function fetchScanById(id: string): Promise<AnalysisResult> {
  const apiUrl = import.meta.env.VITE_API_URL;

  if (!apiUrl) {
    // Mock mode
    return {
      ...MOCK_RESULT,
      scanId: id,
      analyzedAt: new Date().toISOString(),
    };
  }

  const response = await fetch(`${apiUrl}/scans/${encodeURIComponent(id)}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch scan (${response.status})`);
  }

  return response.json();
}
