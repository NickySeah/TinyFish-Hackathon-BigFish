import type { AnalysisRequest, AnalysisResult } from "./types";

const MOCK_RESULT: AnalysisResult = {
  url: "https://secure-banklogin.xyz/verify",
  confidenceScore: 82,
  analyzedAt: new Date().toISOString(),
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

export async function analyzeUrl(
  request: AnalysisRequest
): Promise<AnalysisResult> {
  const apiUrl = import.meta.env.VITE_API_URL;

  if (!apiUrl) {
    // Mock mode: simulate backend delay, return realistic data
    await new Promise((resolve) => setTimeout(resolve, 3000));
    return { ...MOCK_RESULT, url: request.url, analyzedAt: new Date().toISOString() };
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

  return response.json();
}
