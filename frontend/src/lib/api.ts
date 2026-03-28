import type {
  TinyFishEvent,
  VirusTotalResult,
  OpenAIResult,
  MergedScanResult,
} from "./types";

const API_URL = import.meta.env.VITE_API_URL as string | undefined;

function apiBase(): string {
  if (!API_URL) throw new Error("VITE_API_URL is not configured");
  return API_URL;
}

// ---------------------------------------------------------------------------
// TinyFish  –  SSE streaming scan
// ---------------------------------------------------------------------------

export interface TinyFishCallbacks {
  onStreamingUrl?: (url: string) => void;
  onProgress?: (purpose: string) => void;
}

/**
 * Calls POST /tinyfish, reads the SSE stream, and returns the scraped-content
 * string extracted from the COMPLETE event's `result`.
 */
export async function scanWithTinyFish(
  url: string,
  callbacks?: TinyFishCallbacks
): Promise<{ scrapedContent: string; streamingUrl?: string }> {
  const response = await fetch(`${apiBase()}/tinyfish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    throw new Error(
      response.status === 429
        ? "Too many requests. Please wait a moment and try again."
        : `TinyFish scan failed (${response.status})`
    );
  }

  const reader = response.body?.getReader();
  if (!reader) throw new Error("No response stream available");

  const decoder = new TextDecoder();
  let buffer = "";
  let scrapedContent = "";
  let streamingUrl: string | undefined;
  let completed = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || !trimmed.startsWith("data: ")) continue;

      const jsonStr = trimmed.slice(6);
      if (jsonStr === "[DONE]") continue;

      try {
        const event = JSON.parse(jsonStr) as TinyFishEvent;

        switch (event.type) {
          case "STREAMING_URL":
            streamingUrl = event.streaming_url;
            callbacks?.onStreamingUrl?.(event.streaming_url);
            break;
          case "PROGRESS":
            callbacks?.onProgress?.(event.purpose);
            break;
          case "COMPLETE": {
            // Extract scraped text from the result object.
            // The key may vary — try common access paths.
            const res = event.result;
            scrapedContent =
              typeof res === "string"
                ? res
                : (res?.extracted_text as string) ??
                  (res?.text as string) ??
                  (res?.content as string) ??
                  (res?.result as string) ??
                  JSON.stringify(res);
            completed = true;
            break;
          }
          case "ERROR":
            throw new Error(event.message);
        }
      } catch (err) {
        // Re-throw errors we created intentionally
        if (err instanceof Error && err.message) throw err;
      }
    }

    // Stop reading as soon as we have the result — don't wait for heartbeats
    if (completed) {
      reader.cancel();
      break;
    }
  }

  if (!scrapedContent) {
    throw new Error("TinyFish completed without returning scraped content");
  }

  return { scrapedContent, streamingUrl };
}

// ---------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------

export async function scanWithVirusTotal(url: string): Promise<VirusTotalResult> {
  const response = await fetch(`${apiBase()}/virustotal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    throw new Error(`VirusTotal scan failed (${response.status})`);
  }

  return response.json();
}

// ---------------------------------------------------------------------------
// OpenAI phishing analysis
// ---------------------------------------------------------------------------

export async function analyzeWithOpenAI(
  url: string,
  scrapedContent: string
): Promise<OpenAIResult> {
  const response = await fetch(`${apiBase()}/openai`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, scraped_content: scrapedContent }),
  });

  if (!response.ok) {
    throw new Error(`OpenAI analysis failed (${response.status})`);
  }

  return response.json();
}

// ---------------------------------------------------------------------------
// Full orchestrator
// ---------------------------------------------------------------------------

export type ScanStage = "scraping" | "analyzing" | "complete";

export interface FullScanCallbacks {
  onStageChange?: (stage: ScanStage) => void;
  onStreamingUrl?: (url: string) => void;
  onProgress?: (purpose: string) => void;
}

/**
 * Orchestrates the full scan:
 *  1. TinyFish SSE stream (scraping page)
 *  2. VirusTotal + OpenAI in parallel (once scraping completes)
 *  3. Merge into MergedScanResult
 */
export async function runFullScan(
  url: string,
  callbacks?: FullScanCallbacks
): Promise<MergedScanResult> {
  // --- Step 1: TinyFish ---
  callbacks?.onStageChange?.("scraping");

  const { scrapedContent, streamingUrl } = await scanWithTinyFish(url, {
    onStreamingUrl: callbacks?.onStreamingUrl,
    onProgress: callbacks?.onProgress,
  });

  // --- Step 2: VT + Gemini in parallel (either can fail) ---
  callbacks?.onStageChange?.("analyzing");

  const [vtSettled, aiSettled] = await Promise.allSettled([
    scanWithVirusTotal(url),
    analyzeWithOpenAI(url, scrapedContent),
  ]);

  const virusTotal = vtSettled.status === "fulfilled" ? vtSettled.value : null;
  const openai = aiSettled.status === "fulfilled" ? aiSettled.value : null;

  // If both failed, throw so the caller can show an error
  if (!virusTotal && !openai) {
    const vtErr = vtSettled.status === "rejected" ? vtSettled.reason : null;
    const aiErr = aiSettled.status === "rejected" ? aiSettled.reason : null;
    throw new Error(
      `Both analyses failed. VT: ${vtErr?.message ?? "unknown"}. AI: ${aiErr?.message ?? "unknown"}`
    );
  }

  // --- Step 3: Merge ---
  callbacks?.onStageChange?.("complete");

  return {
    url,
    scannedAt: new Date().toISOString(),
    scrapedContent,
    streamingUrl,
    virusTotal,
    openai,
  };
}
