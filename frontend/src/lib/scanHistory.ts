import type { ScanHistoryEntry } from "./types";

const STORAGE_KEY = "tinyphish_recent_scans";
const MAX_ENTRIES = 10;

export function getScanHistory(): ScanHistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as ScanHistoryEntry[];
  } catch {
    return [];
  }
}

export function addScanToHistory(entry: ScanHistoryEntry): void {
  const history = getScanHistory();
  // Remove duplicate if same scanId already exists
  const filtered = history.filter((h) => h.scanId !== entry.scanId);
  const updated = [entry, ...filtered].slice(0, MAX_ENTRIES);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
}

export function clearScanHistory(): void {
  localStorage.removeItem(STORAGE_KEY);
}
