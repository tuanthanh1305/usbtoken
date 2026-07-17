// Client gọi daemon vn-esign (localhost). Vite proxy "/api" -> 127.0.0.1:8787.

import type { ModuleCandidate, PlatformInfo, TrustStatus } from "../types";

const BASE = "/api";

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`Yêu cầu ${path} thất bại: HTTP ${res.status}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => getJSON<{ status: string; version: string }>("/health"),
  platform: () => getJSON<PlatformInfo>("/platform"),
  modules: () => getJSON<ModuleCandidate[]>("/modules"),
  trustStatus: () => getJSON<TrustStatus>("/trust/status"),
};
