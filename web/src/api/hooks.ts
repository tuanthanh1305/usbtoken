// Hook react-query cho các endpoint daemon.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { api } from "./client";
import { useTokenEvents } from "./events";

export function useHealth() {
  return useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15_000 });
}

export function useDiagnose() {
  return useQuery({ queryKey: ["diagnose"], queryFn: api.diagnose });
}

/** Danh sách token; tự làm mới khi có sự kiện cắm/rút (WS /events). */
export function useTokens() {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ["tokens"], queryFn: api.tokens });
  const { lastEvent } = useTokenEvents();
  useEffect(() => {
    if (lastEvent?.type === "token_event") {
      qc.invalidateQueries({ queryKey: ["tokens"] });
    }
  }, [lastEvent, qc]);
  return query;
}

export function useLogin() {
  return useMutation({
    mutationFn: (v: { tokenId: string; pin: string }) => api.login(v.tokenId, v.pin),
  });
}

export function useLogout() {
  return useMutation({ mutationFn: (sessionId: string) => api.logout(sessionId) });
}

export function useSign() {
  return useMutation({ mutationFn: api.sign });
}

export function useValidate() {
  return useMutation({ mutationFn: api.validate });
}
