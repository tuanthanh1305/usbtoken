// Kết nối WebSocket /events (cắm/rút token realtime), tự kết nối lại.

import { useEffect, useRef, useState } from "react";
import type { TokenEvent } from "../types";

export function useTokenEvents() {
  const [lastEvent, setLastEvent] = useState<TokenEvent | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let closed = false;
    let retry: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      if (closed) return;
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${window.location.host}/events`);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onmessage = (ev) => {
        try {
          setLastEvent(JSON.parse(ev.data) as TokenEvent);
        } catch {
          /* bỏ qua bản tin hỏng */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 3000); // tự kết nối lại
      };
      ws.onerror = () => ws.close();
    };
    connect();

    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      wsRef.current?.close();
    };
  }, []);

  return { lastEvent, connected };
}
