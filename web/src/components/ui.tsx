// Thành phần UI dùng chung, tối giản.

import { useState, type ReactNode } from "react";
import type { ValidationStatus } from "../types";
import { STATUS_LABEL, STATUS_TONE } from "../i18n";

export function Card({ title, children, tone }: { title?: ReactNode; children: ReactNode; tone?: string }) {
  return (
    <section className={`card${tone ? ` ${tone}` : ""}`}>
      {title && <h2>{title}</h2>}
      {children}
    </section>
  );
}

export function StatusBadge({ status, big }: { status: ValidationStatus; big?: boolean }) {
  return (
    <span className={`badge ${STATUS_TONE[status]}${big ? " big" : ""}`}>{STATUS_LABEL[status]}</span>
  );
}

export function CopyButton({ text, label = "Sao chép" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn small"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* trình duyệt chặn clipboard — bỏ qua */
        }
      }}
    >
      {done ? "✓ Đã sao chép" : label}
    </button>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return <p className="note bad">⚠️ {message}</p>;
}

export function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("vi-VN");
}
