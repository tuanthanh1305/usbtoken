// Client gọi daemon vn-esign (loopback). Vite proxy chuyển tiếp tới 127.0.0.1:8787.
// Thông báo lỗi LUÔN bằng tiếng Việt (Điều 5 TT 15/2025).

import type {
  DiagnoseResponse,
  HealthResponse,
  LoginResponse,
  SignResponse,
  TokensResponse,
  ValidateResponse,
} from "../types";

/** Lỗi API có sẵn thông điệp tiếng Việt để hiển thị. */
export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

function messageFromDetail(detail: unknown, status: number): string {
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object") {
    const d = detail as Record<string, unknown>;
    if (typeof d.message_vi === "string") return d.message_vi;
    if (typeof d.detail === "string") return d.detail;
  }
  return `Yêu cầu thất bại (HTTP ${status}).`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
    });
  } catch {
    throw new ApiError(
      "Không kết nối được daemon. Hãy chạy 'python -m service.app' rồi thử lại.",
      0,
      null,
    );
  }
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // Thân phản hồi không phải JSON (vd. trang lỗi 502 của proxy) — vẫn báo lỗi
    // tiếng Việt thân thiện thay vì ném SyntaxError tiếng Anh.
    if (!res.ok) throw new ApiError(messageFromDetail(null, res.status), res.status, text);
    throw new ApiError("Phản hồi từ daemon không hợp lệ (không phải JSON).", res.status, text);
  }
  if (!res.ok) {
    const detail = body && typeof body === "object" ? (body as Record<string, unknown>).detail ?? body : body;
    throw new ApiError(messageFromDetail(detail, res.status), res.status, detail);
  }
  return body as T;
}

export const api = {
  health: () => request<HealthResponse>("/health"),
  diagnose: () => request<DiagnoseResponse>("/diagnose"),
  tokens: () => request<TokensResponse>("/tokens"),
  tokenCerts: (id: string, sessionId?: string) =>
    request<{ token_id: string; logged_in: boolean; certificates: TokensResponse["tokens"][number]["certificates"]; warnings: string[] }>(
      `/tokens/${encodeURIComponent(id)}/certs${sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : ""}`,
    ),
  login: (tokenId: string, pin: string) =>
    request<LoginResponse>("/login", { method: "POST", body: JSON.stringify({ token_id: tokenId, pin }) }),
  logout: (sessionId: string) =>
    request<{ logged_out: boolean }>("/logout", { method: "POST", body: JSON.stringify({ session_id: sessionId }) }),
  sign: (input: {
    token_id: string;
    key_id: string;
    format: string;
    payload_base64: string;
    session_id: string;
    tsa_url?: string;
  }) => request<SignResponse>("/sign", { method: "POST", body: JSON.stringify(input) }),
  validate: (input: {
    certificate_b64: string;
    signature?: { data_b64: string; signature_b64: string; algorithm?: string };
  }) => request<ValidateResponse>("/validate", { method: "POST", body: JSON.stringify(input) }),
};

/** Đọc file -> base64 (không kèm tiền tố data:). */
export function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result);
      resolve(result.slice(result.indexOf(",") + 1));
    };
    reader.onerror = () => reject(new Error("Không đọc được tệp."));
    reader.readAsDataURL(file);
  });
}

/** Tải một chuỗi base64 xuống dưới dạng tệp nhị phân. */
export function downloadBase64(b64: string, filename: string): void {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
