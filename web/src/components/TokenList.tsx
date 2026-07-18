// Màn 1 — Danh sách token realtime, hiển thị TÁCH BẠCH BA TRỤC:
//   module (tên file + Track A/B) | chip (manufacturer_id) | CA (từ chain).
// Chọn token -> đăng nhập PIN -> xem chi tiết cert + ký.

import { useState } from "react";
import { useTokens } from "../api/hooks";
import { useTokenEvents } from "../api/events";
import type { CertRecord, LoginResponse, TokenBundle } from "../types";
import { Card, StatusBadge } from "./ui";
import { CertDetail } from "./CertDetail";
import { PinLogin } from "./PinLogin";
import { SignPanel } from "./SignPanel";

function ThreeAxis({ bundle }: { bundle: TokenBundle }) {
  const t = bundle.token;
  const cas = Array.from(new Set(bundle.certificates.map((c) => c.ca.ca_name).filter(Boolean)));
  return (
    <div className="axes">
      <div className="axis">
        <div className="axis-label">TRỤC 1 · MODULE</div>
        <div className="axis-val mono">{t.module_path.split(/[\\/]/).pop() || t.module_path}</div>
        <div className="axis-sub">Track {t.track || "?"} · {t.arch}{t.via_bridge ? " · qua cầu nối" : ""}</div>
      </div>
      <div className="axis">
        <div className="axis-label">TRỤC 2 · CHIP THẬT</div>
        <div className="axis-val">{t.manufacturer_id || "—"}</div>
        <div className="axis-sub">{t.model || ""}</div>
      </div>
      <div className="axis">
        <div className="axis-label">TRỤC 3 · CA (chain)</div>
        <div className="axis-val">{cas.length ? cas.join(", ") : "—"}</div>
        <div className="axis-sub">xác định bằng mật mã, không từ tên file</div>
      </div>
    </div>
  );
}

function TokenCard({ bundle }: { bundle: TokenBundle }) {
  const [session, setSession] = useState<LoginResponse | null>(null);
  const [openCert, setOpenCert] = useState<string | null>(null);

  // Sau khi đăng nhập, dùng danh sách cert (có khoá private) từ /login.
  const certs: CertRecord[] = session ? session.certificates : bundle.certificates;

  return (
    <Card
      title={
        <span>
          🔑 {bundle.token.label || "(không nhãn)"}{" "}
          <small className="muted">SN {bundle.token.serial || "—"}</small>
        </span>
      }
    >
      <ThreeAxis bundle={bundle} />

      {!session && <PinLogin tokenId={bundle.id} token={bundle.token} onLoggedIn={setSession} />}
      {session && <p className="note ok">Đã đăng nhập — phiên hết hạn sau {session.expires_in}s.</p>}

      <h3>Chứng thư ({certs.length})</h3>
      {certs.length === 0 && <p className="muted">Chưa thấy chứng thư (có thể cần đăng nhập PIN).</p>}
      {certs.map((rec) => {
        const key = rec.cert.sha256_thumbprint || rec.cert.subject_raw;
        const open = openCert === key;
        return (
          <div key={key} className="cert-item">
            <button className="cert-head" onClick={() => setOpenCert(open ? null : key)}>
              <StatusBadge status={rec.validation.status} />
              <span className="cert-cn">{rec.cert.subject_raw || "(không tên)"}</span>
              <span className="muted">{open ? "▲" : "▼"}</span>
            </button>
            {open && (
              <div className="cert-body">
                <CertDetail record={rec} />
                <h3>Ký tài liệu</h3>
                <SignPanel tokenId={bundle.id} sessionId={session?.session_id ?? ""} record={rec} />
              </div>
            )}
          </div>
        );
      })}
    </Card>
  );
}

export function TokenList() {
  const { data, isLoading, isError, error } = useTokens();
  const { connected } = useTokenEvents();

  return (
    <div>
      <p className="muted">
        Trạng thái theo dõi cắm/rút: {connected ? "🟢 đang lắng nghe (realtime)" : "🔴 mất kết nối"}
      </p>
      {isLoading && <p>Đang quét token…</p>}
      {isError && <p className="note bad">{error instanceof Error ? error.message : "Lỗi tải token."}</p>}
      {data && data.tokens.length === 0 && (
        <Card title="Chưa thấy token nào">
          <p>Hãy cắm USB token. Nếu đã cắm mà không thấy, xem tab “Chẩn đoán”.</p>
        </Card>
      )}
      {data?.tokens.map((b) => <TokenCard key={b.id} bundle={b} />)}

      {data && data.fallback_certificates.length > 0 && (
        <Card title="Chứng thư trong kho hệ điều hành (không đọc trực tiếp từ token)">
          <p className="note warn">
            Các chứng thư này do middleware/hệ điều hành lưu lại — vẫn đã qua kiểm tra hiệu lực, nhưng
            KHÔNG đọc trực tiếp từ chip.
          </p>
          {data.fallback_certificates.map((rec, i) => (
            <div key={i} className="cert-item">
              <div className="cert-head static">
                <StatusBadge status={rec.validation.status} />
                <span className="cert-cn">{rec.cert.subject_raw || "(không tên)"}</span>
                <span className="muted">{rec.source}</span>
              </div>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}
