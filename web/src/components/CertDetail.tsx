// Màn 2 — Chi tiết chứng thư. TRẠNG THÁI HỢP LỆ nổi bật nhất; kèm đường dẫn tin
// cậy + thông tin thu hồi (Điều 5 TT 15/2025).

import type { CertRecord } from "../types";
import { PROFILE_CONFIDENCE_LABEL, STATUS_HINT } from "../i18n";
import { StatusBadge, CopyButton, fmtDate } from "./ui";
import { TrustPath } from "./TrustPath";
import { RevocationInfo } from "./RevocationInfo";

function vnIdEntries(vn: Record<string, string[]>): [string, string][] {
  return Object.entries(vn).flatMap(([k, vs]) => vs.map((v) => [k, v] as [string, string]));
}

export function CertDetail({ record }: { record: CertRecord }) {
  const { cert, ca, validation } = record;
  const status = validation.status;
  const lowConfidence = cert.profile_confidence === "unknown" || cert.profile_confidence === "low";
  const ids = vnIdEntries(cert.vn_ids);

  return (
    <div className="certdetail">
      {/* ⭐ Trạng thái hợp lệ — nổi bật nhất */}
      <div className="status-hero">
        <StatusBadge status={status} big />
        <p className="status-hint">{STATUS_HINT[status]}</p>
        {validation.reasons_vi.length > 0 && (
          <ul className="reasons">
            {validation.reasons_vi.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        )}
      </div>

      <dl className="kv">
        <dt>Tên chủ thể (CN)</dt>
        <dd>{cert.subject_raw || "—"}</dd>
        <dt>CA phát hành (từ chain)</dt>
        <dd>{ca.ca_name || "—"}</dd>
        <dt>Định danh VN (MST/CCCD…)</dt>
        <dd>
          {ids.length === 0 ? (
            "—"
          ) : (
            <>
              {ids.map(([k, v], i) => (
                <span key={i} className="chip">
                  {k}: {v}
                </span>
              ))}
              {lowConfidence && (
                <div className="note warn">
                  ⚠️ Độ tin cậy trích xuất định danh: {PROFILE_CONFIDENCE_LABEL[cert.profile_confidence] ?? cert.profile_confidence}.
                  Hãy đối chiếu Subject gốc — KHÔNG coi là chuẩn.
                </div>
              )}
            </>
          )}
        </dd>
        <dt>Hiệu lực</dt>
        <dd>
          {fmtDate(cert.not_before)} → {fmtDate(cert.not_after)}
          {cert.is_expired ? " · ĐÃ HẾT HẠN" : cert.days_remaining != null ? ` · còn ${cert.days_remaining} ngày` : ""}
        </dd>
        <dt>Thumbprint SHA-256</dt>
        <dd className="mono">
          {cert.sha256_thumbprint || "—"} {cert.sha256_thumbprint && <CopyButton text={cert.sha256_thumbprint} />}
        </dd>
        <dt>Khoá công khai</dt>
        <dd>
          {cert.public_key_algo || "?"} {cert.key_size ? `${cert.key_size} bit` : ""}
          {cert.key?.has_private_key ? " · có khoá private trên token" : ""}
        </dd>
        <dt>Key Usage</dt>
        <dd>{cert.key_usage.length ? cert.key_usage.join(", ") : "—"}</dd>
        <dt>Nguồn phát hiện</dt>
        <dd>
          {record.source}
          {record.from_token ? " · đọc trực tiếp từ token" : " · CACHE trong kho hệ điều hành (không từ token)"}
        </dd>
      </dl>

      <h3>Đường dẫn tin cậy</h3>
      <TrustPath nodes={validation.trust_path} />

      <h3>Kiểm tra thu hồi</h3>
      <RevocationInfo items={validation.revocations} />
    </div>
  );
}
