// ⭐ Thông tin kiểm tra thu hồi: phương thức (CRL/OCSP), thời điểm, hiệu lực CRL.

import type { RevocationEvidence } from "../types";
import { REVOCATION_LABEL } from "../i18n";
import { fmtDate } from "./ui";

function toneOf(r: RevocationEvidence): string {
  if (r.status === "revoked") return "bad";
  if (r.status === "good") return "ok";
  return "warn";
}

function crlExpired(r: RevocationEvidence): boolean {
  return r.next_update != null && new Date(r.next_update).getTime() < Date.now();
}

export function RevocationInfo({ items }: { items: RevocationEvidence[] }) {
  if (items.length === 0) {
    return <p className="note warn">Chưa có dữ liệu kiểm tra thu hồi.</p>;
  }
  return (
    <table className="rev">
      <thead>
        <tr>
          <th>Mắt xích</th>
          <th>Trạng thái</th>
          <th>Phương thức</th>
          <th>Thời điểm kiểm</th>
          <th>Hiệu lực đến</th>
        </tr>
      </thead>
      <tbody>
        {items.map((r, i) => (
          <tr key={i}>
            <td>{r.node_subject || "—"}</td>
            <td className={toneOf(r)}>{REVOCATION_LABEL[r.status]}</td>
            <td>{r.method || "—"}</td>
            <td>{fmtDate(r.checked_at)}</td>
            <td className={crlExpired(r) ? "bad" : ""}>
              {fmtDate(r.next_update)}
              {crlExpired(r) && " · ⚠️ CRL đã hết hạn"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
