// Màn 4 — Ký. Nếu status != VALID -> DISABLE nút ký + giải thích tiếng Việt
// (yêu cầu luật định Điều 5). Upload PDF/XML -> /sign -> kết quả + evidence_id.

import { useState } from "react";
import type { CertRecord, SignResponse } from "../types";
import { useSign } from "../api/hooks";
import { ApiError, downloadBase64, fileToBase64 } from "../api/client";
import { STATUS_HINT } from "../i18n";
import { fmtDate } from "./ui";

export function SignPanel({
  tokenId,
  sessionId,
  record,
}: {
  tokenId: string;
  sessionId: string;
  record: CertRecord;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState("cms");
  const [result, setResult] = useState<SignResponse | null>(null);
  const sign = useSign();

  const status = record.validation.status;
  const canSign =
    status === "valid" && record.cert.key?.has_private_key === true && sessionId !== "";

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    const payload_base64 = await fileToBase64(file);
    sign.mutate(
      { token_id: tokenId, key_id: record.cert.key_id_hex, format, payload_base64, session_id: sessionId },
      { onSuccess: setResult },
    );
  };

  if (!canSign) {
    return (
      <div className="note bad">
        🚫 KHÔNG được phép ký bằng chứng thư này.
        <div>{STATUS_HINT[status]}</div>
        {!record.cert.key?.has_private_key && <div>Chứng thư không có khoá private trên token.</div>}
        {sessionId === "" && <div>Cần đăng nhập PIN token trước khi ký.</div>}
      </div>
    );
  }

  return (
    <form className="signform" onSubmit={submit}>
      <div className="row">
        <label>
          Định dạng
          <select value={format} onChange={(e) => setFormat(e.target.value)}>
            <option value="cms">CMS/PKCS#7 (CAdES)</option>
            <option value="pades">PAdES (PDF)</option>
            <option value="xades">XAdES (XML)</option>
          </select>
        </label>
        <input type="file" accept=".pdf,.xml,application/pdf,text/xml" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        <button className="btn" type="submit" disabled={!file || sign.isPending}>
          {sign.isPending ? "Đang ký…" : "Ký tài liệu"}
        </button>
      </div>

      {sign.isError && (
        <p className="note bad">{sign.error instanceof ApiError ? sign.error.message : "Ký thất bại."}</p>
      )}

      {result && (
        <div className="card ok">
          <h3>✅ Đã ký thành công</h3>
          <dl className="kv">
            <dt>Mã bằng chứng</dt>
            <dd className="mono">{result.evidence_id}</dd>
            <dt>Định dạng · thuật toán</dt>
            <dd>
              {result.format.toUpperCase()} · {result.signature_algorithm}
            </dd>
            <dt>Thời điểm ký</dt>
            <dd>{fmtDate(result.signing_time)}</dd>
            <dt>Dấu thời gian (TSA)</dt>
            <dd>{result.timestamped ? "có" : "không"}</dd>
          </dl>
          <ul className="reasons">
            {result.reasons_vi.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
          <button
            className="btn"
            type="button"
            onClick={() => downloadBase64(result.signed_document_base64, `signed_${result.evidence_id}.${result.format === "pades" ? "pdf" : "p7s"}`)}
          >
            ⬇ Tải tài liệu đã ký
          </button>
        </div>
      )}
    </form>
  );
}
