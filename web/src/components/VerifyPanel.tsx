// Màn 5 — Kiểm tra chữ ký số (phần mềm kiểm tra CKS).
// Upload chứng thư (+ tuỳ chọn dữ liệu gốc & chữ ký tách rời) -> /validate.
// Hiển thị đầy đủ trust path + trạng thái thu hồi + cảnh báo nếu dữ liệu bị đổi.

import { useState } from "react";
import { useValidate } from "../api/hooks";
import { ApiError, fileToBase64 } from "../api/client";
import type { ValidateResponse } from "../types";
import { Card, StatusBadge } from "./ui";
import { TrustPath } from "./TrustPath";
import { RevocationInfo } from "./RevocationInfo";

export function VerifyPanel() {
  const [certFile, setCertFile] = useState<File | null>(null);
  const [dataFile, setDataFile] = useState<File | null>(null);
  const [sigFile, setSigFile] = useState<File | null>(null);
  const [result, setResult] = useState<ValidateResponse | null>(null);
  const validate = useValidate();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!certFile) return;
    const certificate_b64 = await fileToBase64(certFile);
    const input: Parameters<typeof validate.mutate>[0] = { certificate_b64 };
    if (dataFile && sigFile) {
      input.signature = {
        data_b64: await fileToBase64(dataFile),
        signature_b64: await fileToBase64(sigFile),
        algorithm: "sha256",
      };
    }
    validate.mutate(input, { onSuccess: setResult });
  };

  return (
    <Card title="Kiểm tra chữ ký số / chứng thư">
      <form className="signform" onSubmit={submit}>
        <label className="field">
          Chứng thư người ký (DER/.cer) — bắt buộc
          <input type="file" onChange={(e) => setCertFile(e.target.files?.[0] ?? null)} />
        </label>
        <label className="field">
          Dữ liệu gốc (tuỳ chọn — để kiểm chữ ký tách rời)
          <input type="file" onChange={(e) => setDataFile(e.target.files?.[0] ?? null)} />
        </label>
        <label className="field">
          Tệp chữ ký (tuỳ chọn)
          <input type="file" onChange={(e) => setSigFile(e.target.files?.[0] ?? null)} />
        </label>
        <button className="btn" type="submit" disabled={!certFile || validate.isPending}>
          {validate.isPending ? "Đang kiểm tra…" : "Kiểm tra"}
        </button>
      </form>

      {validate.isError && (
        <p className="note bad">{validate.error instanceof ApiError ? validate.error.message : "Kiểm tra thất bại."}</p>
      )}

      {result && (
        <div className="verify-result">
          <div className="status-hero">
            <StatusBadge status={result.validation.status} big />
            <ul className="reasons">
              {result.validation.reasons_vi.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>

          {result.signature_valid !== undefined && (
            <p className={`note ${result.signature_valid ? "ok" : "bad"}`}>
              {result.signature_valid
                ? "✅ Chữ ký khớp — dữ liệu TOÀN VẸN."
                : "⛔ Chữ ký KHÔNG khớp — dữ liệu có thể ĐÃ BỊ THAY ĐỔI."}
              {result.signature_reason_vi ? ` ${result.signature_reason_vi}` : ""}
            </p>
          )}

          <h3>Đường dẫn tin cậy</h3>
          <TrustPath nodes={result.validation.trust_path} />
          <h3>Kiểm tra thu hồi</h3>
          <RevocationInfo items={result.validation.revocations} />
        </div>
      )}
    </Card>
  );
}
