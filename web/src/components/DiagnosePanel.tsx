// Màn 6 — Chẩn đoán theo ĐÚNG OS. Remediation do daemon tính sẵn theo hệ điều
// hành (/diagnose); UI hiển thị + nút sao chép (vd. nội dung udev rule trên Linux).

import { useDiagnose } from "../api/hooks";
import { OS_LABEL } from "../i18n";
import { Card, CopyButton } from "./ui";

export function DiagnosePanel() {
  const { data, isLoading, isError, error } = useDiagnose();

  if (isLoading) return <p>Đang chẩn đoán…</p>;
  if (isError) return <p className="note bad">{error instanceof Error ? error.message : "Lỗi chẩn đoán."}</p>;
  if (!data) return null;

  const os = data.platform.name;

  return (
    <div>
      <Card title={`Chẩn đoán — ${OS_LABEL[os] ?? os}`}>
        <dl className="kv">
          <dt>Kiến trúc</dt>
          <dd>
            {data.platform.machine} · {data.platform.bits}-bit
            {data.platform.rosetta ? " · Rosetta 2" : ""}
          </dd>
          <dt>PC/SC</dt>
          <dd>{data.pcsc_ready ? "✅ sẵn sàng" : "⚠️ chưa sẵn sàng"}</dd>
          <dt>Module phát hiện</dt>
          <dd>{data.modules_found}</dd>
        </dl>
        {!data.pcsc_ready && data.pcsc_remediation && (
          <RemediationBlock text={data.pcsc_remediation} />
        )}
        <p className="note">{data.note}</p>
      </Card>

      <Card title="Nguyên nhân khả dĩ & cách khắc phục (theo thứ tự xác suất)">
        {data.diagnostics.length === 0 ? (
          <p className="note ok">Không phát hiện vấn đề nào cản trở.</p>
        ) : (
          <ol className="diag-list">
            {data.diagnostics.map((d, i) => (
              <li key={i}>
                <div className="diag-msg">
                  <span className="chip">{d.code}</span> {d.message_vi}
                </div>
                {d.remediation && <RemediationBlock text={d.remediation} />}
              </li>
            ))}
          </ol>
        )}
      </Card>

      {data.platform.service_install_hint && (
        <Card title="Chạy daemon dưới nền">
          <RemediationBlock text={data.platform.service_install_hint} />
        </Card>
      )}
    </div>
  );
}

function RemediationBlock({ text }: { text: string }) {
  return (
    <div className="remediation">
      <pre className="hint">{text}</pre>
      <CopyButton text={text} label="Sao chép hướng dẫn" />
    </div>
  );
}
