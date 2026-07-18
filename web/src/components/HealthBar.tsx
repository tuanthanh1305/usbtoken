// Màn 7 (+ thanh trạng thái đầu trang) — nền tảng + kho neo tin cậy.
// CẢNH BÁO NỔI BẬT nếu kho quá cũ (stale) hoặc chưa ký/rỗng.

import { useHealth } from "../api/hooks";
import { OS_LABEL } from "../i18n";
import { Card, fmtDate } from "./ui";

export function HealthBar() {
  const { data, isError, error } = useHealth();

  if (isError) {
    return (
      <div className="healthbar bad">
        ⛔ Không kết nối được daemon: {error instanceof Error ? error.message : ""}. Chạy{" "}
        <code>python -m service.app</code> rồi tải lại.
      </div>
    );
  }
  if (!data) return <div className="healthbar">Đang kết nối daemon…</div>;

  const ts = data.trust_store;
  return (
    <div className={`healthbar${ts.stale || ts.empty || !ts.verified ? " warn" : " ok"}`}>
      <span>
        {OS_LABEL[data.platform.os] ?? data.platform.os} · {data.platform.arch} · {data.platform.bits}-bit
        {data.platform.rosetta ? " · Rosetta 2" : ""}
        {data.platform.bridge_active ? " · 🔗 cầu nối đang chạy" : ""}
      </span>
      <span className="spacer" />
      <span>daemon v{data.version}</span>
    </div>
  );
}

export function TrustStorePanel() {
  const { data } = useHealth();
  if (!data) return null;
  const ts = data.trust_store;
  const problem = ts.stale || ts.empty || !ts.verified;

  return (
    <Card title="Kho neo tin cậy (NEAC + CA công cộng)" tone={problem ? "warn" : undefined}>
      <dl className="kv">
        <dt>Đồng bộ lần cuối</dt>
        <dd>{fmtDate(ts.synced_at)}</dd>
        <dt>Trạng thái</dt>
        <dd>
          {ts.empty ? "RỖNG" : ts.verified ? "đã ký & xác minh" : "CHƯA ký/xác minh"}
        </dd>
      </dl>
      {problem && (
        <div className="note bad">
          ⚠️ CẢNH BÁO: kho neo tin cậy {ts.empty ? "đang RỖNG" : ts.stale ? "đã QUÁ CŨ" : "CHƯA được ký/xác minh"} —
          kết quả kiểm tra hiệu lực có thể không đáng tin. Hãy đồng bộ lại từ rootca.gov.vn.
          {ts.reasons_vi.map((r, i) => (
            <div key={i}>• {r}</div>
          ))}
        </div>
      )}
    </Card>
  );
}
