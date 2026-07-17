import { useEffect, useState } from "react";
import { api } from "./api/client";
import type { ModuleCandidate, PlatformInfo, TrustStatus } from "./types";

// Màn hình chẩn đoán: nền tảng, module (Track A/B), trạng thái kho tin cậy & Phụ lục.

export function App() {
  const [platform, setPlatform] = useState<PlatformInfo | null>(null);
  const [modules, setModules] = useState<ModuleCandidate[]>([]);
  const [trust, setTrust] = useState<TrustStatus | null>(null);
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [p, m, t] = await Promise.all([api.platform(), api.modules(), api.trustStatus()]);
        if (!alive) return;
        setPlatform(p);
        setModules(m);
        setTrust(t);
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  return (
    <main className="container">
      <header>
        <h1>vn-esign-suite</h1>
        <p className="subtitle">
          Ký số &amp; kiểm tra chữ ký số trên USB token — Windows · macOS · Linux
        </p>
      </header>

      {loading && <p>Đang tải dữ liệu chẩn đoán…</p>}

      {error && (
        <section className="card error">
          <h2>Không kết nối được daemon</h2>
          <p>{error}</p>
          <p>
            Chạy: <code>python -m service.main</code> rồi tải lại trang.
          </p>
        </section>
      )}

      {platform && (
        <section className="card">
          <h2>Nền tảng</h2>
          <dl className="kv">
            <dt>Hệ điều hành</dt>
            <dd>{platform.name}</dd>
            <dt>Kiến trúc</dt>
            <dd>
              {platform.machine} · {platform.bits}-bit
              {platform.rosetta ? " · Rosetta 2" : ""}
            </dd>
            <dt>PC/SC</dt>
            <dd>{platform.pcsc_ready ? "✅ Sẵn sàng" : "⚠️ Chưa sẵn sàng"}</dd>
          </dl>
          {!platform.pcsc_ready && platform.pcsc_remediation && (
            <pre className="hint">{platform.pcsc_remediation}</pre>
          )}
        </section>
      )}

      {trust && (
        <section className="card">
          <h2>Kho tin cậy &amp; Tuân thủ TT 15/2025</h2>
          <dl className="kv">
            <dt>Chứng thư trong kho</dt>
            <dd>
              {trust.trust_store.total_certificates} (neo gốc:{" "}
              {trust.trust_store.trust_anchors})
            </dd>
            <dt>Phụ lục I</dt>
            <dd>{trust.appendix_i_filled ? "✅ đã điền" : "⚠️ chưa điền"}</dd>
            <dt>Phụ lục II</dt>
            <dd>{trust.appendix_ii_filled ? "✅ đã điền" : "⚠️ chưa điền"}</dd>
          </dl>
          {!trust.fully_configured && (
            <p className="note">
              Kiểm tra hợp lệ theo Phụ lục bị tạm khoá (fail-safe) tới khi điền đủ
              từ bản gốc TT 15/2025.
            </p>
          )}
        </section>
      )}

      <section className="card">
        <h2>Module PKCS#11 — Track A/B ({modules.length})</h2>
        <p className="note">
          TRỤC 1 (cách nạp). Chip thật đọc qua token; CA xác định bằng chain
          building — KHÔNG bằng tên file.
        </p>
        {modules.length === 0 ? (
          <p>Chưa phát hiện module nào.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Track</th>
                <th>Gợi ý</th>
                <th>Đường dẫn</th>
                <th>Arch</th>
                <th>Cầu nối</th>
              </tr>
            </thead>
            <tbody>
              {modules.map((m) => (
                <tr key={m.path}>
                  <td>{m.track}</td>
                  <td>{m.chip_hint || "—"}</td>
                  <td className="mono">{m.path}</td>
                  <td>{m.arch}</td>
                  <td>{m.needs_arch_bridge ? "⚠️ cần" : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
