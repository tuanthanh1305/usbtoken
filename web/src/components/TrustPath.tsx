// ⭐ Đường dẫn tin cậy trực quan: Thuê bao → CA công cộng → Vietnam National Root CA
// (Điều 5 TT 15: hiển thị rõ ràng chuỗi đường dẫn tin cậy).

import type { TrustPathNode } from "../types";

function roleOf(node: TrustPathNode, index: number, total: number): string {
  if (node.is_trust_anchor || index === total - 1) return "Neo gốc (NEAC Root)";
  if (index === 0) return "Thuê bao (người ký)";
  return "CA công cộng";
}

export function TrustPath({ nodes }: { nodes: TrustPathNode[] }) {
  if (nodes.length === 0) {
    return <p className="note bad">Không dựng được đường dẫn tin cậy tới gốc NEAC.</p>;
  }
  return (
    <div className="trustpath">
      {nodes.map((n, i) => (
        <div key={n.fingerprint_sha256 || i} className="trustpath-row">
          <div className={`tp-node${n.is_trust_anchor ? " anchor" : ""}`}>
            <div className="tp-role">{roleOf(n, i, nodes.length)}</div>
            <div className="tp-name">{n.ca_name || n.subject}</div>
            <div className="tp-fp mono">SHA-256: {n.fingerprint_sha256.slice(0, 32)}…</div>
          </div>
          {i < nodes.length - 1 && <div className="tp-arrow">↑ được cấp bởi</div>}
        </div>
      ))}
    </div>
  );
}
