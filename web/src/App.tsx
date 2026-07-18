import { useState } from "react";
import { HealthBar, TrustStorePanel } from "./components/HealthBar";
import { TokenList } from "./components/TokenList";
import { VerifyPanel } from "./components/VerifyPanel";
import { DiagnosePanel } from "./components/DiagnosePanel";

type Tab = "tokens" | "verify" | "diagnose" | "trust";

const TABS: { id: Tab; label: string }[] = [
  { id: "tokens", label: "Token & Ký" },
  { id: "verify", label: "Kiểm tra chữ ký" },
  { id: "diagnose", label: "Chẩn đoán" },
  { id: "trust", label: "Kho tin cậy" },
];

export function App() {
  const [tab, setTab] = useState<Tab>("tokens");

  return (
    <div className="app">
      <HealthBar />
      <header className="apphead">
        <h1>vn-esign-suite</h1>
        <p className="subtitle">Ký số &amp; kiểm tra chữ ký số trên USB token — Windows · macOS · Linux</p>
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button key={t.id} className={`tab${tab === t.id ? " active" : ""}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </nav>

      <main className="container">
        {tab === "tokens" && <TokenList />}
        {tab === "verify" && <VerifyPanel />}
        {tab === "diagnose" && <DiagnosePanel />}
        {tab === "trust" && <TrustStorePanel />}
      </main>

      <footer className="appfoot">
        Thông báo bằng tiếng Việt theo Điều 5 TT 15/2025/TT-BKHCN. Daemon chỉ chạy loopback; PIN không lưu, không log.
      </footer>
    </div>
  );
}
