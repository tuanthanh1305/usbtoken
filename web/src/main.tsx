import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import "./styles.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Không tìm thấy #root để mount React.");

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
