// Kiểu TS phản chiếu data model pydantic (core/models.py). Giữ đồng bộ thủ công.

export interface PlatformInfo {
  name: "windows" | "macos" | "linux";
  bits: 64 | 32;
  machine: "arm64" | "x86_64";
  rosetta: boolean;
  python_version: string;
  pcsc_ready: boolean;
  pcsc_remediation: string;
  config_dir: string;
  log_dir: string;
  service_install_hint: string;
}

export interface ModuleCandidate {
  path: string;
  track: "A" | "B";
  chip_hint: string;
  source: string;
  confidence: number;
  arch: string;
  validated: boolean;
  needs_arch_bridge: boolean;
  warnings: string[];
}

export interface TrustStatus {
  trust_store: { total_certificates: number; trust_anchors: number };
  appendix_i_filled: boolean;
  appendix_ii_filled: boolean;
  fully_configured: boolean;
}
