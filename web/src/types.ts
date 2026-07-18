// Kiểu dữ liệu API — ánh xạ trực tiếp core/models.py của daemon.
// Giữ tối giản: chỉ trường UI dùng tới (nhưng đủ để không "đoán" phía backend).

export type ValidationStatus =
  | "valid"
  | "invalid"
  | "expired"
  | "revoked"
  | "unknown"
  | "foreign_recognized";

export type RevocationStatus = "good" | "revoked" | "unknown" | "unchecked";

export interface PinState {
  login_required: boolean;
  count_low: boolean;
  final_try: boolean;
  locked: boolean;
  protected_auth_path: boolean;
}

export interface TokenInfo {
  module_path: string;
  slot_id: number;
  label: string;
  manufacturer_id: string; // ⭐ TRỤC 2 — chip THẬT
  model: string;
  serial: string;
  flags: number;
  pin_state: PinState;
  track: string; // TRỤC 1 — A|B
  chip_hint: string;
  source: string;
  arch: string;
  via_bridge: boolean;
}

export interface KeyInfo {
  has_private_key: boolean;
  label: string;
  id_hex: string;
  key_type: string;
  key_size: number | null;
  usable_for_signing: boolean;
}

export interface CertInfo {
  subject_raw: string;
  issuer_raw: string;
  serial_number: string;
  not_before: string | null;
  not_after: string | null;
  is_expired: boolean;
  days_remaining: number | null;
  key_usage: string[];
  extended_key_usage: string[];
  sha1_thumbprint: string;
  sha256_thumbprint: string;
  public_key_algo: string;
  key_size: number | null;
  vn_ids: Record<string, string[]>;
  profile_confidence: string; // unknown|low|medium
  warnings: string[];
  der_b64: string;
  key_id_hex: string;
  key: KeyInfo | null;
}

export interface CAInfo {
  ca_name: string; // ⭐ TRỤC 3 — từ chain building
  ca_cert_subject: string;
  chain_verified: boolean;
  trust_anchor: string;
}

export interface TrustPathNode {
  subject: string;
  issuer: string;
  serial_hex: string;
  is_trust_anchor: boolean;
  fingerprint_sha256: string;
  ca_name: string;
}

export interface RevocationEvidence {
  node_subject: string;
  status: RevocationStatus;
  method: string; // OCSP|CRL|NONE
  source_url: string;
  checked_at: string | null;
  this_update: string | null;
  next_update: string | null;
  crl_snapshot_sha256: string;
  reasons_vi: string[];
}

export interface ValidationResult {
  status: ValidationStatus;
  checked_at: string;
  at_time: string;
  subject: string;
  ca_name: string;
  trust_path: TrustPathNode[];
  revocations: RevocationEvidence[];
  trust_store_synced_at: string | null;
  reasons_vi: string[];
}

export interface CertRecord {
  cert: CertInfo;
  ca: CAInfo;
  validation: ValidationResult;
  source: string;
  from_token: boolean;
  token_ref: string;
}

export interface TokenBundle {
  id: string;
  token: TokenInfo;
  certificates: CertRecord[];
}

export interface TokensResponse {
  tokens: TokenBundle[];
  fallback_certificates: CertRecord[];
  sources_scanned: string[];
  warnings: string[];
}

export interface TrustStoreHealth {
  synced_at: string | null;
  stale: boolean;
  verified: boolean;
  empty: boolean;
  reasons_vi: string[];
}

export interface HealthResponse {
  ok: boolean;
  version: string;
  platform: {
    os: "windows" | "macos" | "linux";
    arch: string;
    bits: number;
    rosetta: boolean;
    bridge_active: boolean;
  };
  trust_store: TrustStoreHealth;
}

export interface ErrorInfo {
  code: string;
  message_vi: string;
  remediation: string;
  platform: string;
  detail: string;
}

export interface DiagnoseResponse {
  platform: {
    name: "windows" | "macos" | "linux";
    machine: string;
    bits: number;
    rosetta: boolean;
    service_install_hint: string;
  };
  pcsc_ready: boolean;
  pcsc_remediation: string;
  modules_found: number;
  modules: Array<{
    track: string;
    chip_hint: string;
    path: string;
    arch: string;
    needs_arch_bridge: boolean;
  }>;
  trust_store: TrustStoreHealth;
  diagnostics: ErrorInfo[];
  note: string;
}

export interface LoginResponse {
  session_id: string;
  token_id: string;
  expires_in: number;
  certificates: CertRecord[];
  warnings: string[];
}

export interface SignResponse {
  signed_document_base64: string;
  validation_result: ValidationResult;
  evidence_id: string;
  format: string;
  mechanism: string;
  signature_algorithm: string;
  signing_time: string;
  timestamped: boolean;
  reasons_vi: string[];
}

export interface ValidateResponse {
  validation: ValidationResult;
  signature_valid?: boolean;
  signature_reason_vi?: string;
}

export interface TokenEvent {
  type: "ready" | "token_event";
  readers?: string[];
  action?: "inserted" | "removed";
  reader?: string;
  atr?: string;
}
