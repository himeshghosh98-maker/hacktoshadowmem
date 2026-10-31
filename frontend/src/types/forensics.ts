export type ProcessStatus =
  | "Malicious (Injected)"
  | "Suspicious"
  | "Legitimate JIT Engine"
  | "Clean";

export interface ProcessClassification {
  id?: string;
  name?: string;
  mechanism?: string;
  detection_signature?: string;
  forensic_indicator?: string;
  remediation?: string;
  short_description?: string;
  typical_indicators?: string;
  display_name?: string;
  mitre_id?: string;
  recommended_response?: string;
}

export interface UnbackedRegion {
  base_address: number | string;
  size: number;
  protection: string;
  allocation_protect?: string;
}

export interface ProcessEntry {
  pid: number;
  name: string;
  exe: string;
  rwx_count: number;
  unbacked_exec_count: number;
  total_rwx_bytes: number;
  allocated_kb: number;
  num_threads: number;
  thread_unbacked_start: number;
  vad_protection_anomaly: number;
  threat_score: number;
  status: ProcessStatus;
  jit_engine: boolean;
  model_used: boolean;
  classification: ProcessClassification | null;
  unbacked_regions?: UnbackedRegion[];
  is_isolated?: boolean;
  attribution?: Record<string, number>;
  attribution_reasons?: string[];
  entropy?: number;
}

export interface ScanSummary {
  total_scanned: number;
  anomalies_detected: number;
  malicious_count: number;
  suspicious_count: number;
  jit_engine_count: number;
  clean_count: number;
  system_posture: "Threat Detected" | "Protected";
  model_loaded: boolean;
}

export interface ScanResponse {
  summary: ScanSummary;
  processes: ProcessEntry[];
}

export interface AlertItem {
  id: string;
  title: string;
  message: string;
  severity: "critical" | "warn" | "ok" | "info";
  timestamp: string;
  technique?: string | null;
  pid?: number;
}

export interface KernelLogItem {
  id: string;
  tag: "KERNEL" | "SYS" | "ML" | "MONITOR" | "VAD" | "TERMINAL" | "ISOLATE" | "SCAN";
  msg: string;
  level: "info" | "success" | "warning" | "danger" | "purple";
  timestamp: string;
}

export interface ThreatCategoryStat {
  name: string;
  mitreId: string;
  count: number;
  percentage: number;
  severity: "critical" | "high" | "medium";
}

export interface ScanHistoryRecord {
  scanIndex: number;
  timestamp: string;
  timeLabel: string;
  durationMs: number;
  totalScanned: number;
  malicious: number;
  suspicious: number;
  threats: number;
}

export interface HexDumpLine {
  offset: string;
  hex_bytes: string;
  ascii_chars: string;
}

export interface MemoryDumpResponse {
  pid: number;
  name: string;
  base_address: string;
  size: number;
  protection: string;
  entropy: number;
  is_shellcode_suspect: boolean;
  hex_lines: HexDumpLine[];
  disassembly_hints: string[];
}
