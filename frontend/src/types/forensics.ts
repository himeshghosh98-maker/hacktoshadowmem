export type ProcessStatus =
  | "Malicious (Injected)"
  | "Suspicious"
  | "Legitimate JIT Engine"
  | "Clean (Uninfected)";

export interface ProcessClassification {
  id: string;
  name: string;
  mechanism?: string;
  detection_signature?: string;
  forensic_indicator?: string;
  remediation?: string;
  short_description?: string;
  typical_indicators?: string;
  display_name?: string;
  mitre_id?: string;
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
  is_isolated?: boolean;
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
  tag: "KERNEL" | "SYS" | "ML" | "MONITOR" | "VAD" | "TERMINAL" | "ISOLATE";
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
