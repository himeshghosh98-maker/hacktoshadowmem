import {
  ScanResponse,
  AlertItem,
} from "@/types/forensics";

export interface IsolateResponse {
  pid: number;
  name: string;
  action: "suspended" | "resumed";
  success: boolean;
  error?: string | null;
}

export interface AuditAction {
  pid: number;
  name: string;
  action: "isolate" | "resume";
  success: boolean;
  reason?: string | null;
  timestamp: string;
}

export interface AuditResponse {
  actions: AuditAction[];
}

export interface WebSocketAlertPayload {
  type: string;
  event_id?: string;
  timestamp?: string;
  severity?: "info" | "warn" | "critical" | "ok";
  message?: string;
  detection?: {
    is_malicious: boolean;
    confidence: number;
    classifier: string;
    technique: string | null;
  };
}

const getApiBaseUrl = (): string => {
  if (typeof window === "undefined") return "http://127.0.0.1:8000";
  // In development (port 3000), relative /api requests are proxied by next.config.mjs
  // In production (served from app.py on port 8000), relative /api requests hit app.py directly
  return "";
};

function notifyConnection(success: boolean, error?: unknown) {
  if (typeof window !== "undefined") {
    window.dispatchEvent(
      new CustomEvent("shadowmem:connection", { detail: { success, error } })
    );
  }
}

export interface SimulateAlertRequest {
  scenario?: string;
  severity: "critical" | "warn" | "info";
}

export interface SimulateAlertResponse {
  status: string;
  alert_id: string;
  scenario: string;
  severity: string;
}

export async function fetchScan(): Promise<ScanResponse> {
  const base = getApiBaseUrl();
  try {
    const res = await fetch(`${base}/api/v1/scan`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      let errorDetail = `Scan failed with status ${res.status}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) errorDetail = errJson.detail;
      } catch {
        // ignore json parse error
      }
      notifyConnection(false, new Error(errorDetail));
      throw new Error(errorDetail);
    }

    const data = (await res.json()) as ScanResponse;
    notifyConnection(true);
    if (typeof window !== "undefined") {
      window.dispatchEvent(
        new CustomEvent("shadowmem:scan", { detail: { timestamp: Date.now() } })
      );
    }
    return data;
  } catch (err) {
    notifyConnection(false, err);
    throw err;
  }
}

export async function isolateProcess(
  pid: number,
  reason: string = ""
): Promise<IsolateResponse> {
  const base = getApiBaseUrl();
  try {
    const res = await fetch(`${base}/api/v1/isolate/${pid}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ reason }),
    });

    const data = (await res.json()) as IsolateResponse;
    if (!res.ok && !data.error) {
      notifyConnection(false, new Error(`Isolation failed with HTTP ${res.status}`));
      throw new Error(`Isolation failed with HTTP ${res.status}`);
    }
    notifyConnection(true);
    return data;
  } catch (err) {
    notifyConnection(false, err);
    throw err;
  }
}

export async function resumeProcess(pid: number): Promise<IsolateResponse> {
  const base = getApiBaseUrl();
  try {
    const res = await fetch(`${base}/api/v1/resume/${pid}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
    });

    const data = (await res.json()) as IsolateResponse;
    if (!res.ok && !data.error) {
      notifyConnection(false, new Error(`Resume failed with HTTP ${res.status}`));
      throw new Error(`Resume failed with HTTP ${res.status}`);
    }
    notifyConnection(true);
    return data;
  } catch (err) {
    notifyConnection(false, err);
    throw err;
  }
}

export async function fetchAudit(): Promise<AuditResponse> {
  const base = getApiBaseUrl();
  try {
    const res = await fetch(`${base}/api/v1/audit`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      notifyConnection(false, new Error(`Failed to load audit trail: HTTP ${res.status}`));
      throw new Error(`Failed to load audit trail: HTTP ${res.status}`);
    }

    const data = (await res.json()) as AuditResponse;
    notifyConnection(true);
    return data;
  } catch (err) {
    notifyConnection(false, err);
    throw err;
  }
}

export async function simulateAlert(
  scenario: string = "cobalt_strike_reflective_injection",
  severity: "critical" | "warn" | "info" = "critical"
): Promise<SimulateAlertResponse> {
  const base = getApiBaseUrl();
  try {
    const res = await fetch(`${base}/api/v1/simulate/alert`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ scenario, severity }),
    });

    if (!res.ok) {
      let errorDetail = `Simulation failed with HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) errorDetail = errJson.detail;
      } catch {
        // ignore
      }
      throw new Error(errorDetail);
    }

    return (await res.json()) as SimulateAlertResponse;
  } catch (err) {
    console.error("Simulation error:", err);
    throw err;
  }
}

export function connectAlertsWebSocket(
  onAlert: (alert: AlertItem) => void,
  onStatusChange?: (connected: boolean) => void
): () => void {
  if (typeof window === "undefined") return () => {};

  let ws: WebSocket | null = null;
  let isUnmounted = false;
  let reconnectTimer: NodeJS.Timeout | null = null;
  let reconnectDelay = 1000;

  const connect = () => {
    if (isUnmounted) return;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      // If dev server is on port 3000, connect to backend at 127.0.0.1:8000
      // If served from 8000, connect to current host
      const host =
        window.location.port === "3000"
          ? "127.0.0.1:8000"
          : window.location.host || "127.0.0.1:8000";

      const wsUrl = `${protocol}//${host}/api/v1/ws/alerts`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        if (isUnmounted) return;
        reconnectDelay = 1000;
        if (onStatusChange) onStatusChange(true);
      };

      ws.onmessage = (event) => {
        if (isUnmounted) return;
        try {
          const payload = JSON.parse(event.data) as WebSocketAlertPayload;
          // Only alert frames belong in the alerts feed. memory_map frames
          // (live-map payload) and other frame types must not surface here.
          if (payload.type && payload.type !== "alert") return;
          const isCritical = payload.severity === "critical" || payload.detection?.is_malicious;
          const alertItem: AlertItem = {
            id: payload.event_id || `ws-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
            title: payload.detection?.technique
              ? `Threat Alert: ${payload.detection.technique}`
              : isCritical
              ? "Critical Memory Detection"
              : "System Telemetry Event",
            message: payload.message || "Forensic telemetry alert received over WebSocket.",
            severity: isCritical ? "critical" : payload.severity === "warn" ? "warn" : "info",
            timestamp: payload.timestamp
              ? new Date(payload.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })
              : new Date().toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                }),
            technique: payload.detection?.technique || null,
          };
          onAlert(alertItem);
        } catch {
          // ignore non-json messages
        }
      };

      ws.onclose = () => {
        if (onStatusChange) onStatusChange(false);
        if (!isUnmounted) {
          reconnectTimer = setTimeout(() => {
            reconnectDelay = Math.min(reconnectDelay * 1.5, 10000);
            connect();
          }, reconnectDelay);
        }
      };

      ws.onerror = () => {
        if (ws) {
          try {
            ws.close();
          } catch {
            // ignore
          }
        }
      };
    } catch {
      if (onStatusChange) onStatusChange(false);
    }
  };

  connect();

  return () => {
    isUnmounted = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (ws) {
      try {
        ws.close();
      } catch {
        // ignore
      }
    }
  };
}
