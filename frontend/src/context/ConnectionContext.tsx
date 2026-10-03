"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";
import { connectAlertsWebSocket } from "@/lib/api";

export interface ConnectionContextType {
  isConnected: boolean;
  isReconnected: boolean;
  lastConnectedTime: number | null;
  reportSuccess: () => void;
  reportFailure: (err?: unknown) => void;
}

const ConnectionContext = createContext<ConnectionContextType>({
  isConnected: true,
  isReconnected: false,
  lastConnectedTime: null,
  reportSuccess: () => {},
  reportFailure: () => {},
});

export function ConnectionProvider({ children }: { children: React.ReactNode }) {
  const [isConnected, setIsConnected] = useState<boolean>(true);
  const [isReconnected, setIsReconnected] = useState<boolean>(false);
  const [lastConnectedTime, setLastConnectedTime] = useState<number | null>(null);

  const isConnectedRef = useRef(isConnected);
  isConnectedRef.current = isConnected;

  const reconnectedTimerRef = useRef<NodeJS.Timeout | null>(null);

  const reportSuccess = useCallback(() => {
    const wasDisconnected = !isConnectedRef.current;
    setIsConnected(true);
    setLastConnectedTime(Date.now());

    if (wasDisconnected) {
      setIsReconnected(true);
      if (reconnectedTimerRef.current) clearTimeout(reconnectedTimerRef.current);
      reconnectedTimerRef.current = setTimeout(() => {
        setIsReconnected(false);
      }, 2500);
    }
  }, []);

  const reportFailure = useCallback((_err?: unknown) => {
    void _err;
    if (isConnectedRef.current) {
      setIsConnected(false);
      setIsReconnected(false);
    }
  }, []);

  // Listen to custom connection events dispatched from api.ts
  useEffect(() => {
    const handleEvent = (e: Event) => {
      const customEvent = e as CustomEvent<{ success: boolean; error?: unknown }>;
      if (customEvent.detail?.success) {
        reportSuccess();
      } else {
        reportFailure(customEvent.detail?.error);
      }
    };

    window.addEventListener("shadowmem:connection", handleEvent);
    return () => {
      window.removeEventListener("shadowmem:connection", handleEvent);
    };
  }, [reportSuccess, reportFailure]);

  // Periodic heartbeat / connectivity probe
  useEffect(() => {
    let unmounted = false;

    const probe = async () => {
      if (unmounted) return;
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);

        const res = await fetch("/api/audit", {
          method: "GET",
          headers: { Accept: "application/json" },
          cache: "no-store",
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (res.ok) {
          reportSuccess();
        } else {
          reportFailure(new Error(`Probe HTTP ${res.status}`));
        }
      } catch (err) {
        reportFailure(err);
      }
    };

    // Initial check
    probe();

    // Check interval: every 3 seconds
    const interval = setInterval(probe, 3000);

    // Also attach to WebSocket connection status
    const disconnectWs = connectAlertsWebSocket(
      () => {},
      (connected) => {
        if (connected) {
          reportSuccess();
        } else {
          // If WS drops, verify immediately with a probe
          probe();
        }
      }
    );

    return () => {
      unmounted = true;
      clearInterval(interval);
      disconnectWs();
      if (reconnectedTimerRef.current) clearTimeout(reconnectedTimerRef.current);
    };
  }, [reportSuccess, reportFailure]);

  return (
    <ConnectionContext.Provider
      value={{
        isConnected,
        isReconnected,
        lastConnectedTime,
        reportSuccess,
        reportFailure,
      }}
    >
      {children}
    </ConnectionContext.Provider>
  );
}

export function useConnection() {
  return useContext(ConnectionContext);
}
