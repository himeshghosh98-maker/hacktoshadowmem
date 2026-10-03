"use client";

import React, { createContext, useContext, useState, useCallback, ReactNode } from "react";
import { AlertItem } from "@/types/forensics";

interface NotificationsContextType {
  alerts: AlertItem[];
  addAlert: (alert: AlertItem) => void;
  clearAlerts: () => void;
  markAllRead: () => void;
  unreadCount: number;
}

const NotificationsContext = createContext<NotificationsContextType | null>(null);

export function NotificationsProvider({ children }: { children: ReactNode }) {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [readAlertIds, setReadAlertIds] = useState<Set<string>>(new Set());

  const addAlert = useCallback((alert: AlertItem) => {
    setAlerts((prev) => [alert, ...prev.slice(0, 99)]);
  }, []);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
    setReadAlertIds(new Set());
  }, []);

  const markAllRead = useCallback(() => {
    setReadAlertIds(new Set(alerts.map((a) => a.id)));
  }, [alerts]);

  const unreadCount = alerts.filter((a) => !readAlertIds.has(a.id)).length;

  return (
    <NotificationsContext.Provider
      value={{
        alerts,
        addAlert,
        clearAlerts,
        markAllRead,
        unreadCount,
      }}
    >
      {children}
    </NotificationsContext.Provider>
  );
}

export function useNotifications() {
  const context = useContext(NotificationsContext);
  if (!context) {
    throw new Error("useNotifications must be used within a NotificationsProvider");
  }
  return context;
}