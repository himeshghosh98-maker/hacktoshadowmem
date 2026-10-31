"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Radio,
  Cpu,
  BarChart3,
  ShieldAlert,
  Terminal,
  ShieldCheck,
} from "lucide-react";

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

const navItems: NavItem[] = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Live Map", href: "/live-map", icon: Radio },
  { name: "Process Table", href: "/process-table", icon: Cpu },
  { name: "Analytics", href: "/analytics", icon: BarChart3 },
  { name: "Alerts", href: "/alerts", icon: ShieldAlert },
  { name: "Activity Log", href: "/kernel-log", icon: Terminal },
];

export function Sidebar() {
  const pathname = usePathname();
  const [lastScanTime, setLastScanTime] = useState<string>("none");

  useEffect(() => {
    const handleScan = (e: Event) => {
      const customEvent = e as CustomEvent<{ timestamp?: number }>;
      if (customEvent.detail?.timestamp) {
        setLastScanTime(
          new Date(customEvent.detail.timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          })
        );
      }
    };
    window.addEventListener("shadowmem:scan", handleScan);
    return () => window.removeEventListener("shadowmem:scan", handleScan);
  }, []);

  return (
    <aside className="w-64 h-screen bg-card border-r border-border flex flex-col shrink-0 select-none z-30">
      {/* Brand & Logo Header */}
      <div className="h-16 px-5 flex items-center gap-3 border-b border-border">
        <div className="w-9 h-9 rounded-lg bg-lime/10 border border-lime/30 flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-lime" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-base tracking-tight text-textBright font-sans">
              ShadowMem
            </span>
            <span className="px-1.5 py-0.5 text-xs font-mono font-bold bg-lime/10 text-lime rounded border border-lime/30">
              SOC
            </span>
          </div>
          <p className="text-xs text-textDim tracking-tight">
            Volatile Memory Forensics
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-2 pb-2 text-xs font-mono font-semibold uppercase tracking-wider text-textDim">
          Forensics Navigation
        </div>
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group relative flex items-center gap-3 px-3 py-2.5 rounded-md text-xs font-medium transition-colors ${
                isActive
                  ? "bg-lime/10 text-lime border border-lime/30 font-semibold"
                  : "text-textFog hover:text-textBright hover:bg-raise border border-transparent"
              }`}
            >
              {isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-lime rounded-r" />
              )}
              <Icon
                className={`w-4 h-4 transition-colors ${
                  isActive ? "text-lime" : "text-textDim group-hover:text-textBright"
                }`}
              />
              <span className="flex-1 font-sans">{item.name}</span>

              {item.badge && (
                <span className="px-1.5 py-0.5 rounded text-xs font-mono font-semibold bg-threat-malicious/10 text-threat-malicious border border-threat-malicious/30">
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Engine Status Box */}
      <div className="px-3 py-3">
        <div className="p-3 rounded-lg bg-background border border-border space-y-2">
          <div className="text-xs font-mono font-semibold uppercase tracking-wider text-textDim">
            Forensic Engine
          </div>
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-textDim">Traversal</span>
            <span className="text-textBright font-medium">VirtualQueryEx</span>
          </div>
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-textDim">Classifier</span>
            <span className="text-textBright font-medium">Random Forest</span>
          </div>
          <div className="pt-2 border-t border-border flex items-center justify-between text-xs font-mono text-textDim">
            <span>Last Scan</span>
            <span className="text-lime font-bold">{lastScanTime}</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
