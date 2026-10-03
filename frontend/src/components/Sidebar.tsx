"use client";

import React from "react";
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
  UserCheck,
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
  { name: "Kernel Log", href: "/kernel-log", icon: Terminal },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 h-screen bg-card border-r border-border flex flex-col shrink-0 select-none z-30">
      {/* Brand & Logo Header */}
      <div className="h-16 px-5 flex items-center gap-3 border-b border-border/80">
        <div className="w-9 h-9 rounded-lg bg-lime/10 border border-lime/30 flex items-center justify-center shadow-[0_2px_8px_rgba(232,121,60,0.2)]">
          <ShieldCheck className="w-5 h-5 text-lime" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-base tracking-tight text-textBright font-sans">
              ShadowMem
            </span>
            <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-lime/20 text-lime rounded border border-lime/30 tracking-wider">
              SOC
            </span>
          </div>
          <p className="text-[11px] font-medium text-textDim tracking-tight">
            Volatile Memory Forensics
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-2 pb-2 text-[10px] font-mono font-semibold uppercase tracking-wider text-textDim">
          Forensics Navigation
        </div>
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group relative flex items-center gap-3 px-3 py-2.5 rounded-md text-[13px] font-medium transition-all duration-150 ${
                isActive
                  ? "bg-lime/10 text-lime border border-lime/30 shadow-xs font-semibold"
                  : "text-textFog hover:text-textBright hover:bg-raise border border-transparent"
              }`}
            >
              {/* Active left indicator pill */}
              {isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-lime rounded-r shadow-[0_0_8px_rgba(232,121,60,0.4)]" />
              )}
              <Icon
                className={`w-4 h-4 transition-colors ${
                  isActive ? "text-lime" : "text-textDim group-hover:text-textBright"
                }`}
              />
              <span className="flex-1 font-sans">{item.name}</span>

              {item.badge && (
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold bg-threat-malicious/20 text-threat-malicious border border-threat-malicious/40">
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* System Telemetry Pill */}
      <div className="px-3 py-2">
        <div className="p-3 rounded-lg bg-card border border-border space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-textDim font-medium">Filter Driver</span>
            <span className="flex items-center gap-1.5 text-lime font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-lime animate-pulse" />
              Active
            </span>
          </div>
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-textDim font-medium">VAD Monitor</span>
            <span className="text-textBright font-semibold">Ring-0 Hook</span>
          </div>
          <div className="pt-1.5 border-t border-border/60 flex items-center justify-between text-[11px] font-mono text-textDim">
            <span>Model: 7-Feature ML</span>
            <span className="text-lime font-bold">Ready</span>
          </div>
        </div>
      </div>

      {/* User / Analyst Profile Footer */}
      <div className="p-3 border-t border-border bg-[#F8F5F0]">
        <div className="flex items-center gap-3 px-2 py-1.5 rounded-md hover:bg-raise/60 transition-colors">
          <div className="w-8 h-8 rounded-full bg-[#EBE5DF] flex items-center justify-center border border-borderMuted">
            <UserCheck className="w-4 h-4 text-lime" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-xs font-bold text-textBright truncate font-sans">
              SOC Tier-3 Analyst
            </div>
            <div className="text-[10px] font-mono text-textDim truncate font-medium">
              ID: ANALYST-092
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
