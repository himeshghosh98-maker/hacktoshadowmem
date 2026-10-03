"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Radio,
  Play,
  Eye,
  Loader2,
  Crosshair,
} from "lucide-react";
import { ProcessEntry } from "@/types/forensics";
import { fetchScan, isolateProcess, resumeProcess, fetchAudit } from "@/lib/api";
import { ProcessDossierModal } from "@/components/dashboard/ProcessDossierModal";

type MapFilter = "ALL" | "THREAT" | "JIT" | "CLEAN";

interface MapNode {
  process: ProcessEntry;
  angle: number;
  ringFrac: number;
  x: number;
  y: number;
  radius: number;
  color: string;
}

export default function LiveMapPage() {
  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [isolatedPids, setIsolatedPids] = useState<Set<number>>(new Set());
  const [hasScanned, setHasScanned] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [activeFilter, setActiveFilter] = useState<MapFilter>("ALL");
  const [hoveredNode, setHoveredNode] = useState<MapNode | null>(null);
  const [selectedProcess, setSelectedProcess] = useState<ProcessEntry | null>(null);
  const [radarSweepEnabled, setRadarSweepEnabled] = useState(true);

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationFrameRef = useRef<number | null>(null);
  const sweepAngleRef = useRef(0);
  const nodesRef = useRef<MapNode[]>([]);

  // Initial audit sync
  useEffect(() => {
    fetchAudit()
      .then((res) => {
        if (res.actions) {
          const iso = new Set<number>();
          res.actions.forEach((a) => {
            if (a.success) {
              if (a.action === "isolate") iso.add(a.pid);
              if (a.action === "resume") iso.delete(a.pid);
            }
          });
          setIsolatedPids(iso);
        }
      })
      .catch(() => {});
  }, []);

  // Fetch / Scan trigger
  const runScan = async () => {
    setIsScanning(true);
    try {
      const data = await fetchScan();
      const enriched = (data.processes || []).map((p) => ({
        ...p,
        is_isolated: isolatedPids.has(p.pid),
      }));
      setProcesses(enriched);
      setHasScanned(true);
    } catch (err) {
      console.error("Scan error:", err);
    } finally {
      setIsScanning(false);
    }
  };

  // Node Color Mapper
  const getNodeColor = useCallback((status: ProcessEntry["status"]) => {
    switch (status) {
      case "Malicious (Injected)":
        return "#EF4444"; // Red
      case "Suspicious":
        return "#F59E0B"; // Amber
      case "Legitimate JIT Engine":
        return "#3B82F6"; // Blue
      default:
        return "#10B981"; // Emerald
    }
  }, []);

  // Build Polar Layout from processes
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const filtered = processes.filter((p) => {
      if (activeFilter === "THREAT") {
        return p.status === "Malicious (Injected)" || p.status === "Suspicious";
      }
      if (activeFilter === "JIT") return p.jit_engine;
      if (activeFilter === "CLEAN") return p.status === "Clean (Uninfected)";
      return true;
    });

    const rect = canvas.getBoundingClientRect();
    const cssW = rect.width || 800;
    const cssH = rect.height || 550;
    const cx = cssW / 2;
    const cy = cssH / 2;
    const maxR = Math.min(cssW, cssH) / 2 - 35;

    const ringRadii = {
      malicious: 0.28,
      suspicious: 0.48,
      jit: 0.70,
      clean: 0.92,
    };

    const newNodes: MapNode[] = filtered.map((p, idx) => {
      let ringFrac = ringRadii.clean;
      if (p.status === "Malicious (Injected)") ringFrac = ringRadii.malicious;
      else if (p.status === "Suspicious") ringFrac = ringRadii.suspicious;
      else if (p.jit_engine) ringFrac = ringRadii.jit;

      // Golden angle distribution for natural organic scattering around the ring
      const angle = ((p.pid * 137.5 + idx * 25) % 360) * (Math.PI / 180);
      const r = maxR * (ringFrac + ((idx % 5) - 2) * 0.025);
      const x = cx + Math.cos(angle) * r;
      const y = cy + Math.sin(angle) * r;

      const isThreat =
        p.status === "Malicious (Injected)" || p.status === "Suspicious";

      return {
        process: p,
        angle,
        ringFrac,
        x,
        y,
        radius: isThreat ? 6.5 : p.jit_engine ? 5 : 4,
        color: getNodeColor(p.status),
      };
    });

    nodesRef.current = newNodes;
  }, [processes, activeFilter, getNodeColor]);

  // Main Canvas Render Loop (Concentric rings + radar beam + process nodes)
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let isMounted = true;

    const render = () => {
      if (!isMounted) return;

      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      const cssW = rect.width;
      const cssH = rect.height;

      if (canvas.width !== cssW * dpr || canvas.height !== cssH * dpr) {
        canvas.width = cssW * dpr;
        canvas.height = cssH * dpr;
      }

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, cssW, cssH);

      const cx = cssW / 2;
      const cy = cssH / 2;
      const maxR = Math.min(cssW, cssH) / 2 - 35;

      // 1. Background Grid Dots
      ctx.fillStyle = "rgba(138, 133, 128, 0.25)";
      const gridSize = 28;
      for (let x = gridSize / 2; x < cssW; x += gridSize) {
        for (let y = gridSize / 2; y < cssH; y += gridSize) {
          ctx.fillRect(x, y, 1.5, 1.5);
        }
      }

      // 2. Concentric Forensic Rings
      const rings = [
        { r: 0.28, label: "RING 0: IN-MEMORY THREATS" },
        { r: 0.48, label: "RING 1: SUSPICIOUS VAD FLIPS" },
        { r: 0.70, label: "RING 2: JIT RUNTIMES" },
        { r: 0.92, label: "RING 3: BENIGN USER-MODE" },
      ];

      rings.forEach((ring) => {
        const radius = maxR * ring.r;
        ctx.strokeStyle = "rgba(220, 214, 206, 0.95)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.stroke();

        // Ring label
        ctx.fillStyle = "rgba(138, 133, 128, 0.85)";
        ctx.font = "9px monospace";
        ctx.textAlign = "center";
        ctx.fillText(ring.label, cx, cy - radius - 3);
      });

      // 3. Coordinate Crosshairs
      ctx.strokeStyle = "rgba(220, 214, 206, 0.8)";
      ctx.beginPath();
      ctx.moveTo(cx, cy - maxR * 0.96);
      ctx.lineTo(cx, cy + maxR * 0.96);
      ctx.moveTo(cx - maxR * 0.96, cy);
      ctx.lineTo(cx + maxR * 0.96, cy);
      ctx.stroke();

      // 4. Radar Sweep Beam (if enabled)
      if (radarSweepEnabled) {
        sweepAngleRef.current = (sweepAngleRef.current + 0.015) % (Math.PI * 2);
        const sweepAngle = sweepAngleRef.current;

        ctx.save();
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, maxR * 0.95, sweepAngle - 0.35, sweepAngle);
        ctx.lineTo(cx, cy);

        const sweepGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR * 0.95);
        sweepGrad.addColorStop(0, "rgba(232, 121, 60, 0.0)");
        sweepGrad.addColorStop(1, "rgba(232, 121, 60, 0.12)");
        ctx.fillStyle = sweepGrad;
        ctx.fill();

        ctx.strokeStyle = "rgba(232, 121, 60, 0.4)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(
          cx + Math.cos(sweepAngle) * maxR * 0.95,
          cy + Math.sin(sweepAngle) * maxR * 0.95
        );
        ctx.stroke();
        ctx.restore();
      }

      // 5. Central Ring-0 Kernel Anchor
      ctx.fillStyle = "#E8793C";
      ctx.beginPath();
      ctx.arc(cx, cy, 5, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "rgba(232, 121, 60, 0.2)";
      ctx.beginPath();
      ctx.arc(cx, cy, 12, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = "#1A1A1A";
      ctx.font = "bold 9px monospace";
      ctx.textAlign = "left";
      ctx.fillText("RING-0 KERNEL", cx + 14, cy + 3);

      // 6. Draw Process Nodes
      const nodes = nodesRef.current;
      nodes.forEach((n) => {
        const isHovered = hoveredNode?.process.pid === n.process.pid;

        // Faint vector link from kernel
        ctx.strokeStyle = isHovered
          ? "rgba(232, 121, 60, 0.5)"
          : "rgba(220, 214, 206, 0.6)";
        ctx.lineWidth = isHovered ? 1.5 : 0.8;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(n.x, n.y);
        ctx.stroke();

        // Node circle
        ctx.fillStyle = n.color;
        ctx.beginPath();
        ctx.arc(n.x, n.y, isHovered ? n.radius + 3 : n.radius, 0, Math.PI * 2);
        ctx.fill();

        // Glow ring around anomalies or hovered
        if (
          isHovered ||
          n.process.status === "Malicious (Injected)" ||
          n.process.status === "Suspicious"
        ) {
          ctx.strokeStyle = isHovered ? "#E8793C" : n.color;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius + 4, 0, Math.PI * 2);
          ctx.stroke();
        }

        // Show label if threat or hovered
        if (isHovered || n.process.threat_score >= 50) {
          ctx.fillStyle = "#1A1A1A";
          ctx.font = "10px monospace";
          ctx.textAlign = "center";
          ctx.fillText(n.process.name, n.x, n.y - (n.radius + 7));
        }
      });

      ctx.restore();
      animationFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      isMounted = false;
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, [radarSweepEnabled, hoveredNode]);

  // Handle Mouse Move for Node Hover Targeting
  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    let closest: MapNode | null = null;
    let minDistance = 16; // hover threshold in px

    for (const node of nodesRef.current) {
      const dist = Math.hypot(node.x - mouseX, node.y - mouseY);
      if (dist < minDistance) {
        minDistance = dist;
        closest = node;
      }
    }

    setHoveredNode(closest);
  };

  const handleMouseLeave = () => {
    setHoveredNode(null);
  };

  const handleCanvasClick = () => {
    if (hoveredNode) {
      setSelectedProcess(hoveredNode.process);
    }
  };

  // Process Isolation toggle
  const handleToggleIsolate = async (pid: number, isCurrentlyIsolated: boolean) => {
    try {
      if (isCurrentlyIsolated) {
        const res = await resumeProcess(pid);
        if (res.success) {
          setIsolatedPids((prev) => {
            const next = new Set(prev);
            next.delete(pid);
            return next;
          });
          setProcesses((prev) =>
            prev.map((p) => (p.pid === pid ? { ...p, is_isolated: false } : p))
          );
          if (selectedProcess?.pid === pid) {
            setSelectedProcess((prev) =>
              prev ? { ...prev, is_isolated: false } : null
            );
          }
        }
      } else {
        const res = await isolateProcess(pid, "Suspended via Live Scope Map");
        if (res.success) {
          setIsolatedPids((prev) => {
            const next = new Set(prev);
            next.add(pid);
            return next;
          });
          setProcesses((prev) =>
            prev.map((p) => (p.pid === pid ? { ...p, is_isolated: true } : p))
          );
          if (selectedProcess?.pid === pid) {
            setSelectedProcess((prev) =>
              prev ? { ...prev, is_isolated: true } : null
            );
          }
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  const threatCount = processes.filter(
    (p) => p.status === "Malicious (Injected)" || p.status === "Suspicious"
  ).length;
  const jitCount = processes.filter((p) => p.jit_engine).length;
  const cleanCount = processes.filter((p) => p.status === "Clean (Uninfected)").length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg bg-card border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <Radio className="w-5 h-5 text-lime" />
            <h2 className="text-2xl sm:text-[26px] font-bold tracking-tight text-textBright">
              Live Process & Memory Scope Map
            </h2>
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider bg-lime/15 text-lime border border-lime/30">
              POLAR RADAR SCOPE
            </span>
          </div>
          <p className="text-sm font-normal text-textFog mt-1.5 font-sans leading-relaxed">
            Spatial 2D projection of user-mode processes categorized across Ring-0 memory defense tiers.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          {/* Radar Sweep Toggle */}
          <button
            onClick={() => setRadarSweepEnabled(!radarSweepEnabled)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-medium border transition-all ${
              radarSweepEnabled
                ? "bg-lime/10 text-lime border-lime/30"
                : "bg-raise text-textDim border-border"
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>RADAR SWEEP {radarSweepEnabled ? "ON" : "OFF"}</span>
          </button>

          {/* Trigger Scan Button */}
          <button
            onClick={runScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-4 py-2 rounded-md font-sans text-xs font-semibold bg-lime hover:bg-lime-hover text-white transition-all shadow-[0_2px_8px_rgba(232,121,60,0.3)] disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white" />
                <span>Scanning VADs...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-white text-white" />
                <span>{hasScanned ? "Re-scan Scope" : "Run Forensics Scan"}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Main Map Workspace Card */}
      <div className="p-5 rounded-lg bg-card border border-border shadow-sm space-y-4">
        {/* Scope Toolbar & Filters */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 bg-[#F5F1EB] p-1 rounded-md border border-border">
            {(
              [
                { key: "ALL", label: "ALL", count: processes.length },
                { key: "THREAT", label: "THREATS", count: threatCount },
                { key: "JIT", label: "JIT RUNTIMES", count: jitCount },
                { key: "CLEAN", label: "CLEAN", count: cleanCount },
              ] as const
            ).map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveFilter(tab.key)}
                className={`px-3 py-1 rounded text-xs font-mono transition-all flex items-center gap-1.5 ${
                  activeFilter === tab.key
                    ? "bg-white text-lime border border-border font-bold shadow-xs"
                    : "text-textFog font-medium hover:text-textBright"
                }`}
              >
                <span>{tab.label}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-semibold ${
                    activeFilter === tab.key
                      ? "bg-lime/20 text-lime"
                      : "bg-border text-textDim"
                  }`}
                >
                  {tab.count}
                </span>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-textFog font-medium">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-threat-malicious" />
              <span>Malicious</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-threat-suspicious" />
              <span>Suspicious</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-threat-jit" />
              <span>JIT</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-threat-clean" />
              <span>Clean</span>
            </span>
          </div>
        </div>

        {/* Canvas Display Viewport */}
        {!hasScanned && processes.length === 0 ? (
          <div className="h-[520px] rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-4 p-8 text-center">
            <div className="w-16 h-16 rounded-full bg-raise/70 border border-border flex items-center justify-center">
              <Radio className="w-8 h-8 text-textDim animate-pulse" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-semibold text-textBright">
                Memory Scope Standby
              </h3>
              <p className="text-xs font-mono text-textDim max-w-md">
                Click <strong>Run Forensics Scan</strong> to query active process address spaces via Win32 VirtualQueryEx and populate the radar map.
              </p>
            </div>
            <button
              onClick={runScan}
              disabled={isScanning}
              className="mt-2 flex items-center gap-2 px-4 py-2 rounded-md font-sans text-xs font-semibold bg-lime text-white hover:bg-lime-hover shadow-[0_2px_8px_rgba(232,121,60,0.3)] transition-colors"
            >
              <Play className="w-3.5 h-3.5 fill-white text-white" />
              <span>Initialize Memory Scan</span>
            </button>
          </div>
        ) : (
          <div className="relative rounded-lg overflow-hidden border border-border/80 bg-[#FAF7F2]">
            {/* HTML5 Canvas */}
            <canvas
              ref={canvasRef}
              onMouseMove={handleMouseMove}
              onMouseLeave={handleMouseLeave}
              onClick={handleCanvasClick}
              className="w-full h-[520px] block cursor-crosshair"
            />

            {/* Floating HUD Tooltip when hovering over a node */}
            {hoveredNode && (
              <div
                className="absolute z-20 pointer-events-none p-3 rounded-lg bg-card/95 border border-lime/60 shadow-[0_4px_20px_rgba(0,0,0,0.12)] backdrop-blur-md space-y-1.5 font-mono text-xs w-64"
                style={{
                  left: Math.min(hoveredNode.x + 15, (canvasRef.current?.clientWidth || 800) - 270),
                  top: Math.min(hoveredNode.y + 15, (canvasRef.current?.clientHeight || 520) - 130),
                }}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-textBright truncate">
                    {hoveredNode.process.name}
                  </span>
                  <span className="text-[10px] text-textDim">
                    PID {hoveredNode.process.pid}
                  </span>
                </div>

                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-textDim">Threat Score:</span>
                  <span
                    className={`font-bold ${
                      hoveredNode.process.threat_score >= 60
                        ? "text-threat-malicious"
                        : hoveredNode.process.threat_score >= 30
                        ? "text-threat-suspicious"
                        : "text-threat-clean"
                    }`}
                  >
                    {hoveredNode.process.threat_score.toFixed(1)}%
                  </span>
                </div>

                <div className="text-[10px] text-textFog pt-1 border-t border-border/60 space-y-0.5">
                  <div>RWX Pages: {hoveredNode.process.rwx_count}</div>
                  <div>Unbacked Exec: {hoveredNode.process.unbacked_exec_count}</div>
                  <div>Total RWX: {hoveredNode.process.allocated_kb} KB</div>
                </div>

                <div className="text-[9px] text-lime pt-0.5 font-semibold">
                  Click to open Forensic Dossier & Isolation
                </div>
              </div>
            )}
          </div>
        )}

        {/* Live Inspector Bar */}
        <div className="p-3.5 rounded-lg bg-[#FAF7F2] border border-border flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <Eye className="w-4 h-4 text-lime" />
            <span className="text-textBright font-semibold">Active Coordinates:</span>
            {hoveredNode ? (
              <span className="text-lime font-mono">
                {hoveredNode.process.name} (PID {hoveredNode.process.pid}) — θ:{" "}
                {((hoveredNode.angle * 180) / Math.PI).toFixed(1)}° | r:{" "}
                {hoveredNode.ringFrac.toFixed(2)}
              </span>
            ) : (
              <span className="text-textDim">
                Move cursor over radar canvas to target volatile process allocations
              </span>
            )}
          </div>

          <div className="text-textDim text-[11px] self-end md:self-auto">
            {nodesRef.current.length} processes projected in scope
          </div>
        </div>
      </div>

      {/* Forensic Dossier Modal */}
      {selectedProcess && (
        <ProcessDossierModal
          process={selectedProcess}
          onClose={() => setSelectedProcess(null)}
          onToggleIsolate={handleToggleIsolate}
        />
      )}
    </div>
  );
}
