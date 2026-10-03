"use client";

import React, { useState, useEffect } from "react";
import { useConnection } from "@/context/ConnectionContext";

interface LastUpdatedProps {
  timestamp?: number | Date | null;
  staleThresholdSec?: number;
  className?: string;
}

export function LastUpdated({
  timestamp,
  staleThresholdSec = 30,
  className = "",
}: LastUpdatedProps) {
  const { isConnected } = useConnection();
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!timestamp) return;
    const interval = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => clearInterval(interval);
  }, [timestamp]);

  if (!timestamp) return null;

  const timeMs = timestamp instanceof Date ? timestamp.getTime() : timestamp;
  const diffSec = Math.max(0, Math.floor((now - timeMs) / 1000));
  const isStale = !isConnected || diffSec >= staleThresholdSec;

  let relativeText = "Updated just now";
  if (diffSec >= 5 && diffSec < 60) {
    relativeText = `Updated ${diffSec}s ago`;
  } else if (diffSec >= 60 && diffSec < 3600) {
    relativeText = `Updated ${Math.floor(diffSec / 60)}m ago`;
  } else if (diffSec >= 3600) {
    relativeText = `Updated ${Math.floor(diffSec / 3600)}h ago`;
  }

  return (
    <span
      className={`text-[10px] font-mono tracking-tight transition-colors ${
        isStale
          ? "text-threat-suspicious font-semibold"
          : "text-textDim font-normal"
      } ${className}`}
      title={
        !isConnected
          ? "Backend disconnected — data may be stale"
          : isStale
          ? `Data older than ${staleThresholdSec}s (may be stale)`
          : `Last synchronized at ${new Date(timeMs).toLocaleTimeString()}`
      }
    >
      {relativeText}
    </span>
  );
}

export default LastUpdated;
