"use client";

import React, { createContext, useContext, useState, useEffect } from "react";

export type Density = "detailed" | "compact";

interface DensityContextType {
  density: Density;
  setDensity: (density: Density) => void;
  isCompact: boolean;
}

const DensityContext = createContext<DensityContextType>({
  density: "detailed",
  setDensity: () => {},
  isCompact: false,
});

const STORAGE_KEY = "shadowmem_density";

export function DensityProvider({ children }: { children: React.ReactNode }) {
  const [density, setDensityState] = useState<Density>("detailed");

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === "compact" || stored === "detailed") {
        setDensityState(stored);
      }
    } catch {
      // Ignore localStorage access errors
    }
  }, []);

  const setDensity = (val: Density) => {
    setDensityState(val);
    try {
      localStorage.setItem(STORAGE_KEY, val);
    } catch {
      // Ignore localStorage access errors
    }
  };

  return (
    <DensityContext.Provider
      value={{
        density,
        setDensity,
        isCompact: density === "compact",
      }}
    >
      {children}
    </DensityContext.Provider>
  );
}

export function useDensity() {
  return useContext(DensityContext);
}
