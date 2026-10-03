import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#FAF7F2",
        card: "#FFFFFF",
        raise: "#F5F1EB",
        border: "#EBE5DF",
        borderMuted: "#F0EBE5",
        lime: {
          DEFAULT: "#E8793C",
          hover: "#D6692D",
          dim: "rgba(232, 121, 60, 0.10)",
          glow: "rgba(232, 121, 60, 0.25)",
        },
        textBright: "#141414",
        textFog: "#48433E",
        textDim: "#6B645C",
        threat: {
          malicious: "#D6453D",
          suspicious: "#E68A2E",
          jit: "#4A7BB0",
          clean: "#3D8B60",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
