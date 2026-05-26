import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./hooks/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        surface: "var(--bg)",
        sidebar: "var(--bg2)",
        panel: "var(--panel)",
        panel2: "var(--panel2)",
        ink: "var(--text)",
        muted: "var(--text2)",
        faint: "var(--text3)",
        line: "var(--border)",
        line2: "var(--border2)",
        accent: "var(--accent)",
        green: "var(--green)",
        red: "var(--red)",
        yellow: "var(--yellow)",
        purple: "var(--purple)",
        teal: {
          50: "var(--accent-dim)",
          600: "var(--accent)",
          700: "var(--accent)"
        },
        amber: {
          50: "var(--yellow-dim)",
          600: "var(--yellow)"
        },
        signal: {
          red: "var(--red)",
          blue: "var(--accent)",
          violet: "var(--purple)"
        }
      },
      boxShadow: {
        panel: "none"
      }
    }
  },
  plugins: []
};

export default config;
