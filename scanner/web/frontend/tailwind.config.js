/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        shell: "#070b13",
        panel: "#0f172a",
        border: "#1e293b",
        accent: "#22d3ee",
        critical: "#ef4444",
        high: "#f97316",
        medium: "#f59e0b",
        low: "#22c55e",
      },
      boxShadow: {
        glass: "0 10px 30px rgba(15,23,42,0.45)",
      },
    },
  },
  plugins: [],
};
