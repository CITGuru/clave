/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        clave: {
          bg: "#0b0d10",
          panel: "#14181d",
          border: "#252b33",
          accent: "#4f8cff",
          muted: "#8a949e",
        },
      },
    },
  },
  plugins: [],
};
