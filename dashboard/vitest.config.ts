import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    globals: true,
    // Exclude Next.js internal directories
    exclude: ["node_modules", ".next", "**/*.spec.*"],
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "."),
    },
  },
});
