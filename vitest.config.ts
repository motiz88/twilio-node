import { defineConfig } from "vitest/config";
import { resolve } from "path";

export default defineConfig({
  resolve: {
    alias: {
      // Redirect `import { jest } from "@jest/globals"` to our shim.
      "@jest/globals": resolve(
        __dirname,
        "spec/__vitest__/jest-globals-shim.ts"
      ),
    },
  },
  test: {
    // Expose Jest-compatible globals (describe, it, expect, vi, …) without imports.
    globals: true,
    // Run the global setup file that maps the `jest` global to `vi`.
    setupFiles: ["./spec/__vitest__/setup.ts"],
    // Match all unit and validation specs but exclude cluster (integration) tests.
    include: ["spec/**/*.spec.{js,ts}"],
    exclude: ["spec/cluster/**", "node_modules/**"],
    // Use Node environment (default for Node.js projects).
    environment: "node",
    // Show a coverage report when run with --coverage.
    coverage: {
      provider: "v8",
      include: ["src/**"],
    },
  },
});
