// Shim for `import { jest } from "@jest/globals"` used in some test files.
// Re-exports Vitest's `vi` object as `jest` so those imports continue to work.
export { vi as jest } from "vitest";
