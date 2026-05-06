/**
 * Jest configuration for the Node.js test suite.
 *
 * Maps bare imports of the package root (e.g. `import X from "../../../src"`)
 * to src/index.node.ts so that every spec exercises the full Node.js entry
 * point, including sync webhook validation and the REST client.
 *
 * All specs are run (including webhooks.spec.js which tests Node-only sync
 * webhook functions).
 */

/** @type {import('jest').Config} */
module.exports = {
  moduleNameMapper: {
    // Match e.g. "../../../src" or "../../../../src" (with optional trailing
    // slash) but NOT sub-path imports like "../../../src/twiml/VoiceResponse".
    "^(\\.\\./)+src/?$": "<rootDir>/src/index.node",
  },
  testPathIgnorePatterns: ["/node_modules/", "spec/cluster"],
};
