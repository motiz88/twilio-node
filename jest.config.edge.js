/**
 * Jest configuration for running the test suite against the edge entry point
 * (src/index.edge.ts) instead of the default Node.js entry point
 * (src/index.node.ts).
 *
 * The moduleNameMapper redirects bare imports of the package root
 * (e.g. `import X from "../../../src"`) to src/index.edge so that the
 * included specs exercise the edge entry point without per-file changes.
 *
 * Specs that rely on Node-only symbols (REST client, JWT, credential providers,
 * sync webhook validation) are either excluded here or self-skip via feature
 * detection inside the spec file (e.g. webhooks.spec.js checks whether the
 * resolved entry point exports `validateRequest` before registering the sync
 * test blocks).
 */

/** @type {import('jest').Config} */
module.exports = {
  moduleNameMapper: {
    // Match e.g. "../../../src" or "../../../../src" (with optional trailing
    // slash) but NOT sub-path imports like "../../../src/twiml/VoiceResponse".
    "^(\\.\\./)+src/?$": "<rootDir>/src/index.edge",
  },
  testPathIgnorePatterns: [
    "/node_modules/",
    "spec/cluster",
    // The specs below import the full SDK via the package root and rely on
    // Node-only symbols (REST client, JWT, credential providers) that are
    // intentionally absent from the edge entry point.
    "spec/integration\\.spec\\.js",
    "spec/unit/rest/",
    "spec/unit/jwt/AccessToken\\.spec\\.js",
    "spec/unit/jwt/validation/",
    "spec/unit/base/Version\\.spec\\.js",
    "spec/unit/auth_strategy/TokenAuthStrategy\\.spec\\.ts",
    "spec/unit/credential_provider/NoAuthCredentialProvider\\.spec\\.ts",
  ],
};
