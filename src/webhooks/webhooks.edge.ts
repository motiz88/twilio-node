/**
 * Edge runtime webhook validation.
 *
 * All async (Web Crypto) webhook validation functions now live in the shared
 * webhooks.ts file since globalThis.crypto is available in both Node.js 15+
 * and WinterCG-compliant edge runtimes.  This file re-exports everything
 * from the shared file for backward compatibility.
 */
export * from "./webhooks";
