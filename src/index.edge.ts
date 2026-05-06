/**
 * Edge runtime entry point for the Twilio SDK.
 *
 * Re-exports everything from the shared entry point (index.ts), which
 * contains only Web Crypto / pure-JS code that is compatible with every
 * WinterCG-compliant runtime (Cloudflare Workers, Vercel Edge, etc.).
 *
 * As more of the SDK is made edge-compatible, the new implementations will
 * be added to index.ts (shared) and automatically appear here.  Node-only
 * things (REST client, sync webhook validation, JWT, …) remain in
 * index.node.ts and are never exported from this file.
 */
export * from "./index";
