/**
 * Shared entry point for the Twilio SDK.
 *
 * Everything exported from this file is compatible with both Node.js and Edge
 * runtimes (Cloudflare Workers, Vercel Edge Functions, etc.).
 *
 * Node-only additions (REST client, sync webhook validation, JWT, …) live in
 * index.node.ts; edge additions live in index.edge.ts.  As more of the SDK is
 * made edge-compatible its exports will migrate here from index.node.ts.
 */

// Async webhook validation — uses only Web Crypto (globalThis.crypto.subtle),
// so it works in every runtime that implements the WinterCG baseline.
export {
  validateRequestAsync,
  validateBodyAsync,
  validateRequestWithBodyAsync,
  validateIncomingRequestAsync,
  getExpectedBodyHashAsync,
  getExpectedTwilioSignatureAsync,
} from "./webhooks/webhooks.edge";

export type {
  Request,
  RequestValidatorOptions,
} from "./webhooks/webhooks.edge";

// TwiML response builders — pure JavaScript (xmlbuilder), no Node.js built-ins.
export { default as VoiceResponse } from "./twiml/VoiceResponse";
export { default as MessagingResponse } from "./twiml/MessagingResponse";
export { default as FaxResponse } from "./twiml/FaxResponse";
