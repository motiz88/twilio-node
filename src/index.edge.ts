/**
 * Edge runtime entry point for Twilio webhook validation.
 *
 * This module exports only the async, Web Crypto-based webhook validation
 * functions. It has no dependency on Node.js built-ins and is suitable for
 * use in edge runtimes such as Cloudflare Workers and Vercel Edge Functions.
 *
 * The exported functions are re-exported under the same names as their
 * sync counterparts in the Node.js entry point, so code can be written
 * against a single API surface regardless of the runtime.
 */
export {
  validateRequestAsync as validateRequest,
  validateBodyAsync as validateBody,
  validateRequestWithBodyAsync as validateRequestWithBody,
  validateIncomingRequestAsync as validateIncomingRequest,
  getExpectedBodyHashAsync as getExpectedBodyHash,
  getExpectedTwilioSignatureAsync as getExpectedTwilioSignature,
} from "./webhooks/webhooks.async";

export type {
  Request,
  RequestValidatorOptions,
} from "./webhooks/webhooks.async";
