/**
 * Edge runtime entry point for Twilio webhook validation.
 *
 * This module exports only the async, Web Crypto-based webhook validation
 * functions. It has no dependency on Node.js built-ins and is suitable for
 * use in edge runtimes such as Cloudflare Workers and Vercel Edge Functions.
 */
export {
  validateRequestAsync,
  validateBodyAsync,
  validateRequestWithBodyAsync,
  validateIncomingRequestAsync,
  getExpectedBodyHashAsync,
  getExpectedTwilioSignatureAsync,
} from "./webhooks/webhooks.async";

export type {
  Request,
  RequestValidatorOptions,
} from "./webhooks/webhooks.async";
