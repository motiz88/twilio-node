/**
 * Shared utilities and async webhook validation for Twilio.
 *
 * This file has no dependency on Node.js built-ins and is safe to import
 * from both the Node.js entry point (webhooks.node.ts) and the edge entry
 * point (webhooks.edge.ts).  All URL helpers use the WHATWG URL API and
 * encodeURIComponent, which are available in every supported runtime.
 *
 * The async validation functions use only globalThis.crypto.subtle, which is
 * available in Node.js 15+ and all WinterCG-compliant edge runtimes.
 */

export interface Request {
  protocol: string;
  header(name: string): string | undefined;
  /**
   * The `host` header value is the only property accessed by the validation
   * helpers.  The index signature accepts the full range of HTTP header values
   * (string, string[], or undefined) so that both Express's IncomingHttpHeaders
   * and plain objects are assignable here.
   */
  headers: { host?: string; [key: string]: string | string[] | undefined };
  originalUrl: string;
  rawBody?: any;
  body: any;
}

export interface RequestValidatorOptions {
  /**
   * The full URL (with query string) you used to configure the webhook with Twilio - overrides host/protocol options
   */
  url?: string;
  /**
   * Manually specify the host name used by Twilio in a number's webhook config
   */
  host?: string;
  /**
   * Manually specify the protocol used by Twilio in a number's webhook config
   */
  protocol?: string;
}

/**
 * Utility function to construct the URL string, since Node.js url library
 * won't include standard port numbers.
 *
 * @param parsedUrl - The parsed url object that Twilio requested on your server
 * @returns URL with standard port number included
 */
export function buildUrlWithStandardPort(parsedUrl: URL): string {
  let url = "";
  const port = parsedUrl.protocol === "https:" ? ":443" : ":80";

  url += parsedUrl.protocol ? parsedUrl.protocol + "//" : "";
  url += parsedUrl.username;
  url += parsedUrl.password ? ":" + parsedUrl.password : "";
  url += parsedUrl.username || parsedUrl.password ? "@" : "";
  url += parsedUrl.host ? parsedUrl.host + port : "";
  url += parsedUrl.pathname + parsedUrl.search + parsedUrl.hash;

  return url;
}

/**
 * Utility function to add a port number to a URL.
 *
 * @param parsedUrl - The parsed url object that Twilio requested on your server
 * @returns URL with port
 */
export function addPort(parsedUrl: URL): string {
  if (!parsedUrl.port) {
    return buildUrlWithStandardPort(parsedUrl);
  }
  return parsedUrl.toString();
}

/**
 * Utility function to remove a port number from a URL.
 *
 * @param parsedUrl - The parsed url object that Twilio requested on your server
 * @returns URL without port
 */
export function removePort(parsedUrl: URL): string {
  const copy = new URL(parsedUrl.href); // prevent mutation of original URL object
  copy.port = "";
  return copy.toString();
}

/**
 * Re-encode query-string parameters using encodeURIComponent so that the URL
 * exactly matches what Node's legacy `querystring.stringify` would have
 * produced.  `encodeURIComponent` leaves the same set of characters unencoded
 * as `querystring.stringify` (the RFC 3986 unreserved set: A-Z a-z 0-9 - _ .
 * ! ~ * ' ( )), so the two are interchangeable for every value that can appear
 * in a Twilio webhook URL.
 *
 * `URLSearchParams` first fully decodes percent-encoded characters (e.g.
 * %27 → '), then `encodeURIComponent` re-encodes them, faithfully reproducing
 * the legacy round-trip without any Node.js built-in imports.
 */
export function withLegacyQuerystring(url: string): string {
  const parsedUrl = new URL(url);

  if (parsedUrl.search) {
    const params = new URLSearchParams(parsedUrl.search);
    parsedUrl.search = "";
    const legacyQs = Array.from(params.entries())
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");
    return parsedUrl.toString() + "?" + legacyQs;
  }

  return url;
}

/**
 * Utility function to convert a request parameter to string format for
 * HMAC signing.
 *
 * @param paramName - The request parameter name
 * @param paramValue - The request parameter value
 * @returns Formatted parameter string
 */
export function toFormUrlEncodedParam(
  paramName: string,
  paramValue: string | Array<string>
): string {
  if (paramValue instanceof Array) {
    return Array.from(new Set(paramValue))
      .sort()
      .map((val) => toFormUrlEncodedParam(paramName, val))
      .reduce((acc, val) => acc + val, "");
  }
  return paramName + paramValue;
}

// ---------------------------------------------------------------------------
// Async (Web Crypto) webhook validation
//
// These functions use only globalThis.crypto.subtle, which is available in
// Node.js 15+ and all WinterCG-compliant edge runtimes (Cloudflare Workers,
// Vercel Edge, etc.).  They are in the shared file so they can be imported by
// both webhooks.node.ts (via index.node.ts) and webhooks.edge.ts.
// ---------------------------------------------------------------------------

/** Decode a base64 string to a Uint8Array (portable, no Buffer). */
function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/** Encode an ArrayBuffer as a lowercase hex string. */
function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Async version of getExpectedTwilioSignature using Web Crypto.
 *
 * @param authToken - The auth token, as seen in the Twilio portal
 * @param url - The full URL (with query string) you configured to handle this request
 * @param params - the parameters sent with this request
 * @returns Promise resolving to the expected base64-encoded HMAC-SHA1 signature
 */
export async function getExpectedTwilioSignatureAsync(
  authToken: string,
  url: string,
  params: Record<string, any>
): Promise<string> {
  if (url.indexOf("bodySHA256") !== -1 && params === null) {
    params = {};
  }

  const data = Object.keys(params)
    .sort()
    .reduce((acc, key) => acc + toFormUrlEncodedParam(key, params[key]), url);

  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(authToken),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signature = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(data)
  );

  // Convert ArrayBuffer to base64
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

/**
 * Async version of getExpectedBodyHash using Web Crypto.
 *
 * @param body - The plain-text body of the request
 * @returns Promise resolving to the hex-encoded SHA-256 hash of the body
 */
export async function getExpectedBodyHashAsync(body: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await globalThis.crypto.subtle.digest(
    "SHA-256",
    encoder.encode(body)
  );
  return arrayBufferToHex(hashBuffer);
}

/**
 * Async timing-safe signature validation for a single URL variant.
 * Uses crypto.subtle.verify which is inherently constant-time, replacing scmp.
 */
async function validateSignatureWithUrlAsync(
  authToken: string,
  twilioHeader: string,
  url: string,
  params: Record<string, any>
): Promise<boolean> {
  const data = Object.keys(params)
    .sort()
    .reduce((acc, key) => acc + toFormUrlEncodedParam(key, params[key]), url);

  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(authToken),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["verify"]
  );

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64ToBytes(twilioHeader);
  } catch {
    return false;
  }

  return globalThis.crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    encoder.encode(data)
  );
}

/**
 * Async version of validateRequest using Web Crypto.
 *
 * @param authToken - The auth token, as seen in the Twilio portal
 * @param twilioHeader - The value of the X-Twilio-Signature header from the request
 * @param url - The full URL (with query string) you configured to handle this request
 * @param params - the parameters sent with this request
 * @returns Promise resolving to true if the request is valid
 */
export async function validateRequestAsync(
  authToken: string,
  twilioHeader: string,
  url: string,
  params: Record<string, any>
): Promise<boolean> {
  twilioHeader = twilioHeader || "";
  const urlObject = new URL(url);

  /*
   * Check signature of the url with and without the port number
   * and with and without the legacy querystring (special chars are encoded when using `new URL()`)
   * since signature generation on the back end is inconsistent
   */
  if (
    await validateSignatureWithUrlAsync(
      authToken,
      twilioHeader,
      removePort(urlObject),
      params
    )
  ) {
    return true;
  }

  if (
    await validateSignatureWithUrlAsync(
      authToken,
      twilioHeader,
      addPort(urlObject),
      params
    )
  ) {
    return true;
  }

  if (
    await validateSignatureWithUrlAsync(
      authToken,
      twilioHeader,
      withLegacyQuerystring(removePort(urlObject)),
      params
    )
  ) {
    return true;
  }

  return validateSignatureWithUrlAsync(
    authToken,
    twilioHeader,
    withLegacyQuerystring(addPort(urlObject)),
    params
  );
}

/**
 * Async version of validateBody using Web Crypto.
 *
 * Performs a timing-safe comparison of the given bodyHash against the
 * SHA-256 hash of the body, using an HMAC-based constant-time technique.
 *
 * @param body - The plain-text body of the request
 * @param bodyHash - The expected SHA-256 hex hash (e.g. from the bodySHA256 query parameter)
 * @returns Promise resolving to true if the body matches the hash
 */
export async function validateBodyAsync(
  body: string,
  bodyHash: string
): Promise<boolean> {
  const expectedHash = await getExpectedBodyHashAsync(body);

  // Timing-safe comparison of two hex strings via HMAC-verify.
  // A fixed key would let an attacker with multiple requests pre-compute
  // expected HMACs; a fresh random key per call prevents that while still
  // ensuring crypto.subtle.verify's constant-time guarantee.
  const encoder = new TextEncoder();
  const keyMaterial = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    keyMaterial,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const expectedSig = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(expectedHash)
  );
  return globalThis.crypto.subtle.verify(
    "HMAC",
    key,
    expectedSig,
    encoder.encode(bodyHash)
  );
}

/**
 * Async version of validateRequestWithBody using Web Crypto.
 *
 * @param authToken - The auth token, as seen in the Twilio portal
 * @param twilioHeader - The value of the X-Twilio-Signature header from the request
 * @param url - The full URL (with query string) you configured to handle this request
 * @param body - The body of the request
 * @returns Promise resolving to true if the request and body are valid
 */
export async function validateRequestWithBodyAsync(
  authToken: string,
  twilioHeader: string,
  url: string,
  body: string
): Promise<boolean> {
  const urlObject = new URL(url);
  return (
    (await validateRequestAsync(authToken, twilioHeader, url, {})) &&
    (await validateBodyAsync(
      body,
      urlObject.searchParams.get("bodySHA256") || ""
    ))
  );
}

/**
 * Async version of validateIncomingRequest using Web Crypto.
 *
 * @param request - A request object (based on Express implementation)
 * @param authToken - The auth token, as seen in the Twilio portal
 * @param opts - options for request validation
 * @returns Promise resolving to true if the request is valid
 */
export async function validateIncomingRequestAsync(
  request: Request,
  authToken: string,
  opts?: RequestValidatorOptions
): Promise<boolean> {
  const options = opts || {};
  let webhookUrl: string;

  if (options.url) {
    webhookUrl = options.url;
  } else {
    const protocol = options.protocol || request.protocol;
    const host = options.host || request.headers.host;
    webhookUrl = `${protocol.replace(/:$/, "")}://${host}${request.originalUrl}`;
  }

  if (webhookUrl.indexOf("bodySHA256") > 0) {
    return validateRequestWithBodyAsync(
      authToken,
      request.header("X-Twilio-Signature") || "",
      webhookUrl,
      request.rawBody || "{}"
    );
  } else {
    return validateRequestAsync(
      authToken,
      request.header("X-Twilio-Signature") || "",
      webhookUrl,
      request.body || {}
    );
  }
}
