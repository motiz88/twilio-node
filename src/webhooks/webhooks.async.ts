/**
 * Async (Web Crypto) implementations of Twilio webhook validation.
 *
 * These functions use only standard Web Crypto APIs (globalThis.crypto.subtle)
 * and have no dependency on Node.js built-ins, making them suitable for use in
 * edge runtimes (Cloudflare Workers, Vercel Edge, etc.) as well as Node.js.
 */

export interface Request {
  protocol: string;
  header(name: string): string | undefined;
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

// ---------------------------------------------------------------------------
// Internal helpers (portable, no Node.js dependencies)
// ---------------------------------------------------------------------------

function buildUrlWithStandardPort(parsedUrl: URL): string {
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

function addPort(parsedUrl: URL): string {
  if (!parsedUrl.port) {
    return buildUrlWithStandardPort(parsedUrl);
  }
  return parsedUrl.toString();
}

function removePort(parsedUrl: URL): string {
  parsedUrl = new URL(parsedUrl.toString()); // prevent mutation
  parsedUrl.port = "";
  return parsedUrl.toString();
}

function withLegacyQuerystring(url: string): string {
  const parsedUrl = new URL(url);

  if (parsedUrl.search) {
    // URLSearchParams decodes the query string (e.g. %27 → '), then
    // encodeURIComponent re-encodes it. encodeURIComponent leaves the same
    // set of characters unencoded as querystring.stringify (RFC 3986
    // unreserved chars: A-Z a-z 0-9 - _ . ! ~ * ' ( )), so this faithfully
    // reproduces the legacy querystring.stringify round-trip without importing
    // any Node.js built-ins.
    const params = new URLSearchParams(parsedUrl.search);
    parsedUrl.search = "";
    const legacyQs = Array.from(params.entries())
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");
    return parsedUrl.toString() + "?" + legacyQs;
  }

  return url;
}

function toFormUrlEncodedParam(
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

// ---------------------------------------------------------------------------
// Public async API
// ---------------------------------------------------------------------------

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
