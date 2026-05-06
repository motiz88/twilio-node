/**
 * Shared utilities for Twilio webhook validation.
 *
 * This file has no dependency on Node.js built-ins and is safe to import
 * from both the Node.js entry point (webhooks.node.ts) and the edge entry
 * point (webhooks.edge.ts).  All URL helpers use the WHATWG URL API and
 * encodeURIComponent, which are available in every supported runtime.
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
