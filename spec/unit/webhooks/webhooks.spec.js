/**
 * Tests for Twilio webhook validation — both sync (Node.js) and async (Web Crypto).
 *
 * Async tests always run in both the Node.js and Edge test suites.
 *
 * Sync tests (Node.js crypto / scmp) are gated by feature detection:
 *   - In the Node.js test suite (jest.config.node.js), ../../../src resolves
 *     to src/index.node which exports validateRequest and friends, so
 *     hasSyncValidation is true and the sync tests are registered.
 *   - In the Edge test suite (jest.config.edge.js), ../../../src resolves to
 *     src/index.edge which does not export sync functions, so hasSyncValidation
 *     is false and those describe blocks are never registered.
 */
import {
  validateRequestAsync,
  validateBodyAsync,
  validateRequestWithBodyAsync,
  validateIncomingRequestAsync,
  getExpectedBodyHashAsync,
  getExpectedTwilioSignatureAsync,
} from "../../../src";

// Feature-detect sync webhook validation via the entry point.
// Uses require() so we can inspect the resolved exports at module evaluation
// time, before any test is registered.
const sdk = require("../../../src");
const hasSyncValidation = typeof sdk.validateRequest === "function";

let validateRequest,
  getExpectedTwilioSignature,
  validateBody,
  getExpectedBodyHash,
  validateRequestWithBody;
if (hasSyncValidation) {
  ({
    validateRequest,
    getExpectedTwilioSignature,
    validateBody,
    getExpectedBodyHash,
    validateRequestWithBody,
  } = sdk);
}

describe("webhooks", () => {
  const authToken = "s3cr3t";

  // ===========================================================================
  // Sync validation (Node.js only — uses node:crypto + scmp)
  // Registered only when the Node entry point is active (hasSyncValidation).
  // ===========================================================================
  if (hasSyncValidation) {
    describe("validateRequest()", () => {
      it("should return false when the signature URL does not match the target URL", () => {
        const serverUrl = "https://example.com/path?test=param";
        const targetUrl = "https://example.com/path?test=param2";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = validateRequest(authToken, signature, targetUrl, {});

        expect(result).toBe(false);
      });

      describe("when the signature is derived from an URL with port", () => {
        it("should return true when the target url contains the port", () => {
          const serverUrl = "https://example.com:443/path?test=param";
          const targetUrl = "https://example.com:443/path?test=param";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });

        it("should return true when the target url does not contain the port", () => {
          const serverUrl = "https://example.com:443/path?test=param";
          const targetUrl = "https://example.com/path?test=param";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });
      });

      describe("when the signature is derived from an URL without port", () => {
        it("should return true when the target url does not contain the port", () => {
          const serverUrl = "https://example.com/path?test=param";
          const targetUrl = "https://example.com/path?test=param";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });

        it("should return true when the target url contains the port", () => {
          const serverUrl = "https://example.com/path?test=param";
          const targetUrl = "https://example.com:443/path?test=param";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });
      });

      describe("when the signature is derived from an URL with a query param containing an unescaped single quote", () => {
        it("should return true when the target url contains the unescaped single quote", () => {
          const serverUrl = "https://example.com/path?test=param'WithQuote";
          const targetUrl = "https://example.com/path?test=param'WithQuote";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });

        it("should return true when the target url contains the escaped single quote", () => {
          const serverUrl = "https://example.com/path?test=param'WithQuote";
          const targetUrl = "https://example.com/path?test=param%27WithQuote";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });
      });

      describe("when the signature is derived from an URL with a query param containing an escaped single quote", () => {
        it("should return true when the target url contains the unescaped single quote", () => {
          const serverUrl = "https://example.com/path?test=param%27WithQuote";
          const targetUrl = "https://example.com/path?test=param'WithQuote";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });

        it("should return true when the target url contains the escaped single quote", () => {
          const serverUrl = "https://example.com/path?test=param%27WithQuote";
          const targetUrl = "https://example.com/path?test=param%27WithQuote";

          const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
          const result = validateRequest(authToken, signature, targetUrl, {});

          expect(result).toBe(true);
        });
      });
    });
  }

  // ===========================================================================
  // Async validation (Web Crypto — works on both Node.js and Edge)
  // ===========================================================================

  describe("getExpectedTwilioSignatureAsync()", () => {
    it("should return a valid base64 signature (self-consistent round-trip)", async () => {
      const url = "https://example.com/path?test=param";
      const params = { foo: "bar", baz: "qux" };
      const result = await getExpectedTwilioSignatureAsync(authToken, url, params);

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      // Round-trip: the returned signature should validate correctly
      await expect(
        validateRequestAsync(authToken, result, url, params)
      ).resolves.toBe(true);
    });

    if (hasSyncValidation) {
      it("should return the same value as the sync version", async () => {
        const url = "https://example.com/path?test=param";
        const params = { foo: "bar", baz: "qux" };

        const sync = getExpectedTwilioSignature(authToken, url, params);
        const result = await getExpectedTwilioSignatureAsync(authToken, url, params);

        expect(result).toBe(sync);
      });

      it("should return the same value for a URL with a single-quote param", async () => {
        const url = "https://example.com/path?test=param'WithQuote";
        const params = {};

        const sync = getExpectedTwilioSignature(authToken, url, params);
        const result = await getExpectedTwilioSignatureAsync(authToken, url, params);

        expect(result).toBe(sync);
      });

      it("should return the same value for array param values", async () => {
        const url = "https://example.com/path";
        const params = { items: ["b", "a", "c"] };

        const sync = getExpectedTwilioSignature(authToken, url, params);
        const result = await getExpectedTwilioSignatureAsync(authToken, url, params);

        expect(result).toBe(sync);
      });
    }
  });

  describe("getExpectedBodyHashAsync()", () => {
    it("should produce the correct SHA-256 hash (self-consistent round-trip)", async () => {
      const body = '{"key":"value"}';
      const hash = await getExpectedBodyHashAsync(body);
      // Round-trip: the returned hash should validate correctly
      await expect(validateBodyAsync(body, hash)).resolves.toBe(true);
    });

    it("should produce the correct hash for an empty body", async () => {
      const hash = await getExpectedBodyHashAsync("");
      await expect(validateBodyAsync("", hash)).resolves.toBe(true);
    });

    if (hasSyncValidation) {
      it("should return the same value as the sync version", async () => {
        const body = '{"key":"value"}';

        const sync = getExpectedBodyHash(body);
        const result = await getExpectedBodyHashAsync(body);

        expect(result).toBe(sync);
      });

      it("should return the same value for an empty body", async () => {
        const sync = getExpectedBodyHash("");
        const result = await getExpectedBodyHashAsync("");
        expect(result).toBe(sync);
      });
    }
  });

  describe("validateRequestAsync()", () => {
    it("should return false when the signature URL does not match the target URL", async () => {
      const serverUrl = "https://example.com/path?test=param";
      const targetUrl = "https://example.com/path?test=param2";

      const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
      const result = await validateRequestAsync(authToken, signature, targetUrl, {});

      expect(result).toBe(false);
    });

    it("should return true for a validly signed request", async () => {
      const url = "https://example.com/path?test=param";
      const params = { foo: "bar" };
      const signature = await getExpectedTwilioSignatureAsync(authToken, url, params);

      await expect(
        validateRequestAsync(authToken, signature, url, params)
      ).resolves.toBe(true);
    });

    if (hasSyncValidation) {
      it("should agree with the sync version on valid requests", async () => {
        const url = "https://example.com/path?test=param";
        const params = { foo: "bar" };
        const signature = getExpectedTwilioSignature(authToken, url, params);

        const syncResult = validateRequest(authToken, signature, url, params);
        const asyncResult = await validateRequestAsync(authToken, signature, url, params);

        expect(asyncResult).toBe(syncResult);
        expect(asyncResult).toBe(true);
      });
    }

    describe("when the signature is derived from an URL with port", () => {
      it("should return true when the target url contains the port", async () => {
        const serverUrl = "https://example.com:443/path?test=param";
        const targetUrl = "https://example.com:443/path?test=param";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url does not contain the port", async () => {
        const serverUrl = "https://example.com:443/path?test=param";
        const targetUrl = "https://example.com/path?test=param";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });

    describe("when the signature is derived from an URL without port", () => {
      it("should return true when the target url does not contain the port", async () => {
        const serverUrl = "https://example.com/path?test=param";
        const targetUrl = "https://example.com/path?test=param";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url contains the port", async () => {
        const serverUrl = "https://example.com/path?test=param";
        const targetUrl = "https://example.com:443/path?test=param";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });

    describe("when the signature is derived from an URL with a query param containing an unescaped single quote", () => {
      it("should return true when the target url contains the unescaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param'WithQuote";
        const targetUrl = "https://example.com/path?test=param'WithQuote";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url contains the escaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param'WithQuote";
        const targetUrl = "https://example.com/path?test=param%27WithQuote";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });

    describe("when the signature is derived from an URL with a query param containing an escaped single quote", () => {
      it("should return true when the target url contains the unescaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param%27WithQuote";
        const targetUrl = "https://example.com/path?test=param'WithQuote";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url contains the escaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param%27WithQuote";
        const targetUrl = "https://example.com/path?test=param%27WithQuote";

        const signature = await getExpectedTwilioSignatureAsync(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });
  });

  describe("validateBodyAsync()", () => {
    it("should return true when the body matches the hash", async () => {
      const body = '{"key":"value"}';
      const bodyHash = await getExpectedBodyHashAsync(body);

      await expect(validateBodyAsync(body, bodyHash)).resolves.toBe(true);
    });

    it("should return false when the body does not match the hash", async () => {
      const body = '{"key":"value"}';
      const differentBodyHash = await getExpectedBodyHashAsync("different body");

      await expect(validateBodyAsync(body, differentBodyHash)).resolves.toBe(false);
    });

    if (hasSyncValidation) {
      it("should agree with the sync version when the body matches", async () => {
        const body = '{"key":"value"}';
        const bodyHash = getExpectedBodyHash(body);

        const syncResult = validateBody(body, bodyHash);
        const asyncResult = await validateBodyAsync(body, bodyHash);

        expect(asyncResult).toBe(syncResult);
        expect(asyncResult).toBe(true);
      });

      it("should agree with the sync version when the body does not match", async () => {
        const body = '{"key":"value"}';
        const wrongHash = getExpectedBodyHash("different body");

        const syncResult = validateBody(body, wrongHash);
        const asyncResult = await validateBodyAsync(body, wrongHash);

        expect(asyncResult).toBe(syncResult);
        expect(asyncResult).toBe(false);
      });
    }
  });

  describe("validateRequestWithBodyAsync()", () => {
    it("should return true for a valid request with body", async () => {
      const body = '{"key":"value"}';
      const bodyHash = await getExpectedBodyHashAsync(body);
      const url = `https://example.com/path?bodySHA256=${encodeURIComponent(bodyHash)}`;
      const signature = await getExpectedTwilioSignatureAsync(authToken, url, {});

      await expect(
        validateRequestWithBodyAsync(authToken, signature, url, body)
      ).resolves.toBe(true);
    });

    it("should return false when the body does not match", async () => {
      const body = '{"key":"value"}';
      const differentBodyHash = await getExpectedBodyHashAsync("different body");
      const url = `https://example.com/path?bodySHA256=${encodeURIComponent(differentBodyHash)}`;
      const signature = await getExpectedTwilioSignatureAsync(authToken, url, {});

      await expect(
        validateRequestWithBodyAsync(authToken, signature, url, body)
      ).resolves.toBe(false);
    });

    if (hasSyncValidation) {
      it("should agree with the sync version for a valid request", async () => {
        const body = '{"key":"value"}';
        const bodyHash = getExpectedBodyHash(body);
        const url = `https://example.com/path?bodySHA256=${encodeURIComponent(bodyHash)}`;
        const signature = getExpectedTwilioSignature(authToken, url, {});

        const syncResult = validateRequestWithBody(authToken, signature, url, body);
        const asyncResult = await validateRequestWithBodyAsync(
          authToken,
          signature,
          url,
          body
        );

        expect(asyncResult).toBe(syncResult);
        expect(asyncResult).toBe(true);
      });
    }
  });

  // ===========================================================================
  // Edge entry point contract
  // Verifies that src/index.edge.ts exports the async API and does NOT
  // expose the Node-only sync functions.  Runs in both test suites since it
  // imports index.edge directly (not through the module mapper).
  // ===========================================================================
  describe("edge entry point (src/index.edge.ts)", () => {
    let edge;
    beforeAll(async () => {
      edge = await import("../../../src/index.edge");
    });

    it("exports async webhook validation functions", () => {
      expect(typeof edge.getExpectedTwilioSignatureAsync).toBe("function");
      expect(typeof edge.validateRequestAsync).toBe("function");
      expect(typeof edge.validateBodyAsync).toBe("function");
      expect(typeof edge.validateRequestWithBodyAsync).toBe("function");
      expect(typeof edge.validateIncomingRequestAsync).toBe("function");
      expect(typeof edge.getExpectedBodyHashAsync).toBe("function");
    });

    it("does not export Node-only sync webhook functions", () => {
      // Sync validation uses Node.js crypto/scmp and belongs only in
      // index.node.ts; it must not appear in the edge entry point.
      expect(edge.validateRequest).toBeUndefined();
      expect(edge.validateBody).toBeUndefined();
      expect(edge.getExpectedTwilioSignature).toBeUndefined();
    });

    it("getExpectedTwilioSignatureAsync produces the correct signature", async () => {
      const url = "https://example.com/path?test=param";
      const params = { foo: "bar" };

      const fromEdge = await edge.getExpectedTwilioSignatureAsync(
        authToken,
        url,
        params
      );
      // Cross-validate using our own import of the async function
      const local = await getExpectedTwilioSignatureAsync(authToken, url, params);
      expect(fromEdge).toBe(local);
    });

    it("validateRequestAsync correctly validates a signed request", async () => {
      const url = "https://example.com/path?test=param";
      const params = { foo: "bar" };
      const signature = await getExpectedTwilioSignatureAsync(authToken, url, params);

      const result = await edge.validateRequestAsync(
        authToken,
        signature,
        url,
        params
      );
      expect(result).toBe(true);
    });
  });
});
