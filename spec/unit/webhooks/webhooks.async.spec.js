// Sync reference implementations — imported directly from the Node build so
// that this spec works identically in both the node and edge test runs.
import {
  getExpectedTwilioSignature,
  getExpectedBodyHash,
  validateRequest,
  validateBody,
  validateRequestWithBody,
} from "../../../src/webhooks/webhooks.node";
import {
  getExpectedTwilioSignatureAsync,
  getExpectedBodyHashAsync,
  validateRequestAsync,
  validateBodyAsync,
  validateRequestWithBodyAsync,
} from "../../../src/webhooks/webhooks.edge";

describe("webhooks async (Web Crypto)", () => {
  const authToken = "s3cr3t";

  describe("getExpectedTwilioSignatureAsync()", () => {
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
  });

  describe("getExpectedBodyHashAsync()", () => {
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
  });

  describe("validateRequestAsync()", () => {
    it("should return false when the signature URL does not match the target URL", async () => {
      const serverUrl = "https://example.com/path?test=param";
      const targetUrl = "https://example.com/path?test=param2";

      const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
      const result = await validateRequestAsync(authToken, signature, targetUrl, {});

      expect(result).toBe(false);
    });

    it("should agree with the sync version on valid requests", async () => {
      const url = "https://example.com/path?test=param";
      const params = { foo: "bar" };
      const signature = getExpectedTwilioSignature(authToken, url, params);

      const syncResult = validateRequest(authToken, signature, url, params);
      const asyncResult = await validateRequestAsync(authToken, signature, url, params);

      expect(asyncResult).toBe(syncResult);
      expect(asyncResult).toBe(true);
    });

    describe("when the signature is derived from an URL with port", () => {
      it("should return true when the target url contains the port", async () => {
        const serverUrl = "https://example.com:443/path?test=param";
        const targetUrl = "https://example.com:443/path?test=param";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url does not contain the port", async () => {
        const serverUrl = "https://example.com:443/path?test=param";
        const targetUrl = "https://example.com/path?test=param";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });

    describe("when the signature is derived from an URL without port", () => {
      it("should return true when the target url does not contain the port", async () => {
        const serverUrl = "https://example.com/path?test=param";
        const targetUrl = "https://example.com/path?test=param";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url contains the port", async () => {
        const serverUrl = "https://example.com/path?test=param";
        const targetUrl = "https://example.com:443/path?test=param";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });

    describe("when the signature is derived from an URL with a query param containing an unescaped single quote", () => {
      it("should return true when the target url contains the unescaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param'WithQuote";
        const targetUrl = "https://example.com/path?test=param'WithQuote";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url contains the escaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param'WithQuote";
        const targetUrl = "https://example.com/path?test=param%27WithQuote";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });

    describe("when the signature is derived from an URL with a query param containing an escaped single quote", () => {
      it("should return true when the target url contains the unescaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param%27WithQuote";
        const targetUrl = "https://example.com/path?test=param'WithQuote";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });

      it("should return true when the target url contains the escaped single quote", async () => {
        const serverUrl = "https://example.com/path?test=param%27WithQuote";
        const targetUrl = "https://example.com/path?test=param%27WithQuote";

        const signature = getExpectedTwilioSignature(authToken, serverUrl, {});
        const result = await validateRequestAsync(authToken, signature, targetUrl, {});

        expect(result).toBe(true);
      });
    });
  });

  describe("validateBodyAsync()", () => {
    it("should return true when the body matches the hash", async () => {
      const body = '{"key":"value"}';
      const bodyHash = getExpectedBodyHash(body);

      const syncResult = validateBody(body, bodyHash);
      const asyncResult = await validateBodyAsync(body, bodyHash);

      expect(asyncResult).toBe(syncResult);
      expect(asyncResult).toBe(true);
    });

    it("should return false when the body does not match the hash", async () => {
      const body = '{"key":"value"}';
      const wrongHash = getExpectedBodyHash("different body");

      const syncResult = validateBody(body, wrongHash);
      const asyncResult = await validateBodyAsync(body, wrongHash);

      expect(asyncResult).toBe(syncResult);
      expect(asyncResult).toBe(false);
    });
  });

  describe("validateRequestWithBodyAsync()", () => {
    it("should return true for a valid request with body", async () => {
      const body = '{"key":"value"}';
      const bodyHash = getExpectedBodyHash(body);
      const url = `https://example.com/path?bodySHA256=${encodeURIComponent(bodyHash)}`;
      const signature = getExpectedTwilioSignature(authToken, url, {});

      const syncResult = validateRequestWithBody(authToken, signature, url, body);
      const asyncResult = await validateRequestWithBodyAsync(authToken, signature, url, body);

      expect(asyncResult).toBe(syncResult);
      expect(asyncResult).toBe(true);
    });

    it("should return false when the body does not match", async () => {
      const body = '{"key":"value"}';
      const bodyHash = getExpectedBodyHash("different body");
      const url = `https://example.com/path?bodySHA256=${encodeURIComponent(bodyHash)}`;
      const signature = getExpectedTwilioSignature(authToken, url, {});

      const asyncResult = await validateRequestWithBodyAsync(authToken, signature, url, body);

      expect(asyncResult).toBe(false);
    });
  });

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
      const expected = getExpectedTwilioSignature(authToken, url, params);

      const result = await edge.getExpectedTwilioSignatureAsync(
        authToken,
        url,
        params
      );
      expect(result).toBe(expected);
    });

    it("validateRequestAsync correctly validates a signed request", async () => {
      const url = "https://example.com/path?test=param";
      const params = { foo: "bar" };
      const signature = getExpectedTwilioSignature(authToken, url, params);

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
