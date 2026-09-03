/*
 * Unit tests for the HMAC ticket auth and env-derived config in common.ts,
 * plus the wire-protocol constants in protocol.ts. Runs against the built
 * `dist/` output, so `npm run build` first.
 */

import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY ??= "test-root-secret";

const commonModulePath = "../dist/common.js";

describe("common: ticket auth", () => {
    it("round-trips a signed ticket back to the original userId", async () => {
        const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
        const ticket = signWsTicket("user-42");
        assert.equal(verifyWsTicket(ticket), "user-42");
    });

    describe("expiry", () => {
        let originalNow;

        beforeEach(() => {
            originalNow = Date.now;
        });

        afterEach(() => {
            Date.now = originalNow;
        });

        it("rejects a ticket once its TTL has elapsed", async () => {
            const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
            const base = 1_700_000_000_000;
            Date.now = () => base;
            const ticket = signWsTicket("user-1");

            Date.now = () => base + 30_001; // 30s TTL, one ms past expiry.
            assert.equal(verifyWsTicket(ticket), null);
        });

        it("still accepts a ticket at exactly its expiry boundary", async () => {
            const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
            const base = 1_700_000_000_000;
            Date.now = () => base;
            const ticket = signWsTicket("user-1");

            // expiresAt = base + 30000; verifyWsTicket rejects only when
            // Date.now() > expiresAt, so "now === expiresAt" must still pass.
            Date.now = () => base + 30_000;
            assert.equal(verifyWsTicket(ticket), "user-1");
        });
    });

    describe("tampering", () => {
        it("rejects a ticket with a tampered userId", async () => {
            const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
            const ticket = signWsTicket("user-1");
            const [, expiresAt, signature] = ticket.split(".");
            const tampered = `user-2.${expiresAt}.${signature}`;
            assert.equal(verifyWsTicket(tampered), null);
        });

        it("rejects a ticket with a tampered expiry", async () => {
            const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
            const ticket = signWsTicket("user-1");
            const [userId, expiresAt, signature] = ticket.split(".");
            const tampered = `${userId}.${Number(expiresAt) + 60_000}.${signature}`;
            assert.equal(verifyWsTicket(tampered), null);
        });

        it("rejects a ticket with a truncated signature", async () => {
            const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
            const ticket = signWsTicket("user-1");
            assert.equal(verifyWsTicket(ticket.slice(0, -4)), null);
        });

        it("rejects a ticket with garbage in place of the signature", async () => {
            const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
            const ticket = signWsTicket("user-1");
            const [userId, expiresAt] = ticket.split(".");
            assert.equal(verifyWsTicket(`${userId}.${expiresAt}.not-hex-at-all`), null);
        });
    });

    describe("malformed input", () => {
        it("rejects tickets with the wrong number of dot-separated parts", async () => {
            const { verifyWsTicket } = await import(commonModulePath);
            assert.equal(verifyWsTicket(""), null);
            assert.equal(verifyWsTicket("just-one-part"), null);
            assert.equal(verifyWsTicket("a.b"), null);
            assert.equal(verifyWsTicket("a.b.c.d"), null);
        });

        it("rejects an empty userId segment", async () => {
            const { verifyWsTicket } = await import(commonModulePath);
            assert.equal(verifyWsTicket(".9999999999999.abcd"), null);
        });

        it("rejects a non-numeric expiry", async () => {
            const { verifyWsTicket } = await import(commonModulePath);
            assert.equal(verifyWsTicket("user-1.not-a-number.abcd"), null);
        });

        it("rejects a non-hex signature without throwing (guards timingSafeEqual)", async () => {
            const { signWsTicket, verifyWsTicket } = await import(commonModulePath);
            const ticket = signWsTicket("user-1");
            const [userId, expiresAt] = ticket.split(".");
            // Odd-length / non-hex string would make Buffer.from(..., "hex")
            // produce a shorter buffer than the digest, which used to throw
            // out of timingSafeEqual instead of failing closed.
            assert.doesNotThrow(() =>
                verifyWsTicket(`${userId}.${expiresAt}.zz`),
            );
            assert.equal(verifyWsTicket(`${userId}.${expiresAt}.zz`), null);
        });
    });

    describe("key rotation", () => {
        it("rejects a ticket signed under a different root secret", async () => {
            const originalKey = process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY;
            try {
                const { signWsTicket, verifyWsTicket } = await import(commonModulePath);

                process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY = "key-one";
                const ticket = signWsTicket("user-1");

                process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY = "key-two";
                assert.equal(verifyWsTicket(ticket), null);
            } finally {
                process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY = originalKey;
            }
        });
    });

    describe("getWsAuthKey", () => {
        it("throws when the root secret env var is unset", async () => {
            const originalKey = process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY;
            try {
                const { getWsAuthKey } = await import(commonModulePath);
                delete process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY;
                assert.throws(() => getWsAuthKey());
            } finally {
                process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY = originalKey;
            }
        });

        it("returns a stable value once the env var is set", async () => {
            const { getWsAuthKey } = await import(commonModulePath);
            const a = getWsAuthKey();
            const b = getWsAuthKey();
            assert.equal(a, b);
            assert.equal(typeof a, "string");
        });
    });
});

describe("common: connection-string derivation", () => {
    // These exports are computed once at module load from env vars, so each
    // case re-imports the module fresh (cache-busted) after setting env.
    const envKeys = [
        "WEBSOCKET_SESSION_SERVER_PORT",
        "WEBSOCKET_SESSION_SERVER_HOST",
        "NODE_ENV",
    ];
    let savedEnv;

    beforeEach(() => {
        savedEnv = Object.fromEntries(envKeys.map((k) => [k, process.env[k]]));
    });

    afterEach(() => {
        for (const k of envKeys) {
            if (savedEnv[k] === undefined) delete process.env[k];
            else process.env[k] = savedEnv[k];
        }
    });

    async function freshImport() {
        return import(`${commonModulePath}?t=${Date.now()}-${Math.random()}`);
    }

    it("defaults to wss on port 443 with no port suffix", async () => {
        delete process.env.WEBSOCKET_SESSION_SERVER_PORT;
        process.env.WEBSOCKET_SESSION_SERVER_HOST = "example.com";
        delete process.env.NODE_ENV;
        const mod = await freshImport();
        assert.equal(mod.WEBSOCKET_SESSION_SERVER_PORT, 443);
        assert.equal(mod.WEBSOCKET_PROTOCOL, "wss");
        assert.equal(mod.WEBSOCKET_PORT_SUFFIX, "");
        assert.equal(
            mod.NEXT_PUBLIC_WEBSOCKET_SESSION_SERVER_CONN_STRING,
            "wss://example.com/ws/",
        );
    });

    it("uses ws and no suffix on port 80", async () => {
        process.env.WEBSOCKET_SESSION_SERVER_PORT = "80";
        process.env.WEBSOCKET_SESSION_SERVER_HOST = "example.com";
        delete process.env.NODE_ENV;
        const mod = await freshImport();
        assert.equal(mod.WEBSOCKET_PROTOCOL, "ws");
        assert.equal(mod.WEBSOCKET_PORT_SUFFIX, "");
        assert.equal(
            mod.NEXT_PUBLIC_WEBSOCKET_SESSION_SERVER_CONN_STRING,
            "ws://example.com/ws/",
        );
    });

    it("uses ws with an explicit port suffix on a custom port", async () => {
        process.env.WEBSOCKET_SESSION_SERVER_PORT = "28199";
        process.env.WEBSOCKET_SESSION_SERVER_HOST = "127.0.0.1";
        delete process.env.NODE_ENV;
        const mod = await freshImport();
        assert.equal(mod.WEBSOCKET_PROTOCOL, "ws");
        assert.equal(mod.WEBSOCKET_PORT_SUFFIX, ":28199");
        assert.equal(
            mod.NEXT_PUBLIC_WEBSOCKET_SESSION_SERVER_CONN_STRING,
            "ws://127.0.0.1:28199/ws/",
        );
    });

    it("forces wss/secure context when NODE_ENV=production even off port 443", async () => {
        process.env.WEBSOCKET_SESSION_SERVER_PORT = "8443";
        process.env.WEBSOCKET_SESSION_SERVER_HOST = "example.com";
        process.env.NODE_ENV = "production";
        const mod = await freshImport();
        assert.equal(mod.SECURE_CONTEXT_ONLY, true);
        assert.equal(mod.WEBSOCKET_PROTOCOL, "wss");
        assert.equal(mod.WEBSOCKET_PORT_SUFFIX, ":8443");
    });

    it("defaults host to 127.0.0.1 when unset", async () => {
        delete process.env.WEBSOCKET_SESSION_SERVER_HOST;
        delete process.env.WEBSOCKET_SESSION_SERVER_PORT;
        delete process.env.NODE_ENV;
        const mod = await freshImport();
        assert.equal(mod.WEBSOCKET_SESSION_SERVER_HOST, "127.0.0.1");
    });
});

describe("protocol: wire-contract constants", () => {
    it("pins CoreMessageTypes string values", async () => {
        const { CoreMessageTypes } = await import("../dist/protocol.js");
        assert.deepEqual(
            { ...CoreMessageTypes },
            {
                REGISTER_SESSION: "register-session",
                REGISTER_SYNC_PROVIDER: "register-sync-provider",
                SYNC_OBJECT_UPDATE: "sync-object-update",
                DEREGISTER_SYNC_PROVIDER: "deregister-sync-provider",
            },
        );
    });

    it("builds a subprotocol string with the ticket URL-encoded", async () => {
        const { ticketSubprotocol, TICKET_SUBPROTOCOL_PREFIX } = await import(
            "../dist/protocol.js"
        );
        const ticket = "user 1.1234.abcd/ef+gh";
        const result = ticketSubprotocol(ticket);
        assert.ok(result.startsWith(TICKET_SUBPROTOCOL_PREFIX));
        assert.equal(
            result,
            `${TICKET_SUBPROTOCOL_PREFIX}${encodeURIComponent(ticket)}`,
        );
    });
});
