/*
 * Hardening regression tests for the session server core. Runs against the
 * built `dist/` output (the published surface), so `npm run build` first.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY ??= "test-root-secret";

const { startSessionServer } = await import("../dist/server.js");
const { getWsAuthKey, signWsTicket, ticketSubprotocol, verifyWsTicket } =
    await import("../dist/common.js");
const { WebSocket } = await import("ws");

const PORT = 28477;
const URL = `ws://127.0.0.1:${PORT}/`;
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

/**
 * Resolves with the socket's close code, or `"never closed"` if it stays open.
 * Racing against a deadline keeps a missing close a readable assertion failure
 * instead of a hung test run.
 */
function closeCode(socket, timeoutMs = 2000) {
    return Promise.race([
        new Promise((resolve) => socket.once("close", resolve)),
        new Promise((resolve) => setTimeout(() => resolve("never closed"), timeoutMs)),
    ]);
}

/** Opens a ticketed socket and resolves once it is OPEN. */
async function connect(userId, { subprotocol = true } = {}) {
    const ticket = signWsTicket(userId);
    const socket = subprotocol
        ? new WebSocket(URL, ticketSubprotocol(ticket))
        : new WebSocket(`${URL}?ticket=${encodeURIComponent(ticket)}`);
    await new Promise((resolve, reject) => {
        socket.once("open", resolve);
        socket.once("error", reject);
    });
    return socket;
}

describe("session server hardening", () => {
    let server;
    const sockets = [];
    const onClientMessageCalls = [];

    before(async () => {
        server = startSessionServer({
            port: PORT,
            host: "127.0.0.1",
            // Only user "owner" may subscribe to sync objects, so the deny path
            // and the allow path are both exercised.
            canListenToSyncObject: ({ userId }) => userId === "owner",
            validMessageTypes: ["app-custom-type"],
            onClientMessage: (ws, data, dispatch, identity) => {
                onClientMessageCalls.push({ data, identity });
                return true;
            },
        });
        await new Promise((r) => server.wss.once("listening", r));
    });

    after(() => {
        for (const socket of sockets) socket.close();
        server.close();
    });

    const track = (socket) => (sockets.push(socket), socket);

    describe("key derivation (#540.4, #523)", () => {
        it("never puts the root secret on the wire", () => {
            assert.notEqual(getWsAuthKey(), process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY);
        });

        it("round-trips a ticket and rejects a tampered signature", () => {
            const ticket = signWsTicket("user-1");
            assert.equal(verifyWsTicket(ticket), "user-1");
            assert.equal(verifyWsTicket(`${ticket.slice(0, -1)}0`), null);
        });

        it("does not accept the sender key as a ticket", () => {
            // The two subkeys are independent: leaking the cleartext sender key
            // must not let anyone mint a connect ticket.
            assert.equal(verifyWsTicket(getWsAuthKey()), null);
        });
    });

    describe("connect auth", () => {
        it("accepts a ticket presented as a subprotocol (#540.3)", async () => {
            const socket = track(await connect("user-1"));
            assert.equal(socket.readyState, WebSocket.OPEN);
        });

        it("still accepts a ticket in the query string", async () => {
            const socket = track(await connect("user-1", { subprotocol: false }));
            assert.equal(socket.readyState, WebSocket.OPEN);
        });

        it("rejects an unticketed connect", async () => {
            const socket = new WebSocket(URL);
            const outcome = await new Promise((resolve) => {
                socket.once("close", resolve);
                socket.once("error", () => resolve("error"));
            });
            assert.ok(outcome === 1008 || outcome === "error");
        });
    });

    describe("malformed frames (#511)", () => {
        it("survives null, array and primitive payloads", async () => {
            const socket = track(await connect("user-1"));
            socket.send("null");
            socket.send("[1,2,3]");
            socket.send('"a string"');
            socket.send("not json at all");
            await settle();
            // Before the shape guard, `null` threw out of the message handler
            // and killed the process for every connected user.
            assert.equal(socket.readyState, WebSocket.OPEN);
        });
    });

    describe("sync-object subscriptions (#540.1)", () => {
        it("denies a subscription the app does not authorize", async () => {
            const socket = track(await connect("intruder"));
            socket.send(
                JSON.stringify({ type: "register-sync-provider", syncObjectId: "obj-1" }),
            );
            await settle();

            let received = false;
            socket.on("message", () => (received = true));
            server.dispatchToSyncObjectListeners("sync-object-update", "obj-1", { x: 1 });
            await settle();
            assert.equal(received, false);
        });

        it("delivers to an authorized subscriber", async () => {
            const socket = track(await connect("owner"));
            socket.send(
                JSON.stringify({ type: "register-sync-provider", syncObjectId: "obj-2" }),
            );
            await settle();

            const delivered = new Promise((resolve) =>
                socket.once("message", (raw) => resolve(JSON.parse(raw.toString()))),
            );
            server.dispatchToSyncObjectListeners("sync-object-update", "obj-2", { x: 1 });
            const message = await delivered;
            assert.equal(message.target, "obj-2");
            assert.deepEqual(message.data, { x: 1 });
        });

        it("stops delivering after deregister-sync-provider (#525)", async () => {
            const socket = track(await connect("owner"));
            socket.send(
                JSON.stringify({ type: "register-sync-provider", syncObjectId: "obj-4" }),
            );
            await settle();
            socket.send(
                JSON.stringify({ type: "deregister-sync-provider", syncObjectId: "obj-4" }),
            );
            await settle();

            let received = false;
            socket.on("message", () => (received = true));
            server.dispatchToSyncObjectListeners("sync-object-update", "obj-4", { x: 1 });
            await settle();
            assert.equal(received, false);
        });

        it("sends exactly one copy when a subscriber is also a session (#540.6)", async () => {
            const socket = track(await connect("owner"));
            socket.send(JSON.stringify({ type: "register-session", initiatorKey: "k1" }));
            socket.send(
                JSON.stringify({ type: "register-sync-provider", syncObjectId: "obj-3" }),
            );
            await settle();

            let count = 0;
            socket.on("message", () => (count += 1));
            server.dispatchMessageToEveryone("sync-object-update", "obj-3", { x: 1 });
            await settle();
            assert.equal(count, 1);
        });
    });

    describe("rate limiting (#524)", () => {
        it("closes a socket that floods past its budget", async () => {
            const socket = track(await connect("flooder"));
            const closed = closeCode(socket);
            for (let i = 0; i < 400; i++) {
                socket.send(JSON.stringify({ type: "register-session", initiatorKey: "k" }));
            }
            assert.equal(await closed, 1008);
        });

        it("stays within budget for a normal client", async () => {
            const socket = track(await connect("polite"));
            let closed = false;
            socket.on("close", () => (closed = true));
            for (let i = 0; i < 20; i++) {
                socket.send(JSON.stringify({ type: "register-session", initiatorKey: "k" }));
            }
            await settle();
            assert.equal(closed, false);
        });
    });

    describe("payload limit (#524)", () => {
        it("rejects a frame larger than maxPayload instead of buffering it", async () => {
            const socket = track(await connect("fat-frame"));
            const closed = closeCode(socket);

            // ws defaults to ~100 MiB; the explicit cap is 64 KiB. A single
            // oversized frame previously bought an attacker that much memory.
            socket.send(
                JSON.stringify({ type: "register-session", initiatorKey: "x".repeat(100_000) }),
            );

            // 1009 = message too big.
            assert.equal(await closed, 1009);
        });

        it("accepts a frame just under the cap", async () => {
            const socket = track(await connect("slim-frame"));
            let closed = false;
            socket.on("close", () => (closed = true));
            socket.send(
                JSON.stringify({ type: "register-session", initiatorKey: "x".repeat(1_000) }),
            );
            await settle();
            assert.equal(closed, false);
        });
    });

    describe("slow consumers (#524)", () => {
        it("drops a recipient whose send buffer is over budget", async () => {
            // A tiny buffered-bytes budget stands in for a consumer that has
            // stopped draining: without this the fan-out queues into it without
            // bound, which full-document broadcasts made worse.
            const strictPort = PORT + 1;
            const strict = startSessionServer({
                port: strictPort,
                host: "127.0.0.1",
                maxBufferedBytes: 0,
            });
            await new Promise((r) => strict.wss.once("listening", r));

            const socket = new WebSocket(
                `ws://127.0.0.1:${strictPort}/`,
                ticketSubprotocol(signWsTicket("slow")),
            );
            await new Promise((r) => socket.once("open", r));
            socket.send(JSON.stringify({ type: "register-session", initiatorKey: "k" }));
            await settle();

            try {
                const closed = closeCode(socket);
                // Large enough that bufferedAmount is non-zero when the next
                // send is considered.
                for (let i = 0; i < 50; i++) {
                    strict.dispatchMessageToEveryone("sync-object-update", undefined, {
                        blob: "y".repeat(20_000),
                    });
                }

                // 1013 = try again later.
                assert.equal(await closed, 1013);
            } finally {
                // Must run even when the assertion fails, or the leaked
                // listener keeps the test runner alive forever.
                socket.close();
                strict.close();
            }
        });
    });

    describe("message protocol handling (#5)", () => {
        it("drops frames with an unknown type", async () => {
            const socket = track(await connect("user-1"));
            let received = false;
            socket.on("message", () => (received = true));
            socket.send(JSON.stringify({ type: "totally-unknown-type" }));
            await settle();
            assert.equal(received, false);
            assert.equal(socket.readyState, WebSocket.OPEN);
        });

        it("routes app-supplied validMessageTypes to onClientMessage with the ticket identity", async () => {
            onClientMessageCalls.length = 0;
            const socket = track(await connect("user-app-hook"));
            socket.send(
                JSON.stringify({ type: "app-custom-type", payload: "hello" }),
            );
            await settle();
            assert.equal(onClientMessageCalls.length, 1);
            assert.equal(onClientMessageCalls[0].data.type, "app-custom-type");
            assert.equal(onClientMessageCalls[0].data.payload, "hello");
            assert.equal(onClientMessageCalls[0].identity.userId, "user-app-hook");
        });

        it("registers the session before dispatching to onClientMessage, gating broadcast eligibility", async () => {
            const socket = track(await connect("user-gate"));
            let received = false;
            socket.on("message", () => (received = true));

            // Not registered yet: dispatchMessageToEveryone must skip it.
            server.dispatchMessageToEveryone("sync-object-update", undefined, { x: 1 });
            await settle();
            assert.equal(received, false);

            socket.send(JSON.stringify({ type: "register-session", initiatorKey: "gate-key" }));
            await settle();

            server.dispatchMessageToEveryone("sync-object-update", undefined, { x: 1 });
            await settle();
            assert.equal(received, true);
        });
    });

    describe("server-originated messages (#5)", () => {
        it("rejects a server frame with a missing authKey and dispatches nothing", async () => {
            const socket = track(await connect("user-1"));
            socket.send(JSON.stringify({ type: "register-session", initiatorKey: "auth-missing" }));
            await settle();

            let received = false;
            socket.on("message", () => (received = true));
            const raw = JSON.stringify({
                sender: "server",
                type: "sync-object-update",
                data: { x: 1 },
            });
            for (const client of server.wss.clients) client.emit("message", Buffer.from(raw));
            await settle();
            assert.equal(received, false);
        });

        it("rejects a server frame with a wrong authKey and dispatches nothing", async () => {
            const socket = track(await connect("user-wrong-key"));
            socket.send(JSON.stringify({ type: "register-session", initiatorKey: "wrong-key" }));
            await settle();

            let received = false;
            socket.on("message", () => (received = true));
            const raw = JSON.stringify({
                sender: "server",
                type: "sync-object-update",
                authKey: "not-the-real-key",
                data: { x: 1 },
            });
            for (const client of server.wss.clients) client.emit("message", Buffer.from(raw));
            await settle();
            assert.equal(received, false);
        });

        it("dispatches to everyone with the correct authKey and strips it from the forwarded frame", async () => {
            const socket = track(await connect("user-correct-key"));
            socket.send(JSON.stringify({ type: "register-session", initiatorKey: "correct-key" }));
            await settle();

            const delivered = new Promise((resolve) =>
                socket.once("message", (raw) => resolve(JSON.parse(raw.toString()))),
            );
            const raw = JSON.stringify({
                sender: "server",
                type: "sync-object-update",
                authKey: getWsAuthKey(),
                data: { x: 1 },
            });
            for (const client of server.wss.clients) client.emit("message", Buffer.from(raw));
            const message = await delivered;
            assert.equal(message.type, "sync-object-update");
            assert.deepEqual(message.data, { x: 1 });
            assert.equal("authKey" in message, false);
        });
    });

    describe("error paths (#5)", () => {
        it("does not throw dispatching to a sync object with no listeners", () => {
            assert.doesNotThrow(() =>
                server.dispatchToSyncObjectListeners("sync-object-update", "nobody-listening", {
                    x: 1,
                }),
            );
        });

        it("cleans up both registries on disconnect", async () => {
            const socket = await connect("owner");
            socket.send(JSON.stringify({ type: "register-session", initiatorKey: "cleanup-key" }));
            socket.send(
                JSON.stringify({ type: "register-sync-provider", syncObjectId: "cleanup-obj" }),
            );
            await settle();

            const closed = closeCode(socket);
            socket.close();
            await closed;
            await settle();

            // No listener left for the object; dispatch is a documented no-op,
            // not a throw against a stale registry entry.
            assert.doesNotThrow(() =>
                server.dispatchToSyncObjectListeners("sync-object-update", "cleanup-obj", {}),
            );
        });
    });

    describe("shutdown", () => {
        it("close() closes all live sessions with 1001 and clears the heartbeat timer", async () => {
            const closePort = PORT + 2;
            const closeServer = startSessionServer({ port: closePort, host: "127.0.0.1" });
            await new Promise((r) => closeServer.wss.once("listening", r));

            const socket = new WebSocket(
                `ws://127.0.0.1:${closePort}/`,
                ticketSubprotocol(signWsTicket("shutdown-user")),
            );
            await new Promise((r) => socket.once("open", r));

            const closed = closeCode(socket);
            closeServer.close();
            assert.equal(await closed, 1001);
        });
    });
});
