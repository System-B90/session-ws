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

    before(async () => {
        server = startSessionServer({
            port: PORT,
            host: "127.0.0.1",
            // Only user "owner" may subscribe to sync objects, so the deny path
            // and the allow path are both exercised.
            canListenToSyncObject: ({ userId }) => userId === "owner",
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
            const closed = new Promise((resolve) => socket.once("close", resolve));
            for (let i = 0; i < 400; i++) {
                socket.send(JSON.stringify({ type: "register-session", initiatorKey: "k" }));
            }
            assert.equal(await closed, 1008);
        });
    });
});
