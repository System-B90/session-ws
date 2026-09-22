/*
 * Heartbeat-sweep coverage for the session server (#5). Kept out of
 * server.test.mjs because these need their own server with a deliberately
 * tiny `heartbeatIntervalMs`, and a short sweep would make the other suite's
 * long-lived sockets flaky. Runs against built `dist/`.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY ??= "test-root-secret";

const { startSessionServer } = await import("../dist/server.js");
const { signWsTicket, ticketSubprotocol } = await import("../dist/common.js");
const { WebSocket } = await import("ws");

const PORT = 28611;
const URL = `ws://127.0.0.1:${PORT}/`;
// Two sweeps kill a silent socket: the first pings and clears isAlive, the
// second sees it still clear and terminates. Everything below is timed in
// multiples of this.
const HEARTBEAT_MS = 120;

const settle = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Opens a ticketed socket. `autoPong: false` makes the `ws` client behave like
 * a crashed tab or a half-open TCP connection: the socket is still writable,
 * so only the missing pong reveals that it is dead.
 */
async function connect(userId, { autoPong = true } = {}) {
    const socket = new WebSocket(URL, ticketSubprotocol(signWsTicket(userId)), {
        autoPong,
    });
    await new Promise((resolve, reject) => {
        socket.once("open", resolve);
        socket.once("error", reject);
    });
    return socket;
}

/** Resolves with the close code, or `"never closed"` past the deadline. */
function closeCode(socket, timeoutMs = HEARTBEAT_MS * 8) {
    return Promise.race([
        new Promise((resolve) => socket.once("close", resolve)),
        new Promise((resolve) =>
            setTimeout(() => resolve("never closed"), timeoutMs),
        ),
    ]);
}

/** Collects every frame a socket receives, for fan-out assertions. */
function collect(socket) {
    const frames = [];
    socket.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
    return frames;
}

describe("heartbeat sweep (#5)", () => {
    let server;
    const sockets = [];

    before(async () => {
        server = startSessionServer({
            port: PORT,
            host: "127.0.0.1",
            heartbeatIntervalMs: HEARTBEAT_MS,
            canListenToSyncObject: () => true,
        });
        await new Promise((r) => server.wss.once("listening", r));
    });

    after(() => {
        for (const socket of sockets) socket.terminate();
        server.close();
    });

    const track = (socket) => (sockets.push(socket), socket);

    it("terminates a client that never pongs", async () => {
        const socket = track(await connect("silent", { autoPong: false }));

        const closed = closeCode(socket);

        // `terminate()` kills the socket without a close handshake, so the
        // client sees an abnormal closure rather than a protocol code.
        assert.notEqual(await closed, "never closed");
        assert.equal(socket.readyState, WebSocket.CLOSED);
    });

    it("leaves a responsive client alive across several sweeps", async () => {
        const socket = track(await connect("responsive"));

        await settle(HEARTBEAT_MS * 5);

        assert.equal(
            socket.readyState,
            WebSocket.OPEN,
            "a ponging client must survive repeated sweeps",
        );
    });

    it("removes a terminated client from the broadcast registry", async () => {
        const silent = track(await connect("silent-broadcast", { autoPong: false }));
        const survivor = track(await connect("survivor"));
        silent.send(
            JSON.stringify({ type: "register-session", initiatorKey: "silent-key" }),
        );
        survivor.send(
            JSON.stringify({ type: "register-session", initiatorKey: "survivor-key" }),
        );
        await settle(HEARTBEAT_MS);

        await closeCode(silent);
        // Let the "close" handler run its registry cleanup.
        await settle(HEARTBEAT_MS);

        const frames = collect(survivor);
        assert.doesNotThrow(() =>
            server.dispatchMessageToEveryone("app-message", { n: 1 }),
        );
        await settle(HEARTBEAT_MS);

        // The dispatch walked the registry without throwing on the dead entry,
        // and the live socket still got its frame.
        assert.equal(frames.length, 1);
        assert.equal(frames[0].type, "app-message");
        assert.equal(silent.readyState, WebSocket.CLOSED);
        assert.equal(survivor.readyState, WebSocket.OPEN);
    });

    it("removes a terminated client from the sync-object registry", async () => {
        const silent = track(await connect("silent-sync", { autoPong: false }));
        silent.send(
            JSON.stringify({ type: "register-session", initiatorKey: "sync-key" }),
        );
        silent.send(
            JSON.stringify({
                type: "register-sync-provider",
                syncObjectId: "heartbeat-obj",
            }),
        );
        await settle(HEARTBEAT_MS);

        await closeCode(silent);
        await settle(HEARTBEAT_MS);

        // The reverse index entry is gone, so this is the documented
        // no-listeners no-op rather than a throw against a stale socket.
        assert.doesNotThrow(() =>
            server.dispatchToSyncObjectListeners(
                "sync-object-update",
                "heartbeat-obj",
                { x: 1 },
            ),
        );
        assert.equal(silent.readyState, WebSocket.CLOSED);
    });

    it("close() stops the sweep so no timer outlives the server", async () => {
        const port = PORT + 1;
        const other = startSessionServer({
            port,
            host: "127.0.0.1",
            heartbeatIntervalMs: HEARTBEAT_MS,
        });
        await new Promise((r) => other.wss.once("listening", r));

        const socket = new WebSocket(
            `ws://127.0.0.1:${port}/`,
            ticketSubprotocol(signWsTicket("timer-user")),
            { autoPong: false },
        );
        await new Promise((r) => socket.once("open", r));

        other.close();
        // Well past the point where a surviving interval would have fired; a
        // leaked timer would keep sweeping a closed server's registry.
        await settle(HEARTBEAT_MS * 4);

        assert.equal(socket.readyState, WebSocket.CLOSED);
    });
});
