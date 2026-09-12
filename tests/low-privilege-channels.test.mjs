/*
 * Defences for a socket whose holder is hostile: a channel that may carry no
 * payload, tickets that cannot be replayed, and a budget on the pre-auth
 * connect path.
 *
 * The threat model is a *signed-in* low-privilege user — they hold a valid
 * ticket for their own scope, they can read the whole client bundle, and they
 * will replay frames by hand. Each property here closes a way that user could
 * reach data or work that their scope does not entitle them to, without
 * relying on any app-side call site getting it right.
 *
 * Runs against the built `dist/` output, like the other suites here.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY ??= "test-root-secret";

const { startSessionServer } = await import("../dist/server.js");
const { signWsTicket, ticketSubprotocol } = await import("../dist/common.js");
const { WebSocket } = await import("ws");

const PORT = 28481;
const URL = `ws://127.0.0.1:${PORT}/`;
const PING_CHANNEL = "students";
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

/** Opens a socket on an explicit ticket, resolved once OPEN. */
function open(ticket) {
    const socket = new WebSocket(URL, ticketSubprotocol(ticket));
    return new Promise((resolve, reject) => {
        socket.once("open", () => resolve(socket));
        socket.once("error", reject);
    });
}

/** Opens a socket carrying a freshly minted ticket for `userId` at `scope`. */
function connect(userId, scope) {
    return open(signWsTicket(userId, scope));
}

/** Collects every frame a socket receives. */
function collect(socket) {
    const frames = [];
    socket.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
    return frames;
}

/** Resolves with the socket's close code, or `"never closed"` on timeout. */
function closeCode(socket, timeoutMs = 2000) {
    return Promise.race([
        new Promise((resolve) => socket.once("close", resolve)),
        new Promise((resolve) =>
            setTimeout(() => resolve("never closed"), timeoutMs),
        ),
    ]);
}

describe("payload-free sync objects", () => {
    let server;
    const sockets = [];

    before(async () => {
        server = startSessionServer({
            port: PORT,
            host: "127.0.0.1",
            payloadFreeSyncObjects: [PING_CHANNEL],
            canRegisterSession: ({ scope }) => scope !== "student",
            canListenToSyncObject: ({ scope }, syncObjectId) =>
                scope === "student" ? syncObjectId === PING_CHANNEL : true,
        });
        await new Promise((r) => server.wss.once("listening", r));
    });

    after(() => {
        for (const socket of sockets) socket.close();
        server.close();
    });

    const track = (socket) => (sockets.push(socket), socket);

    /** Subscribes `socket` to `syncObjectId` and returns its frame log. */
    async function listen(socket, syncObjectId) {
        const frames = collect(socket);
        socket.send(
            JSON.stringify({ type: "register-sync-provider", syncObjectId }),
        );
        await settle();
        return frames;
    }

    it("strips the payload from a targeted dispatch", async () => {
        const student = track(await connect("student-1", "student"));
        const frames = await listen(student, PING_CHANNEL);

        // The app-side regression this exists for: a caller that passes real
        // data alongside the low-privilege target.
        server.dispatchToSyncObjectListeners("refresh", PING_CHANNEL, {
            staffOnly: "secret",
        });
        await settle();

        assert.equal(frames.length, 1);
        assert.equal(frames[0].type, "refresh");
        assert.equal(frames[0].target, PING_CHANNEL);
        assert.equal(frames[0].data, undefined);
    });

    it("strips it when the channel arrives inside a targets array", async () => {
        const student = track(await connect("student-2", "student"));
        const staff = track(await connect("staff-2", "staff"));
        const studentFrames = await listen(student, PING_CHANNEL);
        const staffFrames = await listen(staff, "staff-channel");

        // Same broadcast, two targets: the privileged channel keeps its
        // payload, the payload-free one does not.
        server.dispatchMessageToEveryone(
            "refresh",
            [PING_CHANNEL, "staff-channel"],
            { staffOnly: "secret" },
        );
        await settle();

        assert.equal(studentFrames.length, 1);
        assert.equal(studentFrames[0].data, undefined);
        assert.equal(staffFrames.length, 1);
        assert.equal(staffFrames[0].data.staffOnly, "secret");
    });

    it("strips it on a server-sender frame too", async () => {
        const { getWsAuthKey } = await import("../dist/common.js");
        const student = track(await connect("student-3", "student"));
        const frames = await listen(student, PING_CHANNEL);

        // The path a compromised or buggy app server would take.
        const sender = track(await connect("server", "staff"));
        sender.send(
            JSON.stringify({
                sender: "server",
                authKey: getWsAuthKey(),
                type: "refresh",
                targets: PING_CHANNEL,
                data: { staffOnly: "secret" },
            }),
        );
        await settle();

        assert.equal(frames.length, 1);
        assert.equal(frames[0].data, undefined);
    });

    it("leaves undeclared sync objects carrying their payload", async () => {
        const staff = track(await connect("staff-4", "staff"));
        const frames = await listen(staff, "staff-only");

        server.dispatchToSyncObjectListeners("update", "staff-only", {
            value: 7,
        });
        await settle();

        assert.equal(frames.at(-1).data.value, 7);
    });
});

describe("single-use tickets", () => {
    let server;
    const sockets = [];
    const PORT_SINGLE_USE = 28482;
    const URL_SINGLE_USE = `ws://127.0.0.1:${PORT_SINGLE_USE}/`;

    function openAt(ticket) {
        const socket = new WebSocket(
            URL_SINGLE_USE,
            ticketSubprotocol(ticket),
        );
        return socket;
    }

    before(async () => {
        server = startSessionServer({
            port: PORT_SINGLE_USE,
            host: "127.0.0.1",
            singleUseTickets: true,
        });
        await new Promise((r) => server.wss.once("listening", r));
    });

    after(() => {
        for (const socket of sockets) socket.close();
        server.close();
    });

    it("refuses a ticket that already opened a socket", async () => {
        const ticket = signWsTicket("victim", "staff");

        const first = openAt(ticket);
        sockets.push(first);
        await new Promise((resolve) => first.once("open", resolve));

        // The attack: the same ticket, observed and replayed inside its TTL,
        // would otherwise mint a second socket carrying the victim's scope.
        const replay = openAt(ticket);
        sockets.push(replay);
        assert.equal(await closeCode(replay), 1008);
    });

    it("still accepts a freshly minted ticket for the same user", async () => {
        const socket = openAt(signWsTicket("victim", "staff"));
        sockets.push(socket);
        await new Promise((resolve, reject) => {
            socket.once("open", resolve);
            socket.once("close", () => reject(new Error("was refused")));
        });
    });

    it("refuses a replay even after the first socket closed", async () => {
        const ticket = signWsTicket("victim-2", "staff");

        const first = openAt(ticket);
        await new Promise((resolve) => first.once("open", resolve));
        first.close();
        await settle();

        // Closing the socket must not release the ticket: otherwise an
        // attacker just waits for the tab to close.
        const replay = openAt(ticket);
        sockets.push(replay);
        assert.equal(await closeCode(replay), 1008);
    });
});

describe("connect rate limit", () => {
    let server;
    const sockets = [];
    const PORT_BUDGET = 28483;
    const URL_BUDGET = `ws://127.0.0.1:${PORT_BUDGET}/`;

    before(async () => {
        server = startSessionServer({
            port: PORT_BUDGET,
            host: "127.0.0.1",
            maxConnectsPerWindow: 3,
            connectWindowMs: 60_000,
        });
        await new Promise((r) => server.wss.once("listening", r));
    });

    after(() => {
        for (const socket of sockets) socket.close();
        server.close();
    });

    it("closes connects past the per-address budget", async () => {
        for (let attempt = 0; attempt < 3; attempt += 1) {
            const socket = new WebSocket(
                URL_BUDGET,
                ticketSubprotocol(signWsTicket(`u${attempt}`, "staff")),
            );
            sockets.push(socket);
            await new Promise((resolve) => socket.once("open", resolve));
        }

        const overBudget = new WebSocket(
            URL_BUDGET,
            ticketSubprotocol(signWsTicket("u-over", "staff")),
        );
        sockets.push(overBudget);
        assert.equal(await closeCode(overBudget), 1013);
    });

    it("survives an upgrade request with no socket on it", async () => {
        // Consumers that drive the core over a test double or a custom
        // transport hand it a bare request object. The budget runs before
        // everything else on the connect path, so assuming `req.socket` here
        // took their whole socket handling down.
        const fake = {
            protocol: "",
            readyState: 1,
            bufferedAmount: 0,
            on() {},
            once() {},
            ping() {},
            send() {},
            close() {},
            terminate() {},
        };
        assert.doesNotThrow(() =>
            server.wss.emit("connection", fake, {
                url: `/?ticket=${encodeURIComponent(
                    signWsTicket("no-socket", "staff"),
                )}`,
            }),
        );
    });

    it("spends budget on unticketed connects too", async () => {
        // The point of budgeting before ticket verification: an attacker with
        // no valid ticket must not get unlimited free handshakes.
        const unticketed = new WebSocket(URL_BUDGET);
        sockets.push(unticketed);
        const code = await closeCode(unticketed);
        assert.ok(code === 1013 || code === 1008);
    });
});
