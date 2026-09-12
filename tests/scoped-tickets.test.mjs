/*
 * Scoped tickets and the session-registration gate.
 *
 * These exist for apps whose sockets do not all hold the same read rights —
 * a staff/student split, an admin/viewer split, a per-tenant split. Two
 * properties carry that: the scope is signed (so the browser cannot pick its
 * own privilege), and a socket the app refuses to register as a session is
 * excluded from the untargeted fan-out (so "broadcast to everyone" is not a
 * way around the app's own gate).
 *
 * Runs against the built `dist/` output, like the other suites here.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY ??= "test-root-secret";

const { startSessionServer } = await import("../dist/server.js");
const { signWsTicket, ticketSubprotocol, verifyWsTicket, verifyWsTicketIdentity } =
    await import("../dist/common.js");
const { WebSocket } = await import("ws");

const PORT = 28479;
const URL = `ws://127.0.0.1:${PORT}/`;
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

/** Opens a socket carrying a ticket for `userId` at `scope`, resolved once OPEN. */
async function connect(userId, scope) {
    const socket = new WebSocket(URL, ticketSubprotocol(signWsTicket(userId, scope)));
    await new Promise((resolve, reject) => {
        socket.once("open", resolve);
        socket.once("error", reject);
    });
    return socket;
}

/** Collects every frame a socket receives until `settle`. */
function collect(socket) {
    const frames = [];
    socket.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
    return frames;
}

describe("scoped tickets", () => {
    it("round-trips a scope", () => {
        const identity = verifyWsTicketIdentity(signWsTicket("u1", "staff"));
        assert.equal(identity.userId, "u1");
        assert.equal(identity.scope, "staff");
    });

    it("still accepts an unscoped ticket, reporting no scope", () => {
        const identity = verifyWsTicketIdentity(signWsTicket("u1"));
        assert.equal(identity.userId, "u1");
        assert.equal(identity.scope, undefined);
    });

    it("mints a distinct ticket even twice in the same millisecond", () => {
        // A ticket used to be a pure function of (userId, scope, expiry in ms),
        // so two minted in the same tick were byte-identical — which makes any
        // single-use check refuse the legitimate second socket (two tabs, or a
        // reconnecting sender) as if it were a replay.
        const tickets = new Set();
        for (let i = 0; i < 50; i += 1) {
            tickets.add(signWsTicket("u1", "staff"));
        }
        assert.equal(tickets.size, 50);

        // …and every one of them still verifies to the same identity.
        for (const ticket of tickets) {
            const identity = verifyWsTicketIdentity(ticket);
            assert.equal(identity.userId, "u1");
            assert.equal(identity.scope, "staff");
        }
    });

    it("round-trips an unscoped ticket through the current 5-part form", () => {
        // The empty scope field keeps the field count fixed; it must read back
        // as "no scope", not as a scope named "".
        const identity = verifyWsTicketIdentity(signWsTicket("u1"));
        assert.equal(identity.scope, undefined);
        assert.equal(identity.userId, "u1");
    });

    it("reports the ticket expiry and signature for replay defence", () => {
        const ticket = signWsTicket("u1", "staff");
        const identity = verifyWsTicketIdentity(ticket);
        assert.equal(identity.signature, ticket.split(".").at(-1));
        assert.ok(identity.expiresAt > Date.now());
    });

    it("keeps verifyWsTicket working for callers that ignore scope", () => {
        assert.equal(verifyWsTicket(signWsTicket("u1", "staff")), "u1");
        assert.equal(verifyWsTicket(signWsTicket("u1")), "u1");
    });

    it("rejects a ticket whose scope was edited after signing", () => {
        const ticket = signWsTicket("u1", "student");
        const [userId, expiresAt, , signature] = ticket.split(".");
        const forged = `${userId}.${expiresAt}.staff.${signature}`;

        assert.equal(verifyWsTicketIdentity(forged), null);
    });

    it("rejects a scope appended to an unscoped ticket", () => {
        const [userId, expiresAt, signature] = signWsTicket("u1").split(".");

        assert.equal(
            verifyWsTicketIdentity(`${userId}.${expiresAt}.staff.${signature}`),
            null,
        );
    });

    it("refuses to sign a dot-bearing user id or scope, which would be ambiguous", () => {
        assert.throws(() => signWsTicket("a.b"));
        assert.throws(() => signWsTicket("u1", "a.b"));
        assert.throws(() => signWsTicket("u1", ""));
    });
});

describe("session registration gate", () => {
    let server;
    const sockets = [];

    before(async () => {
        server = startSessionServer({
            port: PORT,
            host: "127.0.0.1",
            // A stand-in for the mixed-privilege app this exists for: only
            // staff join the everyone-fan-out, and students may listen to
            // their own sync object and nothing else.
            canRegisterSession: ({ scope }) => scope !== "student",
            canListenToSyncObject: ({ scope }, syncObjectId) =>
                scope === "student" ? syncObjectId === "students" : true,
        });
        await new Promise((r) => server.wss.once("listening", r));
    });

    after(() => {
        for (const socket of sockets) socket.close();
        server.close();
    });

    const track = (socket) => (sockets.push(socket), socket);

    it("keeps a denied socket out of the untargeted broadcast", async () => {
        const staff = track(await connect("staff-1", "staff"));
        const student = track(await connect("student-1", "student"));

        const staffFrames = collect(staff);
        const studentFrames = collect(student);

        // Both ask to register; only staff is allowed to.
        for (const socket of [staff, student]) {
            socket.send(
                JSON.stringify({
                    type: "register-session",
                    initiatorKey: socket === staff ? "staff-key" : "student-key",
                }),
            );
        }
        await settle();

        server.dispatchMessageToEveryone("secret", undefined, { secret: 1 });
        await settle();

        assert.equal(staffFrames.length, 1);
        assert.equal(staffFrames[0].data.secret, 1);
        assert.deepEqual(studentFrames, []);
    });

    it("still lets a denied socket listen to a sync object it is allowed", async () => {
        const student = track(await connect("student-2", "student"));
        const frames = collect(student);

        student.send(
            JSON.stringify({
                type: "register-sync-provider",
                syncObjectId: "students",
            }),
        );
        await settle();

        server.dispatchToSyncObjectListeners("ping", "students", {});
        await settle();

        assert.equal(frames.length, 1);
        assert.equal(frames[0].type, "ping");
    });

    it("denies that socket a sync object outside its scope", async () => {
        const student = track(await connect("student-3", "student"));
        const frames = collect(student);

        student.send(
            JSON.stringify({
                type: "register-sync-provider",
                syncObjectId: "staff-only",
            }),
        );
        await settle();

        server.dispatchToSyncObjectListeners("staff-data", "staff-only", {
            secret: 1,
        });
        await settle();

        assert.deepEqual(frames, []);
    });

    it("registers a socket by default when the app supplies no gate", async () => {
        const ungatedPort = PORT + 1;
        const ungated = startSessionServer({
            port: ungatedPort,
            host: "127.0.0.1",
        });
        await new Promise((r) => ungated.wss.once("listening", r));

        const socket = new WebSocket(
            `ws://127.0.0.1:${ungatedPort}/`,
            ticketSubprotocol(signWsTicket("anyone")),
        );
        await new Promise((resolve, reject) => {
            socket.once("open", resolve);
            socket.once("error", reject);
        });
        const frames = collect(socket);

        socket.send(
            JSON.stringify({ type: "register-session", initiatorKey: "k" }),
        );
        await settle();
        ungated.dispatchMessageToEveryone("hello", undefined, {});
        await settle();

        assert.equal(frames.length, 1);
        socket.close();
        ungated.close();
    });
});
