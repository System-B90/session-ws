/*
 * Shared session-server pieces: env-derived connection config and
 * HMAC-signed connect tickets. Server-side only (imports node:crypto);
 * browser-safe protocol constants live in ./protocol.ts.
 * Canonical source: Bluz `session-server/session-common.ts`.
 */

import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from "crypto";

export * from "./protocol.js";

export const WEBSOCKET_SESSION_SERVER_PORT = parseInt(
    process.env.WEBSOCKET_SESSION_SERVER_PORT ?? "443",
    10,
);

export const WEBSOCKET_SESSION_SERVER_HOST =
    process.env.WEBSOCKET_SESSION_SERVER_HOST ?? "127.0.0.1";

export const SECURE_CONTEXT_ONLY =
    process.env.NODE_ENV === "production" ||
    WEBSOCKET_SESSION_SERVER_PORT === 443;

export const WEBSOCKET_PROTOCOL = SECURE_CONTEXT_ONLY ? "wss" : "ws";

export const WEBSOCKET_PORT_SUFFIX =
    WEBSOCKET_SESSION_SERVER_PORT === 443 ||
    WEBSOCKET_SESSION_SERVER_PORT === 80
        ? ""
        : `:${WEBSOCKET_SESSION_SERVER_PORT}`;

export const NEXT_PUBLIC_WEBSOCKET_SESSION_SERVER_CONN_STRING = `${WEBSOCKET_PROTOCOL}://${WEBSOCKET_SESSION_SERVER_HOST}${WEBSOCKET_PORT_SUFFIX}/ws/`;

// Lazy: evaluated per-use (not at import time) so unrelated code that pulls
// in this module — e.g. tests, or Next.js routes that never touch WS auth —
// doesn't fail just because the env var isn't set in that context.
function getWsRootSecret(): string {
    const key = process.env.WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY;
    if (!key) {
        throw new Error(
            "WEBSOCKET_SESSION_SERVER_SENDER_AUTH_KEY environment variable has not been set!",
        );
    }
    return key;
}

/**
 * The value server processes put in the `authKey` field of broadcast frames.
 * This is the derived sender subkey, not the raw env secret — see the HKDF
 * note below.
 */
export function getWsAuthKey(): string {
    return getWsSenderAuthKey();
}

/*
 * The configured env secret is never used directly on the wire. Two independent
 * subkeys are derived from it with HKDF-SHA256 under distinct `info` labels, so
 * the value that server processes send in cleartext per broadcast (the sender
 * key) cannot be replayed against the ticket HMAC, and vice versa. Rotating the
 * root secret rotates both.
 */
const SENDER_KEY_INFO = "system-b90/session-ws/sender-auth-key/v1";
const TICKET_KEY_INFO = "system-b90/session-ws/ticket-hmac-key/v1";
const SUBKEY_BYTES = 32;

function deriveSubkey(info: string): Buffer {
    return Buffer.from(
        hkdfSync("sha256", getWsRootSecret(), Buffer.alloc(0), info, SUBKEY_BYTES),
    );
}

// Derivation is pure but not free; memoize per root secret so a rotated env var
// (as tests do) still takes effect.
let subkeyCache: null | { root: string; sender: Buffer; ticket: Buffer } = null;

function subkeys() {
    const root = getWsRootSecret();
    if (!subkeyCache || subkeyCache.root !== root) {
        subkeyCache = {
            root,
            sender: deriveSubkey(SENDER_KEY_INFO),
            ticket: deriveSubkey(TICKET_KEY_INFO),
        };
    }
    return subkeyCache;
}

/** Key server processes present in the `authKey` field of broadcast frames. */
export function getWsSenderAuthKey(): string {
    return subkeys().sender.toString("hex");
}

/** Key used to sign and verify connect tickets. Never sent on the wire. */
export function getWsTicketKey(): Buffer {
    return subkeys().ticket;
}

/**
 * Length-independent constant-time string compare. Both sides are hashed first
 * so the comparison buffers are always 32 bytes, which keeps `timingSafeEqual`
 * from throwing (and from leaking length) on attacker-controlled input.
 */
export function secureCompare(a: string, b: string): boolean {
    const digest = (value: string) =>
        createHmac("sha256", "session-ws/compare").update(value).digest();
    return timingSafeEqual(digest(a), digest(b));
}

const WS_TICKET_TTL_MS = 30_000;

/**
 * Signs a short-lived (30s), user-bound ticket for the browser to present on
 * WS connect, so the session server can bind the socket to a real user
 * instead of trusting a client-supplied random UUID. Cheap HMAC compare, not
 * a static shared secret sent per-message, keeps the connect path fast.
 */
/**
 * The authenticated bearer of a ticket.
 *
 * `scope` is the app's own privilege label — "staff"/"student", "admin"/
 * "viewer", a tenant id, whatever the app tiers on. The core never interprets
 * it; it only guarantees it was signed by the app's own key and so cannot be
 * chosen by the browser presenting the ticket. Apps that serve a single
 * privilege level can ignore it entirely.
 */
export type WsTicketIdentity = {
    userId: string;
    scope?: string;
    /**
     * Epoch ms this ticket stops being valid. Exposed so a server can key a
     * single-use replay cache on the ticket and evict the entry exactly when
     * the ticket would have expired anyway.
     */
    expiresAt: number;
    /**
     * The ticket's HMAC signature — a collision-resistant identifier for
     * *this* ticket, safe to use as a replay-cache key. It is not a secret the
     * holder doesn't already have.
     */
    signature: string;
};

/*
 * Ticket wire format. A ticket is dot-separated, so no field may contain a dot:
 *   legacy  `userId.expiresAt.signature`                    (3 parts, no scope)
 *   scoped  `userId.expiresAt.scope.signature`              (4 parts)
 *   current `userId.expiresAt.scope.nonce.signature`        (5 parts)
 * Both older forms stay valid, so a server can be upgraded before its clients.
 * In the current form an empty `scope` field means "no scope", which keeps the
 * field count fixed whether or not the app tiers on privilege.
 */
const TICKET_FIELD_PATTERN = /^[^.]+$/;
const TICKET_NONCE_BYTES = 12;

export function signWsTicket(userId: string, scope?: string): string {
    if (!TICKET_FIELD_PATTERN.test(userId)) {
        throw new Error("signWsTicket: userId must not contain a dot");
    }
    if (scope !== undefined && !TICKET_FIELD_PATTERN.test(scope)) {
        throw new Error("signWsTicket: scope must be non-empty and dot-free");
    }
    const expiresAt = Date.now() + WS_TICKET_TTL_MS;
    /*
     * Without this, a ticket is a pure function of (userId, scope, expiry in
     * ms) — so two tickets minted for the same user in the same millisecond
     * are byte-identical. That is fine for verification and fatal for any
     * single-use check: two tabs (or a reconnecting sender) that ask at the
     * same moment produce one ticket, and the second socket is refused as a
     * replay of the first. The nonce makes every minted ticket distinct, which
     * is what lets a server treat a repeat as genuinely a replay.
     */
    const nonce = randomBytes(TICKET_NONCE_BYTES).toString("hex");
    // Scope and nonce are inside the signed payload, not appended after it: a
    // scope the holder could edit would make the whole gate decorative.
    const payload = `${userId}.${expiresAt}.${scope ?? ""}.${nonce}`;
    const signature = createHmac("sha256", getWsTicketKey())
        .update(payload)
        .digest("hex");
    return `${payload}.${signature}`;
}

/**
 * Verifies a ticket and returns its full identity, or null when it is
 * malformed, expired, or not signed by this key.
 */
export function verifyWsTicketIdentity(
    ticket: string,
): null | WsTicketIdentity {
    const parts = ticket.split(".");
    if (parts.length < 3 || parts.length > 5) return null;

    const signature = parts[parts.length - 1]!;
    const [userId, expiresAtRaw] = parts;
    // 3 parts carry no scope; 4 and 5 both carry it in the same slot, and in
    // the 5-part form an empty string there means the app signed no scope.
    const rawScope = parts.length === 3 ? undefined : parts[2];
    const scope = rawScope ? rawScope : undefined;
    const expiresAt = Number(expiresAtRaw);
    if (!userId || !Number.isFinite(expiresAt) || Date.now() > expiresAt) {
        return null;
    }

    const payload = parts.slice(0, parts.length - 1).join(".");
    const expectedSignature = createHmac("sha256", getWsTicketKey())
        .update(payload)
        .digest("hex");
    if (!secureCompare(expectedSignature, signature)) {
        return null;
    }

    return scope === undefined
        ? { expiresAt, signature, userId }
        : { expiresAt, scope, signature, userId };
}

/**
 * Verifies a ticket and returns just the user id. Kept for callers that do not
 * tier on scope; {@link verifyWsTicketIdentity} is the full form.
 */
export function verifyWsTicket(ticket: string): null | string {
    return verifyWsTicketIdentity(ticket)?.userId ?? null;
}
