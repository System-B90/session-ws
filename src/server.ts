/*
 * Session-server core, extracted from Bluz `session-server/session-server.ts`:
 * ticket-authenticated connects, in-memory session + sync-object registries,
 * protocol-level heartbeat, graceful shutdown. App-specific message relaying
 * plugs in via `onClientMessage`.
 */

import { WebSocket, WebSocketServer } from "ws";

import {
    CoreMessageTypes,
    getWsAuthKey,
    secureCompare,
    TICKET_SUBPROTOCOL_PREFIX,
    verifyWsTicket,
    WEBSOCKET_SESSION_SERVER_SENDER_SERVER_MAGIC,
} from "./common.js";

export type MessageData = Record<string, unknown>;

interface SessionState {
    initiatorKey?: string;
    /** Authenticated user id resolved from the connect-time ticket. */
    userId: string;
    isAlive: boolean;
    /** Sync-object ids this socket listens to (for O(1) cleanup on close). */
    syncObjectIds: Set<string>;
    /** Sliding-window message budget — see `MESSAGE_RATE_*`. */
    windowStartedAt: number;
    messagesInWindow: number;
}

export interface SessionServerDispatch {
    /** Broadcast to every registered session, plus optional sync-object targets. */
    dispatchMessageToEveryone: (
        messageType: string,
        targets?: Array<string> | string,
        data?: MessageData,
    ) => void;
    /** Send to the listeners of a single sync object. */
    dispatchToSyncObjectListeners: (
        messageType: string,
        syncObjectId: string,
        data?: MessageData,
    ) => void;
}

/** Authenticated identity of the socket a client frame arrived on. */
export interface ClientIdentity {
    /** User id validated from the connect ticket. Never client-supplied. */
    userId: string;
}

export interface SessionServerOptions {
    /** Listen port. Defaults to `WEBSOCKET_SESSION_SERVER_INTERNAL_PORT` or 28199. */
    port?: number;
    /**
     * Interface to bind. Defaults to `WEBSOCKET_SESSION_SERVER_BIND_HOST`, else
     * all interfaces — set `127.0.0.1` for local runs so `npm run session:start`
     * doesn't expose the port to the LAN.
     */
    host?: string;
    /** Heartbeat interval. Defaults to `WEBSOCKET_SESSION_SERVER_HEARTBEAT_MS` or 30s. */
    heartbeatIntervalMs?: number;
    /** Largest accepted frame, in bytes. Defaults to 64 KiB. */
    maxPayloadBytes?: number;
    /** Client frames accepted per socket per `rateLimitWindowMs`. Defaults to 120. */
    maxMessagesPerWindow?: number;
    /** Rate-limit window. Defaults to 10s. */
    rateLimitWindowMs?: number;
    /**
     * Queued-bytes ceiling per socket. A recipient already over this budget is
     * skipped rather than queued into, and repeated offenders are closed.
     * Defaults to 1 MiB.
     */
    maxBufferedBytes?: number;
    /**
     * Complete wire vocabulary this server accepts from clients (core types
     * are always included). Frames with unknown types are dropped.
     */
    validMessageTypes?: Iterable<string>;
    /**
     * Ownership gate for `register-sync-provider`. Without it any authenticated
     * socket can subscribe to any sync-object id and receive its traffic, so the
     * default is deny — apps that use sync objects must opt in explicitly.
     */
    canListenToSyncObject?: (
        identity: ClientIdentity,
        syncObjectId: string,
    ) => boolean;
    /**
     * App hook for client frames the core doesn't handle (anything beyond
     * session/sync registration). Return true when the message was handled;
     * unhandled messages are ignored.
     *
     * `identity` carries the ticket-validated user id: apps relaying
     * client-authored frames (presence, locks) must stamp identity from here and
     * never trust an id inside `data`.
     */
    onClientMessage?: (
        ws: WebSocket,
        data: MessageData,
        dispatch: SessionServerDispatch,
        identity: ClientIdentity,
    ) => boolean;
}

export interface SessionServer extends SessionServerDispatch {
    wss: WebSocketServer;
    close: () => void;
}

function log(message: string) {
    console.log(`[WS] ${message}`);
}

function logError(message: string, error?: unknown) {
    console.error(`[WS] ${message}`, error ?? "");
}

export function startSessionServer(
    options: SessionServerOptions = {},
): SessionServer {
    const listenPort =
        options.port ??
        Number.parseInt(
            process.env.WEBSOCKET_SESSION_SERVER_INTERNAL_PORT ?? "28199",
            10,
        );
    const heartbeatIntervalMs =
        options.heartbeatIntervalMs ??
        Number.parseInt(
            process.env.WEBSOCKET_SESSION_SERVER_HEARTBEAT_MS ?? "30000",
            10,
        );
    const listenHost =
        options.host ?? process.env.WEBSOCKET_SESSION_SERVER_BIND_HOST;
    const maxPayloadBytes = options.maxPayloadBytes ?? 64 * 1024;
    const maxMessagesPerWindow = options.maxMessagesPerWindow ?? 120;
    const rateLimitWindowMs = options.rateLimitWindowMs ?? 10_000;
    const maxBufferedBytes = options.maxBufferedBytes ?? 1024 * 1024;

    /**
     * In-memory connection registry.
     *
     * Every accepted socket gets a SessionState; `sessions` drives the broadcast
     * fan-out and the heartbeat sweep. `syncObjectListeners` is a reverse index
     * (sync-object id → listening sockets) so targeted dispatch never scans the
     * whole session table.
     *
     * NOTE: the registry is process-local. To scale this server horizontally the
     * fan-out must go through a shared broker (e.g. Redis pub/sub).
     */
    const sessions = new Map<WebSocket, SessionState>();
    const syncObjectListeners = new Map<string, Set<WebSocket>>();

    const validMessageTypes = new Set<unknown>([
        ...Object.values(CoreMessageTypes),
        ...(options.validMessageTypes ?? []),
    ]);

    function registerSession(ws: WebSocket, initiatorKey: unknown) {
        if (typeof initiatorKey !== "string") {
            logError(
                `register-session ignored: initiatorKey must be a string, got ${typeof initiatorKey}`,
            );
            return;
        }
        const state = sessions.get(ws);
        if (state) {
            state.initiatorKey = initiatorKey;
        }
    }

    function registerSyncObjectListener(ws: WebSocket, syncObjectId: unknown) {
        if (typeof syncObjectId !== "string") {
            logError(
                `register-sync-provider ignored: syncObjectId must be a string, got ${typeof syncObjectId}`,
            );
            return;
        }
        const state = sessions.get(ws);
        if (!state) return;
        // Deny by default: an unauthorized subscription is a read primitive on
        // another tenant's sync traffic.
        if (!options.canListenToSyncObject?.({ userId: state.userId }, syncObjectId)) {
            logError(
                `register-sync-provider denied for user ${state.userId} on "${syncObjectId}"`,
            );
            return;
        }
        let listeners = syncObjectListeners.get(syncObjectId);
        if (!listeners) {
            listeners = new Set();
            syncObjectListeners.set(syncObjectId, listeners);
        }
        listeners.add(ws);
        state.syncObjectIds.add(syncObjectId);
    }

    function removeConnection(ws: WebSocket) {
        const state = sessions.get(ws);
        if (!state) return;

        for (const syncObjectId of state.syncObjectIds) {
            const listeners = syncObjectListeners.get(syncObjectId);
            if (!listeners) continue;
            listeners.delete(ws);
            if (listeners.size === 0) {
                syncObjectListeners.delete(syncObjectId);
            }
        }
        sessions.delete(ws);
        if (state.initiatorKey) {
            log(`Session ${state.initiatorKey} removed`);
        }
    }

    function buildMessage(
        messageType: string,
        target?: string,
        data?: MessageData,
    ): string {
        return JSON.stringify({ type: messageType, target, data });
    }

    /**
     * Fan-out is best-effort per recipient. A consumer that can't keep up would
     * otherwise accumulate an unbounded outbound queue in this process, so once
     * it is past the buffered-bytes budget we stop queueing into it and close
     * it — the client's reconnect/refetch path recovers the missed state.
     */
    function safeSend(ws: WebSocket, message: string, context: string) {
        if (ws.readyState !== WebSocket.OPEN) return;
        if (ws.bufferedAmount > maxBufferedBytes) {
            logError(
                `Dropping slow consumer (${ws.bufferedAmount} bytes queued) on ${context}`,
            );
            ws.close(1013, "Send buffer exceeded");
            return;
        }
        try {
            ws.send(message);
        } catch (error) {
            logError(`Failed to send ${context}`, error);
        }
    }

    function dispatchMessageToEveryone(
        messageType: string,
        targets?: Array<string> | string,
        data?: MessageData,
    ) {
        // Targeted and everyone-fan-out are mutually exclusive: sending both
        // delivered two copies to any listener that was also a live session.
        if (typeof targets === "string") {
            dispatchToSyncObjectListeners(messageType, targets, data);
            return;
        }
        if (Array.isArray(targets)) {
            for (const target of targets) {
                dispatchToSyncObjectListeners(messageType, target, data);
            }
            return;
        }

        // Serialize once per broadcast instead of once per recipient.
        const message = buildMessage(messageType, undefined, data);
        for (const [ws, state] of sessions) {
            if (state.initiatorKey === undefined) continue;
            safeSend(ws, message, `${messageType} to ${state.initiatorKey}`);
        }
    }

    function dispatchToSyncObjectListeners(
        messageType: string,
        syncObjectId: string,
        data?: MessageData,
    ) {
        const listeners = syncObjectListeners.get(syncObjectId);
        if (!listeners || listeners.size === 0) {
            log(
                `Dispatch requested on sync object "${syncObjectId}" with no listeners`,
            );
            return;
        }
        const message = buildMessage(messageType, syncObjectId, data);
        for (const ws of listeners) {
            safeSend(ws, message, `${messageType} to sync object ${syncObjectId}`);
        }
    }

    const dispatch: SessionServerDispatch = {
        dispatchMessageToEveryone,
        dispatchToSyncObjectListeners,
    };

    function validateServerMessage(data: MessageData) {
        const authKey = data["authKey"];
        if (typeof authKey !== "string") {
            throw new Error(`Missing "authKey" in server data!`);
        }
        // Constant-time: a plain !== leaks the shared key one prefix byte at a
        // time to anyone who can send frames and time the rejection.
        if (!secureCompare(authKey, getWsAuthKey())) {
            throw new Error(`Invalid "authKey" in server data!`);
        }
    }

    function handleServerMessage(data: MessageData) {
        try {
            validateServerMessage(data);
            log(`Server message ${data["type"]}`);
            delete data["authKey"];
            dispatchMessageToEveryone(
                data["type"] as string,
                data["targets"] as Array<string> | string | undefined,
                data["data"] as MessageData | undefined,
            );
        } catch (error) {
            logError("Server message error", error);
        }
    }

    function handleClientMessage(ws: WebSocket, data: MessageData) {
        switch (data["type"]) {
            case CoreMessageTypes.REGISTER_SESSION:
                registerSession(ws, data["initiatorKey"]);
                return;
            case CoreMessageTypes.REGISTER_SYNC_PROVIDER:
                registerSyncObjectListener(ws, data["syncObjectId"]);
                return;
        }
        const state = sessions.get(ws);
        if (!state) return;
        options.onClientMessage?.(ws, data, dispatch, { userId: state.userId });
    }

    /** True while the socket is within its sliding-window message budget. */
    function withinRateLimit(state: SessionState): boolean {
        const now = Date.now();
        if (now - state.windowStartedAt >= rateLimitWindowMs) {
            state.windowStartedAt = now;
            state.messagesInWindow = 0;
        }
        state.messagesInWindow += 1;
        return state.messagesInWindow <= maxMessagesPerWindow;
    }

    const wss = new WebSocketServer({
        port: listenPort,
        host: listenHost,
        // ws defaults to ~100 MiB, which a single authenticated client can use
        // to burn memory and (via deflate) CPU.
        maxPayload: maxPayloadBytes,
        // Echo back the ticket-bearing subprotocol so the handshake completes.
        handleProtocols: (protocols) => {
            for (const protocol of protocols) {
                if (protocol.startsWith(TICKET_SUBPROTOCOL_PREFIX)) return protocol;
            }
            return false;
        },
        perMessageDeflate: {
            zlibDeflateOptions: {
                chunkSize: 1024,
                memLevel: 7,
                level: 3,
            },
            zlibInflateOptions: {
                chunkSize: 10 * 1024,
            },
            clientNoContextTakeover: true,
            serverNoContextTakeover: true,
            serverMaxWindowBits: 10,
            concurrencyLimit: 50, // Limits zlib concurrency for perf.
            threshold: 1024, // Don't compress payloads smaller than this.
        },
    });

    wss.on("listening", () =>
        log(`Listening on ${listenHost ?? "0.0.0.0"}:${listenPort}`),
    );

    wss.on("connection", (ws, req) => {
        // Preferred: ticket as a WebSocket subprotocol, so it never lands in
        // access logs. Query string stays supported for older clients.
        const subprotocolTicket = ws.protocol?.startsWith(TICKET_SUBPROTOCOL_PREFIX)
            ? decodeURIComponent(ws.protocol.slice(TICKET_SUBPROTOCOL_PREFIX.length))
            : null;
        const ticket =
            subprotocolTicket ??
            new URL(req.url ?? "", "http://internal").searchParams.get("ticket");
        const userId = ticket ? verifyWsTicket(ticket) : null;
        if (!userId) {
            logError("Rejected connection: missing or invalid ticket");
            ws.close(1008, "Invalid or missing ticket");
            return;
        }

        sessions.set(ws, {
            isAlive: true,
            userId,
            syncObjectIds: new Set(),
            windowStartedAt: Date.now(),
            messagesInWindow: 0,
        });

        ws.on("pong", () => {
            const state = sessions.get(ws);
            if (state) state.isAlive = true;
        });

        ws.on("error", (error) => logError("Connection error", error));

        ws.on("close", () => removeConnection(ws));

        ws.on("message", (dataString) => {
            const state = sessions.get(ws);
            if (!state) return;
            if (!withinRateLimit(state)) {
                // Frames already buffered keep arriving after close() is
                // requested; log the decision once, on the closing transition.
                if (ws.readyState === WebSocket.OPEN) {
                    logError(
                        `Rate limit exceeded for user ${state.userId}, closing`,
                    );
                    ws.close(1008, "Rate limit exceeded");
                }
                return;
            }

            let parsed: unknown;
            try {
                parsed = JSON.parse(dataString.toString());
            } catch {
                logError("Received malformed frame, ignoring");
                return;
            }

            // `null`, arrays and primitives all parse fine but have no fields;
            // reading through them used to throw out of this handler and take
            // the whole process down with it.
            if (
                parsed === null ||
                typeof parsed !== "object" ||
                Array.isArray(parsed)
            ) {
                logError("Received non-object frame, ignoring");
                return;
            }
            const data = parsed as MessageData;

            if (
                data["sender"] === WEBSOCKET_SESSION_SERVER_SENDER_SERVER_MAGIC
            ) {
                handleServerMessage(data);
                return;
            }
            if (!validMessageTypes.has(data["type"])) {
                logError(`Unknown message type "${data["type"]}", ignoring`);
                return;
            }
            handleClientMessage(ws, data);
        });
    });

    // Protocol-level heartbeat: browsers and the `ws` client answer pings
    // automatically, so a socket that misses a full interval is genuinely dead
    // (half-open TCP, crashed tab, dropped network) and gets terminated.
    const heartbeat = setInterval(() => {
        for (const [ws, state] of sessions) {
            if (!state.isAlive) {
                log(
                    `Terminating unresponsive session${state.initiatorKey ? ` ${state.initiatorKey}` : ""}`,
                );
                ws.terminate(); // "close" handler performs registry cleanup.
                continue;
            }
            state.isAlive = false;
            ws.ping();
        }
    }, heartbeatIntervalMs);

    function close() {
        clearInterval(heartbeat);
        for (const ws of sessions.keys()) {
            ws.close(1001, "Server shutting down");
        }
        wss.close();
    }

    function shutdown(signal: string) {
        log(`${signal} received, shutting down`);
        clearInterval(heartbeat);
        for (const ws of sessions.keys()) {
            ws.close(1001, "Server shutting down");
        }
        // `close()` already closes wss; call it once, here, with the exit callback.
        wss.close(() => process.exit(0));
        // Force-exit if clients keep the server alive past the grace period.
        setTimeout(() => process.exit(0), 5000).unref();
    }

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));

    return { wss, close, ...dispatch };
}
