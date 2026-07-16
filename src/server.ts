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

export interface SessionServerOptions {
    /** Listen port. Defaults to `WEBSOCKET_SESSION_SERVER_INTERNAL_PORT` or 28199. */
    port?: number;
    /** Heartbeat interval. Defaults to `WEBSOCKET_SESSION_SERVER_HEARTBEAT_MS` or 30s. */
    heartbeatIntervalMs?: number;
    /**
     * Complete wire vocabulary this server accepts from clients (core types
     * are always included). Frames with unknown types are dropped.
     */
    validMessageTypes?: Iterable<string>;
    /**
     * App hook for client frames the core doesn't handle (anything beyond
     * session/sync registration). Return true when the message was handled;
     * unhandled messages are ignored.
     */
    onClientMessage?: (
        ws: WebSocket,
        data: MessageData,
        dispatch: SessionServerDispatch,
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
        let listeners = syncObjectListeners.get(syncObjectId);
        if (!listeners) {
            listeners = new Set();
            syncObjectListeners.set(syncObjectId, listeners);
        }
        listeners.add(ws);
        sessions.get(ws)?.syncObjectIds.add(syncObjectId);
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

    function safeSend(ws: WebSocket, message: string, context: string) {
        if (ws.readyState !== WebSocket.OPEN) return;
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
        // Serialize once per broadcast instead of once per recipient.
        const message = buildMessage(messageType, undefined, data);
        for (const [ws, state] of sessions) {
            if (state.initiatorKey === undefined) continue;
            safeSend(ws, message, `${messageType} to ${state.initiatorKey}`);
        }

        if (typeof targets === "string") {
            dispatchToSyncObjectListeners(messageType, targets, data);
        } else if (Array.isArray(targets)) {
            for (const target of targets) {
                dispatchToSyncObjectListeners(messageType, target, data);
            }
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
        if (!("authKey" in data)) {
            throw new Error(`Missing "authKey" in server data!`);
        }
        if (data["authKey"] !== getWsAuthKey()) {
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
        options.onClientMessage?.(ws, data, dispatch);
    }

    const wss = new WebSocketServer({
        port: listenPort,
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

    wss.on("listening", () => log(`Listening on port ${listenPort}`));

    wss.on("connection", (ws, req) => {
        const ticket = new URL(
            req.url ?? "",
            "http://internal",
        ).searchParams.get("ticket");
        const userId = ticket ? verifyWsTicket(ticket) : null;
        if (!userId) {
            logError("Rejected connection: missing or invalid ticket");
            ws.close(1008, "Invalid or missing ticket");
            return;
        }

        sessions.set(ws, { isAlive: true, userId, syncObjectIds: new Set() });

        ws.on("pong", () => {
            const state = sessions.get(ws);
            if (state) state.isAlive = true;
        });

        ws.on("error", (error) => logError("Connection error", error));

        ws.on("close", () => removeConnection(ws));

        ws.on("message", (dataString) => {
            let data: MessageData;
            try {
                data = JSON.parse(dataString.toString());
            } catch {
                logError("Received malformed frame, ignoring");
                return;
            }

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
        close();
        wss.close(() => process.exit(0));
        // Force-exit if clients keep the server alive past the grace period.
        setTimeout(() => process.exit(0), 5000).unref();
    }

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));

    return { wss, close, ...dispatch };
}
