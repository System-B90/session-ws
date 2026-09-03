"use client";

import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useRef,
} from "react";

import { CoreMessageTypes, ticketSubprotocol } from "../protocol.js";
import { useWebSocketConfig } from "./WebsocketConfigProvider.js";

/**
 * Handler callback for processing incoming WebSocket messages on the client.
 * Generic over the app's message-type string union/enum.
 * @param messageType The type of WS message.
 * @param data The JSON data payload containing domain entities/changes.
 */
export type MessageHandlerType<T extends string = string> = (
    messageType: T,
    data: any,
    target?: string,
) => void;

const MessageHandlerContext = createContext<MessageHandlerType>(() => {});

const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 30_000;
/**
 * Ceiling on messages held while the socket is CONNECTING. A socket that never
 * opens (server down, ticket rejected in a loop) would otherwise grow this
 * queue for as long as the tab stays open; oldest entries are dropped first.
 */
const MAX_QUEUED_MESSAGES = 100;

/**
 * Custom hook to establish and manage client-side WebSocket sessions.
 * Manages event listener registrations, session heartbeats, and auto-reconnection
 * with exponential backoff on close/error.
 *
 * @param ticketEndpoint Route that mints the short-lived, user-bound connect
 * ticket from the authenticated session. Defaults to `/api/ws-ticket`.
 * @returns An object containing the WebSocket ref and helpers to add/remove
 * handlers and send messages.
 */
export function useSessionWebSocketContext<T extends string = string>(
    ticketEndpoint = "/api/ws-ticket",
) {
    const { connectionString } = useWebSocketConfig();

    const ws = useRef<null | WebSocket>(null);
    const messageHandlers = useRef<Array<MessageHandlerType<T>>>([]);
    const messageQueue = useRef<Array<Record<string, unknown>>>([]);
    const reconnectAttempt = useRef(0);
    const reconnectTimer = useRef<null | ReturnType<typeof setTimeout>>(null);
    const isMounted = useRef(true);
    /**
     * Sync-object subscriptions this client wants, as *desired state* rather
     * than as frames that were sent once.
     *
     * The server keys subscriptions to the socket and drops them when it
     * closes, so every new socket starts subscribed to nothing. Treating a
     * subscription as a one-off message therefore loses it on the first
     * reconnect — and, because `connect()` awaits the ticket fetch before
     * assigning `ws.current`, a subscription requested during that window was
     * dropped outright (it is neither OPEN nor CONNECTING, so it did not even
     * queue). Both cases left the caller believing it was subscribed while the
     * server never heard of it, and scoped broadcasts silently stopped
     * arriving until a full page reload.
     *
     * Keeping the set and replaying it on every open makes both cases
     * self-healing: what matters is what the client wants, not whether one
     * particular send happened to land.
     */
    const syncObjectIds = useRef<Set<string>>(new Set());
    // Ref to break the circular dependency: onclose calls connect via ref so it
    // always dispatches the latest closure without ESLint's forward-ref warning.
    const connectRef = useRef<() => void>(() => {});

    const addMessageHandler = useCallback((handler: MessageHandlerType<T>) => {
        if (typeof window === "undefined") return () => {};

        messageHandlers.current.push(handler);

        return () => {
            messageHandlers.current = messageHandlers.current.filter(
                (h) => h !== handler,
            );
        };
    }, []);

    const webSocketMessageHandler = useCallback((ev: MessageEvent<any>) => {
        let parsed: unknown;
        try {
            parsed = JSON.parse(ev.data);
        } catch {
            console.error("[WS] Ignoring malformed frame");
            return;
        }
        if (parsed === null || typeof parsed !== "object") return;
        const { type, data, target } = parsed as {
            type: T;
            data: any;
            target?: string;
        };
        messageHandlers.current.forEach((handler) => handler(type, data, target));
    }, []);

    const registerCurrentSession = useCallback((socket: WebSocket) => {
        if (!socket || socket.readyState !== WebSocket.OPEN) return;

        socket.send(
            JSON.stringify({
                type: CoreMessageTypes.REGISTER_SESSION,
                initiatorKey: crypto.randomUUID(),
            }),
        );
    }, []);

    /** Re-asserts every wanted subscription on a freshly opened socket. */
    const replaySyncObjects = useCallback((socket: WebSocket) => {
        if (!socket || socket.readyState !== WebSocket.OPEN) return;

        for (const syncObjectId of syncObjectIds.current) {
            socket.send(
                JSON.stringify({
                    type: CoreMessageTypes.REGISTER_SYNC_PROVIDER,
                    syncObjectId,
                }),
            );
        }
    }, []);

    /**
     * Subscribe to a sync object, now and after every future reconnect.
     *
     * Idempotent, and safe to call before the socket exists: the id is
     * recorded either way and the open handler replays it.
     */
    const registerSyncObject = useCallback((syncObjectId: string) => {
        syncObjectIds.current.add(syncObjectId);

        const socket = ws.current;
        if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(
                JSON.stringify({
                    type: CoreMessageTypes.REGISTER_SYNC_PROVIDER,
                    syncObjectId,
                }),
            );
        }
        // Not open yet: `onopen` replays the whole set, so there is nothing to
        // queue and nothing to lose.
    }, []);

    /** Drop a subscription, so it is not replayed on later reconnects either. */
    const deregisterSyncObject = useCallback((syncObjectId: string) => {
        syncObjectIds.current.delete(syncObjectId);

        const socket = ws.current;
        if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(
                JSON.stringify({
                    type: CoreMessageTypes.DEREGISTER_SYNC_PROVIDER,
                    syncObjectId,
                }),
            );
        }
        // If the socket is gone the server already dropped this socket's
        // subscriptions; removing it from the set is what keeps it from coming
        // back on the next reconnect.
    }, []);

    const connect = useCallback(async () => {
        if (!isMounted.current) return;

        // A short-lived, user-bound ticket (minted from the authenticated
        // session) lets the session server bind this socket to a real user
        // instead of trusting a client-supplied random id.
        let ticket = "";
        try {
            const res = await fetch(ticketEndpoint);
            if (res.ok) {
                ({ ticket } = await res.json());
            }
        } catch {
            // Falls through to an unticketed connect attempt; the server
            // will reject it and the reconnect backoff will retry.
        }
        if (!isMounted.current) return;

        // The ticket rides as a subprotocol rather than a query parameter so it
        // never reaches proxy access logs.
        const socket = new WebSocket(
            connectionString,
            ticketSubprotocol(ticket),
        );
        ws.current = socket;

        socket.onopen = () => {
            reconnectAttempt.current = 0;
            registerCurrentSession(socket);
            // Before the queue: a subscription is a precondition for receiving
            // anything scoped, and the server drops this socket's
            // subscriptions the moment it closes.
            replaySyncObjects(socket);
            while (messageQueue.current.length > 0) {
                const msg = messageQueue.current.shift();
                if (msg) socket.send(JSON.stringify(msg));
            }
        };

        socket.onmessage = webSocketMessageHandler;

        socket.onclose = () => {
            ws.current = null;
            if (!isMounted.current) return;
            const delay = Math.min(
                RECONNECT_BASE_MS * Math.pow(2, reconnectAttempt.current),
                RECONNECT_MAX_MS,
            );
            reconnectAttempt.current += 1;
            reconnectTimer.current = setTimeout(
                () => connectRef.current(),
                delay,
            );
        };

        socket.onerror = () => {
            console.error("[WS] Connection error");
            socket.close();
        };
    }, [
        connectionString,
        ticketEndpoint,
        webSocketMessageHandler,
        registerCurrentSession,
        replaySyncObjects,
    ]);

    useEffect(() => {
        // Keep the ref in sync so onclose always calls the latest closure.
        connectRef.current = connect;
        isMounted.current = true;
        void connect();

        return () => {
            isMounted.current = false;
            if (reconnectTimer.current !== null) {
                clearTimeout(reconnectTimer.current);
                reconnectTimer.current = null;
            }
            if (ws.current) {
                ws.current.onclose = null;
                ws.current.close();
                ws.current = null;
            }
        };
    }, [connect]);

    const sendMessage = useCallback((data: Record<string, unknown>) => {
        const socket = ws.current;
        if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify(data));
        } else if (socket && socket.readyState === WebSocket.CONNECTING) {
            if (messageQueue.current.length >= MAX_QUEUED_MESSAGES) {
                messageQueue.current.shift();
            }
            messageQueue.current.push(data);
        } else {
            console.error("WebSocket is closed. Cannot send message.");
        }
    }, []);

    return {
        ws,
        addMessageHandler,
        sendMessage,
        registerSyncObject,
        deregisterSyncObject,
    };
}

export const useMessageHandler = () => {
    return useContext(MessageHandlerContext);
};
