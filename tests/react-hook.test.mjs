/*
 * Component tests for useSessionWebSocketContext and WebSocketConfigProvider.
 * Runs against the built `dist/` output under a jsdom global environment,
 * with `fetch` and `WebSocket` mocked. Runs on node --test, so `npm run
 * build` first.
 */

import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: "http://localhost/",
});
globalThis.window = dom.window;
globalThis.document = dom.window.document;
// Node defines a read-only global `navigator`; redefine it instead of assigning.
Object.defineProperty(globalThis, "navigator", {
    value: dom.window.navigator,
    configurable: true,
});
globalThis.MessageEvent = dom.window.MessageEvent;
// Node's global `crypto` already provides randomUUID; the hook under test
// calls it directly, so nothing to stub here.

const React = (await import("react")).default;
const { act } = await import("react");
const { renderHook } = await import("@testing-library/react");

const { useSessionWebSocketContext } = await import("../dist/react/SessionWs.js");
const { WebSocketConfigProvider, useWebSocketConfig } = await import(
    "../dist/react/WebsocketConfigProvider.js"
);

/** Minimal mock WebSocket the hook drives through readyState + on* handlers. */
class MockWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;

    constructor(url, protocol) {
        this.url = url;
        this.protocol = protocol;
        this.readyState = MockWebSocket.CONNECTING;
        this.sent = [];
        this.onopen = null;
        this.onmessage = null;
        this.onclose = null;
        this.onerror = null;
        MockWebSocket.instances.push(this);
    }

    send(data) {
        if (this.readyState !== MockWebSocket.OPEN) {
            throw new Error("cannot send: socket not open");
        }
        this.sent.push(data);
    }

    close() {
        if (this.readyState === MockWebSocket.CLOSED) return;
        this.readyState = MockWebSocket.CLOSED;
        this.onclose?.();
    }

    /** Test helper: drive the socket to OPEN and fire onopen. */
    triggerOpen() {
        this.readyState = MockWebSocket.OPEN;
        this.onopen?.();
    }

    /** Test helper: fire onmessage with a JSON-able payload. */
    triggerMessage(payload) {
        this.onmessage?.({ data: JSON.stringify(payload) });
    }

    triggerError() {
        this.onerror?.();
    }
}
MockWebSocket.instances = [];

let originalWebSocket;
let originalFetch;

beforeEach(() => {
    originalWebSocket = globalThis.WebSocket;
    originalFetch = globalThis.fetch;
    globalThis.WebSocket = MockWebSocket;
    MockWebSocket.instances.length = 0;
});

afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    globalThis.fetch = originalFetch;
    mock.timers.reset();
});

function jsonResponse(body, ok = true) {
    return { ok, json: async () => body };
}

describe("WebSocketConfigProvider", () => {
    it("composes connectionString from host/protocol/portSuffix", () => {
        const wrapper = ({ children }) =>
            React.createElement(
                WebSocketConfigProvider,
                { host: "example.com", protocol: "wss", portSuffix: ":8443" },
                children,
            );
        const { result } = renderHook(() => useWebSocketConfig(), { wrapper });
        assert.equal(result.current.connectionString, "wss://example.com:8443/ws/");
    });
});

describe("useSessionWebSocketContext", () => {
    function wrapper({ children }) {
        return React.createElement(
            WebSocketConfigProvider,
            { host: "example.com", protocol: "ws", portSuffix: "" },
            children,
        );
    }

    it("fetches the ticket endpoint and opens the socket with it URL-encoded", async () => {
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "a.b.c" }));

        const { result, unmount } = renderHook(
            () => useSessionWebSocketContext("/api/ws-ticket"),
            { wrapper },
        );

        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        assert.equal(globalThis.fetch.mock.callCount(), 1);
        assert.equal(globalThis.fetch.mock.calls[0].arguments[0], "/api/ws-ticket");
        assert.equal(MockWebSocket.instances.length, 1);
        const socket = MockWebSocket.instances[0];
        assert.equal(socket.url, "ws://example.com/ws/");
        assert.equal(socket.protocol, `ticket.${encodeURIComponent("a.b.c")}`);

        unmount();
    });

    it("falls through to an unticketed connect when the fetch fails", async () => {
        globalThis.fetch = mock.fn(async () => {
            throw new Error("network down");
        });

        const { unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });

        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        assert.equal(MockWebSocket.instances.length, 1);
        assert.equal(MockWebSocket.instances[0].protocol, "ticket.");
        unmount();
    });

    it("falls through to an unticketed connect on a non-ok response", async () => {
        globalThis.fetch = mock.fn(async () => jsonResponse({}, false));

        const { unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });

        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        assert.equal(MockWebSocket.instances[0].protocol, "ticket.");
        unmount();
    });

    it("on open: resets reconnectAttempt, registers the session, and flushes the queue in FIFO order", async () => {
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));

        const { result, unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        const socket = MockWebSocket.instances[0];

        act(() => {
            result.current.sendMessage({ n: 1 });
            result.current.sendMessage({ n: 2 });
        });

        act(() => socket.triggerOpen());

        assert.equal(socket.sent.length, 3); // register-session + 2 queued
        const registerFrame = JSON.parse(socket.sent[0]);
        assert.equal(registerFrame.type, "register-session");
        assert.equal(typeof registerFrame.initiatorKey, "string");
        assert.deepEqual(JSON.parse(socket.sent[1]), { n: 1 });
        assert.deepEqual(JSON.parse(socket.sent[2]), { n: 2 });

        unmount();
    });

    it("sendMessage routes by readyState: OPEN sends, CONNECTING queues, CLOSED drops without throwing", async () => {
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));
        const { result, unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        const socket = MockWebSocket.instances[0];

        // CONNECTING: queued, nothing sent yet.
        act(() => result.current.sendMessage({ q: 1 }));
        assert.equal(socket.sent.length, 0);

        // OPEN: queue flushed plus the register-session frame.
        act(() => socket.triggerOpen());
        assert.equal(socket.sent.length, 2);

        act(() => result.current.sendMessage({ direct: true }));
        assert.equal(socket.sent.length, 3);
        assert.deepEqual(JSON.parse(socket.sent[2]), { direct: true });

        // CLOSED: dropped, no throw.
        act(() => socket.close());
        assert.doesNotThrow(() => act(() => result.current.sendMessage({ dropped: true })));

        unmount();
    });

    it("fans incoming frames out to all registered handlers with type/data/target", async () => {
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));
        const { result, unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });
        const socket = MockWebSocket.instances[0];
        act(() => socket.triggerOpen());

        const calls = [];
        act(() => {
            result.current.addMessageHandler((type, data, target) =>
                calls.push({ type, data, target }),
            );
        });

        act(() =>
            socket.triggerMessage({ type: "sync-object-update", data: { x: 1 }, target: "obj-1" }),
        );

        assert.equal(calls.length, 1);
        assert.deepEqual(calls[0], { type: "sync-object-update", data: { x: 1 }, target: "obj-1" });

        unmount();
    });

    it("addMessageHandler unsubscribe removes only that handler", async () => {
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));
        const { result, unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });
        const socket = MockWebSocket.instances[0];
        act(() => socket.triggerOpen());

        let aCalls = 0;
        let bCalls = 0;
        let unsubA;
        act(() => {
            unsubA = result.current.addMessageHandler(() => (aCalls += 1));
            result.current.addMessageHandler(() => (bCalls += 1));
        });

        act(() => socket.triggerMessage({ type: "t", data: {} }));
        assert.equal(aCalls, 1);
        assert.equal(bCalls, 1);

        act(() => unsubA());
        act(() => socket.triggerMessage({ type: "t", data: {} }));
        assert.equal(aCalls, 1);
        assert.equal(bCalls, 2);

        unmount();
    });

    it("backoff schedule doubles from 500ms, resets on open, and caps at 30s", async () => {
        mock.timers.enable({ apis: ["setTimeout"] });
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));

        const { unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        // Close #1 (before any successful open): delay = 500 * 2^0 = 500ms.
        act(() => MockWebSocket.instances[0].close());
        await act(async () => {
            mock.timers.tick(499);
        });
        assert.equal(MockWebSocket.instances.length, 1);
        await act(async () => {
            mock.timers.tick(1);
            await Promise.resolve();
            await Promise.resolve();
        });
        assert.equal(MockWebSocket.instances.length, 2);

        // Close #2 without an intervening open: delay = 500 * 2^1 = 1000ms.
        act(() => MockWebSocket.instances[1].close());
        await act(async () => {
            mock.timers.tick(999);
        });
        assert.equal(MockWebSocket.instances.length, 2);
        await act(async () => {
            mock.timers.tick(1);
            await Promise.resolve();
            await Promise.resolve();
        });
        assert.equal(MockWebSocket.instances.length, 3);

        // A successful open resets reconnectAttempt to 0.
        act(() => MockWebSocket.instances[2].triggerOpen());
        act(() => MockWebSocket.instances[2].close());
        await act(async () => {
            mock.timers.tick(499);
        });
        assert.equal(MockWebSocket.instances.length, 3);
        await act(async () => {
            mock.timers.tick(1);
            await Promise.resolve();
            await Promise.resolve();
        });
        assert.equal(MockWebSocket.instances.length, 4);

        unmount();
        mock.timers.reset();
    });

    it("caps backoff delay at 30s", async () => {
        mock.timers.enable({ apis: ["setTimeout"] });
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));

        const { unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        // Drive enough consecutive closes that 500*2^n would exceed 30s
        // (n=7 -> 64000ms uncapped) and confirm the actual wait is the 30s cap.
        for (let i = 0; i < 7; i++) {
            const current = MockWebSocket.instances[MockWebSocket.instances.length - 1];
            act(() => current.close());
            await act(async () => {
                mock.timers.runAll();
                await Promise.resolve();
                await Promise.resolve();
            });
        }

        const last = MockWebSocket.instances[MockWebSocket.instances.length - 1];
        act(() => last.close());
        await act(async () => {
            mock.timers.tick(29_999);
        });
        const countBeforeCap = MockWebSocket.instances.length;
        await act(async () => {
            mock.timers.tick(1);
            await Promise.resolve();
            await Promise.resolve();
        });
        assert.equal(MockWebSocket.instances.length, countBeforeCap + 1);

        unmount();
        mock.timers.reset();
    });

    it("unmount during pending backoff clears the reconnect timer so no reconnect fires", async () => {
        mock.timers.enable({ apis: ["setTimeout"] });
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));

        const { unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        act(() => MockWebSocket.instances[0].close());
        unmount();

        await act(async () => {
            mock.timers.runAll();
            await Promise.resolve();
            await Promise.resolve();
        });

        assert.equal(MockWebSocket.instances.length, 1);
        mock.timers.reset();
    });

    it("unmount detaches onclose so closing the (already-closing) socket after unmount doesn't schedule a reconnect", async () => {
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));
        const { unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        const socket = MockWebSocket.instances[0];
        unmount();
        assert.equal(socket.onclose, null);
    });

    it("onerror triggers close, routing into the same backoff path", async () => {
        mock.timers.enable({ apis: ["setTimeout"] });
        globalThis.fetch = mock.fn(async () => jsonResponse({ ticket: "tix" }));

        const { unmount } = renderHook(() => useSessionWebSocketContext(), { wrapper });
        await act(async () => {
            await Promise.resolve();
            await Promise.resolve();
        });

        act(() => MockWebSocket.instances[0].triggerError());
        assert.equal(MockWebSocket.instances[0].readyState, MockWebSocket.CLOSED);

        await act(async () => {
            mock.timers.tick(500);
            await Promise.resolve();
            await Promise.resolve();
        });
        assert.equal(MockWebSocket.instances.length, 2);

        unmount();
        mock.timers.reset();
    });
});
