/*
 * Wire-protocol constants shared by server and browser client.
 * Keep this module free of Node-only imports — it is bundled client-side.
 */

export const WEBSOCKET_SESSION_SERVER_SENDER_SERVER_MAGIC = "server";

/**
 * Connect tickets ride as a WebSocket subprotocol (`ticket.<urlencoded>`)
 * rather than a query parameter, which would be written to proxy access logs.
 * The browser WebSocket API cannot set request headers, so a subprotocol is the
 * only header-borne channel available on connect.
 */
export const TICKET_SUBPROTOCOL_PREFIX = "ticket.";

export function ticketSubprotocol(ticket: string): string {
    return `${TICKET_SUBPROTOCOL_PREFIX}${encodeURIComponent(ticket)}`;
}

/**
 * Core protocol message types the shared server core handles itself.
 * Apps extend the wire vocabulary with their own string values and pass the
 * full set to `startSessionServer({ validMessageTypes })`.
 */
export enum CoreMessageTypes {
    REGISTER_SESSION = "register-session",
    REGISTER_SYNC_PROVIDER = "register-sync-provider",
    SYNC_OBJECT_UPDATE = "sync-object-update",
    DEREGISTER_SYNC_PROVIDER = "deregister-sync-provider",
}
