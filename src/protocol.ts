/*
 * Wire-protocol constants shared by server and browser client.
 * Keep this module free of Node-only imports — it is bundled client-side.
 */

export const WEBSOCKET_SESSION_SERVER_SENDER_SERVER_MAGIC = "server";

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
