# @system-b90/session-ws

WebSocket session-server core (`/server`), HMAC connect tickets (`.`), browser-safe protocol constants (`/protocol`), and React client hooks (`/react`).

## Install

```powershell
"@system-b90:registry=https://npm.pkg.github.com" | Out-File -Append $HOME\.npmrc
"//npm.pkg.github.com/:_authToken=$env:GITHUB_TOKEN" | Out-File -Append $HOME\.npmrc

npm install @system-b90/session-ws
```

## Usage

```ts
// session-server/index.ts
import { startSessionServer } from "@system-b90/session-ws/server";
startSessionServer({ validMessageTypes: Object.values(MyMessageTypes) });
```

## Testing

Tests run against the built `dist/` output (the published surface) with Node's
built-in test runner:

```powershell
npm test              # builds, then runs tests/*.test.mjs
npm run test:coverage # same, with a coverage report
```

Test files live under `tests/`, one per source module (`common.test.mjs`,
`server.test.mjs`, `react-hook.test.mjs`), not colocated with `src/`, since
they import from `dist/` rather than `src/`.
## Mixed-privilege apps (staff/student, admin/viewer, per-tenant)

When not every socket may see everything, two pieces work together.

**Sign the privilege into the ticket.** The scope is inside the signed payload,
so the browser presenting the ticket cannot choose its own:

```ts
signWsTicket(user.id, isStaff ? "staff" : "student");
```

It arrives on every gate as `identity.scope`. Unscoped tickets stay valid and
report no scope, so a server can be upgraded before its clients.

**Gate both registrations.** `register-session` and `register-sync-provider`
are separate privileges, and the core handles both itself — an app cannot
refuse them from `onClientMessage`:

```ts
startSessionServer({
    // A registered session receives every *untargeted* broadcast. Deny the
    // low-privilege scope here, or `dispatchMessageToEveryone(type)` becomes a
    // way around every other gate.
    canRegisterSession: ({ scope }) => scope !== "student",
    // Subscriptions are a read primitive on that sync object's traffic.
    canListenToSyncObject: ({ scope }, id) =>
        scope === "student" ? id === "students" : true,
});
```

A denied socket stays connected and may still listen to sync objects it is
allowed; it is only excluded from the everyone-fan-out. `canRegisterSession`
defaults to allow, so single-privilege apps need no change.

**Declare the channels that may carry no payload.** A low-privilege channel is
usually meant to carry nothing but a "something changed, refetch" ping, so the
listener re-reads through an endpoint that applies the real projection. Keeping
that to a convention means one future call site passing data alongside the
target leaks it. Name the id instead, and the core strips `data` from every
broadcast that reaches it — through `dispatchToSyncObjectListeners`, through a
`targets` array, and through a server-sender frame alike:

```ts
payloadFreeSyncObjects: ["students"],
```

**Turn on single-use tickets and a connect budget for a hostile client.** A
ticket is short-lived but replayable within its TTL, so anyone who observes one
can open their own socket with the victim's scope until it expires; and without
a budget the pre-auth handshake is free work for an unauthenticated attacker:

```ts
singleUseTickets: true,        // second use of a ticket is refused (1008)
maxConnectsPerWindow: 60,      // per remote address, default
connectWindowMs: 60_000,
```

`singleUseTickets` is off by default because it breaks a client that opens more
than one socket per minted ticket; the React hook here mints one per connect
attempt, so it is safe to turn on with it.

Note the asymmetry in the defaults: `canListenToSyncObject` denies by default
(an unauthorized subscription reads another tenant's traffic), while
`canRegisterSession` allows by default (most apps have one privilege level, and
every socket here already passed ticket auth).

## Publishing

CI publishes on GitHub Release (or manual dispatch) via `.github/workflows/publish.yml`. Bump `version` in `package.json` before releasing.
