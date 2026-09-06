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

Note the asymmetry in the defaults: `canListenToSyncObject` denies by default
(an unauthorized subscription reads another tenant's traffic), while
`canRegisterSession` allows by default (most apps have one privilege level, and
every socket here already passed ticket auth).

## Publishing

CI publishes on GitHub Release (or manual dispatch) via `.github/workflows/publish.yml`. Bump `version` in `package.json` before releasing.
