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

## Publishing

CI publishes on GitHub Release (or manual dispatch) via `.github/workflows/publish.yml`. Bump `version` in `package.json` before releasing.
