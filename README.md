# Sub Elite

Sub Elite is a mobile-first Mihomo config builder and converter. It converts proxy links, imports existing Mihomo YAML, lets users edit the generated config visually, and can create a subscription URL through a separate Cloudflare Worker API.

## Architecture

Sub Elite is split into two repositories and two Cloudflare deploy targets.

```text
Frontend repo: superencrypt-dev/sub-elite
Cloudflare Pages
├─ static frontend from dist/
└─ Pages Functions proxy for /api, /healthz, and /sub

Backend repo: superencrypt-dev/sub-elite-api
Cloudflare Worker
├─ GET  /healthz
├─ POST /api/convert
├─ POST /api/subscriptions
└─ GET  /sub/<secret>/config.yaml
```

The browser calls same-origin Pages routes by default:

```text
/api/convert
/api/subscriptions
/healthz
/sub/<secret>/config.yaml
```

Pages Functions forward those requests to the backend Worker. This keeps the Worker URL out of the browser-facing app code.

## Features

- Convert proxy links: `vmess://`, `vless://`, `trojan://`, `ss://`, `ssr://`, `socks5://`, `hysteria://`, `hy2://`, `hysteria2://`, `tuic://`, and `wireguard://`.
- Import existing Mihomo YAML into the visual editor.
- Reject `http://` and `https://` subscription URLs in the input box by design. Paste the actual config links or YAML instead.
- Generate a simple default output: `proxies`, one `select` proxy group, and `rules`.
- Edit YAML with Format, Validate, Auto-fix, Diff, Copy, and Download.
- Edit config visually through Nodes, Proxy Groups, Rules, DNS, Sniffer, TUN, Geo, Proxy Providers, and Rule Providers.
- Create manual nodes for common protocols and additional Mihomo proxy types.
- Keep Transport and TLS UX consistent between imported nodes and manually created nodes.
- Follow Mihomo transport structure for `ws`, `http`, `h2`, `grpc`, and `xhttp` where supported.
- Keep TLS optional. The `TLS` checkbox is off by default for protocols that use a TLS toggle.
- Select one or more ALPN values: `http/1.1`, `h2`, and `h3`.
- Store subscription YAML in Cloudflare KV through the backend API.

## Supported Manual Node Types

Common proxy types:

- `vmess`
- `vless`
- `trojan`
- `ss`
- `ssr`
- `socks5`
- `http`
- `hysteria`
- `hysteria2`
- `tuic`

Additional Mihomo proxy types:

- `snell`
- `anytls`
- `mieru`
- `sudoku`
- `masque`
- `trusttunnel`
- `wireguard`
- `ssh`

## Project Structure

```text
sub-elite/
  index.html
  public/
  src/
    app.js
    styles.css
  lib/
    converter.ts
  server/
    index.ts
    converter.test.js
  scripts/
    build-static.mjs
    make-zip.mjs
  dist/
  wrangler.toml
```

## Local Development

Install dependencies:

```sh
npm install
```

Run local preview:

```sh
npm run dev
```

Open:

```text
http://127.0.0.1:8787
```

Local preview serves the static frontend and local development API from the same origin.

## Build

Build static files:

```sh
npm run build
```

Output:

```text
dist/
```

## Cloudflare Pages Deploy

Use Cloudflare Pages Git Import for the frontend repository.

```text
Framework preset: None
Build command: npm run build
Build output directory: dist
Root directory: /
```

Optional Pages Function environment variable:

```text
SUB_ELITE_BACKEND_ORIGIN=https://sub-elite-api.stroke.workers.dev
```

The frontend proxy already has `https://sub-elite-api.stroke.workers.dev` as a built-in backend origin. Use `SUB_ELITE_BACKEND_ORIGIN` only if the backend Worker URL changes.

Recommended shared proxy secret:

```text
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-worker>
```

Set the same value in the `sub-elite-api` Worker. When the Worker has `SUB_ELITE_PROXY_SECRET`, direct POST requests to the Worker are rejected unless they come through the Pages Function proxy.

Optional browser-side override:

```text
SUB_ELITE_API_BASE_URL=https://sub-elite-api.<account>.workers.dev
```

Do not set `SUB_ELITE_API_BASE_URL` for normal production. It makes the browser call the Worker directly instead of using the same-origin Pages proxy.

`wrangler.toml` is only used for Pages metadata:

```toml
name = "sub-elite"
pages_build_output_dir = "./dist"
compatibility_date = "2026-05-10"
```

For the main production flow, use Git auto deploy instead of `wrangler pages deploy`.

## Backend API

Backend API source lives in a separate repository:

```text
https://github.com/superencrypt-dev/sub-elite-api
```

Worker Git deploy settings:

```text
Build command: npm ci
Deploy command: npx wrangler deploy
```

Backend KV binding:

```toml
[[kv_namespaces]]
binding = "SUBSCRIPTIONS"
id = "804df1bbafd644ad83b42f91161a547e"
```

After the Worker is deployed, the frontend Pages Functions will use `https://sub-elite-api.stroke.workers.dev` automatically. If the Worker URL changes, set the new URL in the frontend Pages environment variable `SUB_ELITE_BACKEND_ORIGIN`, then redeploy Pages.

For full hardening, set the same secret in both projects:

```text
sub-elite Pages:       SUB_ELITE_PROXY_SECRET=<random-secret>
sub-elite-api Worker:  SUB_ELITE_PROXY_SECRET=<same-random-secret>
```

## Subscription URL

The frontend creates subscriptions by calling:

```text
POST /api/subscriptions
```

The Worker returns a secret URL through the Pages proxy:

```text
https://<pages-domain>/sub/<secret>/config.yaml
```

Anyone with this URL can read the YAML, so treat it like a secret.

## Direct Upload ZIP

Create a static frontend ZIP for manual Cloudflare Pages upload:

```sh
npm run archive:cloudflare
```

Output:

```text
sub-elite-cloudflare-pages.zip
```

The ZIP contains only the static frontend. It does not include Pages Functions, so same-origin API proxying requires Git deploy. The backend still must be deployed separately as the `sub-elite-api` Worker.

## Checks

Run tests:

```sh
npm test
```

Run lint:

```sh
npm run lint
```

Build production files:

```sh
npm run build
```

## Notes

- The frontend is intentionally static and no-bundler friendly for Android/Termux shared storage.
- Core conversion logic is in `lib/converter.ts`.
- The frontend project contains only Pages proxy functions. Backend conversion and KV code belongs in `superencrypt-dev/sub-elite-api`.
- Static security headers are defined in `public/_headers`. Pages Functions add equivalent headers for proxied API responses.
- Generated YAML remains editable before it is copied, downloaded, or saved as a subscription URL.
