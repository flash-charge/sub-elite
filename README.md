# Sub Elite

Sub Elite is a mobile-first Mihomo config builder and converter. It converts proxy links, imports existing Mihomo YAML, lets users edit the generated config visually, and can create a subscription URL through a separate Cloudflare Worker API.

## Architecture

Sub Elite uses two repositories and two Cloudflare targets.

```text
Frontend repo: https://github.com/flash-charge/sub-elite
Cloudflare Pages
├─ static frontend from dist/
└─ Pages Functions proxy for /api, /healthz, and /sub

Backend repo: https://github.com/flash-charge/sub-elite-api
Cloudflare Worker
├─ GET  /healthz
├─ POST /api/convert
├─ POST /api/subscriptions
└─ GET  /sub/<secret>/config.yaml
```

The browser should call same-origin Pages routes by default:

```text
/api/convert
/api/subscriptions
/healthz
/sub/<secret>/config.yaml
```

Pages Functions forward those requests to the backend Worker. This keeps the Worker URL and proxy secret out of browser code.

## Features

- Convert proxy links: `vmess://`, `vless://`, `trojan://`, `ss://`, `ssr://`, `socks5://`, `hysteria://`, `hy2://`, `hysteria2://`, `tuic://`, and `wireguard://`.
- Import existing Mihomo YAML into the visual editor.
- Reject `http://` and `https://` subscription URLs in the input box by design. Paste the actual config links or YAML instead.
- Generate a simple default output: `proxies`, one `select` proxy group, and `rules`.
- Edit YAML with Format, Validate, Auto-fix, Diff, Copy, and Download.
- Edit config visually through Nodes, Proxy Groups, Rules, DNS, Sniffer, TUN, Geo, Proxy Providers, and Rule Providers.
- Store subscription YAML in Cloudflare KV through the backend API.

## Project Structure

```text
sub-elite/
  index.html
  public/
  src/
  lib/
  server/
  scripts/
  functions/
  dist/
  wrangler.toml
```

## Local Development

```sh
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:8787
```

Build static files:

```sh
npm run build
```

Run checks:

```sh
npm test
npm run lint
```

## Required Cloudflare Settings

Production should rely on Cloudflare settings. The source code does not include a default backend.

Set these in **Cloudflare Pages > sub-elite > Settings > Environment variables** for production:

```text
SUB_ELITE_BACKEND_ORIGIN=https://<your-worker-subdomain>.workers.dev
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-worker>
```

Do not set `SUB_ELITE_API_BASE_URL` for normal production. If it is set, the browser calls the Worker directly instead of using the same-origin Pages proxy.

The matching Worker secret must be set in `sub-elite-api`:

```text
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-pages>
```

After changing Pages environment variables or secrets, redeploy Pages.

## Deploy Order

Deploy the backend first, then the frontend.

1. Deploy `sub-elite-api` Worker.
2. Confirm `https://<your-worker-subdomain>.workers.dev/healthz` returns `{"ok":true}`.
3. Set `SUB_ELITE_BACKEND_ORIGIN` and `SUB_ELITE_PROXY_SECRET` in Pages.
4. Deploy this frontend.
5. Test `/healthz`, `/api/convert`, and `/api/subscriptions` from the Pages domain.

## Deploy via Cloudflare Pages Upload

This method uploads static assets from `dist`.

```sh
npm install
npm run archive:cloudflare
```

Upload the generated file in Cloudflare Dashboard:

```text
sub-elite-cloudflare-pages.zip
```

Dashboard path:

```text
Cloudflare Dashboard > Workers & Pages > Pages > Create project > Upload assets
```

Important limitation: static upload does not include Pages Functions in the same way Git/Wrangler Pages deployment does. For the normal production flow with `/api`, `/healthz`, and `/sub` proxy routes, use **Deploy via Wrangler** or **Connect GitHub**.

If you use upload-only static hosting, the browser must call the Worker directly by building with `SUB_ELITE_API_BASE_URL`. Do not use this mode with a private `SUB_ELITE_PROXY_SECRET`, because the static frontend intentionally does not expose that secret to the browser.

## Deploy via Wrangler

Login and verify account:

```sh
npx wrangler login
npx wrangler whoami
```

Build and deploy Pages:

```sh
npm install
npm run build
npx wrangler pages deploy dist --project-name sub-elite --branch master
```

Check deployments:

```sh
npx wrangler pages deployment list --project-name sub-elite
```

Set or rotate Pages secrets:

```sh
printf '%s' '<same-random-secret-as-worker>' \
  | npx wrangler pages secret put SUB_ELITE_PROXY_SECRET --project-name sub-elite

printf '%s' 'https://<your-worker-subdomain>.workers.dev' \
  | npx wrangler pages secret put SUB_ELITE_BACKEND_ORIGIN --project-name sub-elite
```

Redeploy after changing secrets or variables:

```sh
npm run build
npx wrangler pages deploy dist --project-name sub-elite --branch master
```

## Deploy via Connect GitHub

In Cloudflare Dashboard:

```text
Workers & Pages > Pages > Create project > Connect to Git
```

Select:

```text
Repository: flash-charge/sub-elite
Production branch: master
Framework preset: None
Build command: npm run build
Build output directory: dist
Root directory: /
```

Set production environment variables/secrets in the Pages project:

```text
SUB_ELITE_BACKEND_ORIGIN=https://<your-worker-subdomain>.workers.dev
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-worker>
```

Then trigger a deployment from Cloudflare or push to `master`.

## Verify Production

Replace the domain with the active Pages domain or custom domain.

```sh
curl https://sub-elite-d3e.pages.dev/healthz

curl -X POST https://sub-elite-d3e.pages.dev/api/convert \
  -H 'content-type: application/json' \
  --data '{"input":"trojan://secret@example.com:443#Test"}'

curl -X POST https://sub-elite-d3e.pages.dev/api/subscriptions \
  -H 'content-type: application/json' \
  --data '{"yaml":"proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n","expiresIn":"7d"}'
```

Expected:

```text
/healthz -> 200 {"ok":true}
/api/convert -> 200 with yaml and stats
/api/subscriptions -> 200 with same-origin /sub/<secret>/config.yaml URL
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

## Notes

- `wrangler.toml` defines Pages metadata only.
- Cloudflare Pages settings must define the active backend origin. The source code does not include a default backend.
- Static security headers are defined in `public/_headers`. Pages Functions add equivalent headers for proxied API responses.
- Generated YAML remains editable before it is copied, downloaded, or saved as a subscription URL.
