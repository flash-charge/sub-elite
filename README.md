# Sub Elite

Sub Elite is a mobile-first Mihomo/Clash Meta config builder and subconverter. It converts proxy links, imports existing Mihomo YAML, provides a visual config editor, and creates permanent subscription URLs.

## Features

- Convert proxy links: `vmess://`, `vless://`, `trojan://`, `ss://`, `ssr://`, `socks5://`, `hysteria://`, `hy2://`, `tuic://`, `wireguard://`
- Import existing Mihomo YAML or fetch from URL
- Visual editor: Nodes, Proxy Groups, Rules, DNS, Sniffer, TUN, Geo, Proxy/Rule Providers
- Rule presets: Proxy, LAN Direct, Indonesia Direct, Privacy (Ads block), Direct
- Subscription URL: Create, Update (same URL), permanent (no expiry)
- Dark mode (auto follows system)
- PWA: installable, offline-capable
- Mobile-first responsive design with tablet breakpoint

## Architecture

```text
Frontend: https://github.com/flash-charge/sub-elite
  Cloudflare Pages (static + Pages Functions proxy)

Backend: https://github.com/flash-charge/sub-elite-api
  Cloudflare Worker (API + KV storage)
```

Routes proxied by Pages Functions:

```text
POST   /api/convert
POST   /api/subscriptions
PUT    /api/subscriptions/:secret
DELETE /api/subscriptions/:secret
GET    /api/subscriptions
GET    /healthz
GET    /sub/<secret>/<filename>.yaml
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

Set production environment variables/secrets:

```text
SUB_ELITE_BACKEND_ORIGIN=https://<your-worker-subdomain>.workers.dev
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-worker>
```

Push to `master` triggers automatic deployment.

## Deploy via Wrangler

```sh
npm install
npx wrangler login
npm run build
npx wrangler pages deploy dist --project-name sub-elite --branch master
```

Set secrets:

```sh
printf '%s' '<worker-url>' | npx wrangler pages secret put SUB_ELITE_BACKEND_ORIGIN --project-name sub-elite
printf '%s' '<secret>' | npx wrangler pages secret put SUB_ELITE_PROXY_SECRET --project-name sub-elite
```

## Local Development

```sh
npm install
npm run dev       # build + start dev server on :8787
npm run build     # build static files to dist/
npm test          # run tests
npm run lint      # eslint
npm run mihomo:check # validate generated sample YAML with local mihomo
```

## OpenVPN Manual Node Example

In the Editor tab, choose `Node` > `Manual Node` > `OpenVPN`. Fill `Server`,
`Port`, `CA`, and `TLS Crypt`. Authentication can use `Username`/`Password`
or a `Cert`/`Key` pair.

```yaml
proxies:
  - name: "OpenVPN Example"
    type: "openvpn"
    server: "vpn.example.com"
    port: 1194
    proto: "udp"
    username: "vpn-user"
    password: "vpn-password"
    ca: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    tls-crypt: |
      -----BEGIN OpenVPN Static key V1-----
      ...
      -----END OpenVPN Static key V1-----
    dev: "tun"
    cipher: "AES-128-GCM"
    auth: "SHA256"
    udp: true
```

## Deploy Order

1. Deploy `sub-elite-api` Worker first
2. Confirm `https://<worker>.workers.dev/healthz` returns `{"ok":true}`
3. Set `SUB_ELITE_BACKEND_ORIGIN` and `SUB_ELITE_PROXY_SECRET` in Pages
4. Deploy this frontend (push to master or wrangler deploy)
5. Test from Pages domain: `/healthz`, `/api/convert`

## Project Structure

```text
sub-elite/
  index.html              # Single page HTML
  public/                 # Static assets (_headers, manifest, icons)
  src/
    app.js                # Entry, event listeners, init
    state.js              # State object, DOM selectors
    constants.ts          # Option arrays, type maps
    utils.ts              # Shared utility functions
    model.ts              # Model normalization
    nodes.js              # Node list rendering/editing
    groups.js             # Proxy group rendering/editing
    rules.js              # Rules editor
    providers.js          # Rule/proxy providers
    editors.js            # DNS, general, sniffer, tun, geo editors
    yaml-tools.js         # Format, validate, diff, export
    proxy-fields.js       # TLS, protocol, transport rendering
    manual-node.js        # Manual node form builder
  lib/
    converter.ts          # Config model, YAML generation
    helpers.ts            # Shared converter utilities
    parsers.ts            # Link parsing
  functions/              # Cloudflare Pages Functions (proxy)
  server/                 # Dev server
  scripts/                # Build scripts
  dist/                   # Built output (gitignored)
```

## Subscription URL

```text
Create:  POST /api/subscriptions → returns URL
Update:  PUT /api/subscriptions/:secret → overwrites YAML, URL unchanged
```

The secret is stored in browser localStorage. Button shows "Update URL" when a previous subscription exists, "Create URL" otherwise. Click "New URL" to reset and create a fresh subscription.

All subscriptions are permanent (no expiry). The filename in the URL matches the File Name field.

## Notes

- `wrangler.toml` defines Pages metadata only
- Security headers in `public/_headers` and Pages Functions
- Config output follows https://wiki.metacubex.one/ field order
- Tested against Mihomo v1.19.10 binary
