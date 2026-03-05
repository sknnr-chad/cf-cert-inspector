# cf-cert-inspector

Inspect TLS certificates and DNS records for every domain a webpage contacts — built entirely on Cloudflare's platform.

Enter a URL and a headless browser navigates to it, discovering every domain the page reaches out to (JS-loaded resources, ads, trackers, APIs). Each domain's TLS certificate is then inspected and its DNS records resolved, all without leaving Cloudflare's network.

> Inspired by [shanselman/cert-inspector](https://github.com/shanselman/cert-inspector)

## How It Works

```
URL submitted
  └─▸ Cloudflare Browser Rendering navigates the page
        └─▸ Every contacted domain is collected
              ├─▸ TLS cert extracted via raw TCP handshake (port 443)
              │     └─▸ Falls back to Certificate Transparency logs
              │         for Cloudflare-proxied origins
              ├─▸ DNS resolved via Cloudflare DoH (A, AAAA, CNAME)
              └─▸ Results cached in KV (1 hour TTL)
```

### Certificate Inspection — Two Methods

**Direct TLS handshake** — The Worker opens a raw TCP connection to port 443, sends a TLS 1.2 ClientHello with SNI, and parses the server's X.509 certificate directly from the handshake response. This extracts the real subject, issuer, validity dates, SANs, and protocol version with zero external dependencies.

**Certificate Transparency fallback** — Cloudflare Workers cannot open raw TCP sockets to Cloudflare's own edge. For domains behind Cloudflare's CDN, the Worker queries [crt.sh](https://crt.sh) to find the most recently issued certificate from public CT logs. These domains are marked with a Cloudflare logo and tooltip in the UI.

## Cloudflare Stack

| Layer | Service | Purpose |
|---|---|---|
| Frontend | **Pages (static assets)** | Vanilla HTML/CSS/JS |
| API | **Workers** | Request routing, orchestration |
| Browser | **Browser Rendering** | Headless Chromium via `@cloudflare/puppeteer` |
| TLS | **TCP Sockets (`connect()`)** | Raw TLS handshake for cert extraction |
| DNS | **Cloudflare DoH** | `cloudflare-dns.com/dns-query` JSON API |
| Cache | **KV** | Cached inspection results (1hr TTL) |

## Features

- **Domain discovery** — Headless browser captures every domain a page contacts, including lazy-loaded resources and third-party scripts
- **Real certificate data** — Subject, issuer, validity dates, SANs, protocol version, and days until expiry
- **Certificate health** — Status classified as healthy (>30d), expiring (≤30d), or expired
- **DNS records** — A, AAAA, and CNAME resolution for every discovered domain
- **Three result views** — Detailed table with expandable rows, summary cards, and a visual expiry timeline
- **Dark/light theme** — Toggleable, persisted in localStorage
- **Cache management** — Results cached for 1 hour; clear cache button for on-demand refresh
- **JSON export** — Download full inspection results as a JSON file
- **Responsive** — Works on desktop and mobile

## Project Structure

```
cert-inspector/
├── public/
│   ├── index.html        # SPA shell: URL input, 3 view tabs, result containers
│   ├── styles.css        # Dark/light theming, status colors, responsive layout
│   └── app.js            # Form handling, API calls, view renderers, export
├── src/
│   ├── index.ts          # Worker entry: router, orchestration, KV caching
│   ├── inspector.ts      # Browser Rendering: domain discovery via Puppeteer
│   ├── tls.ts            # Raw TLS handshake + X.509 parser + CT fallback
│   ├── dns.ts            # DNS lookups via Cloudflare DoH
│   └── types.ts          # Shared TypeScript interfaces
├── wrangler.toml         # Bindings: browser, KV, static assets
├── package.json
└── tsconfig.json
```

## Setup

See [DEPLOY.md](DEPLOY.md) for full deployment instructions.

**Quick start:**

```bash
npm install
# Edit wrangler.toml with your account_id and KV namespace ID
npm run dev    # Local dev (requires --remote for Browser Rendering)
npm run deploy # Deploy to Cloudflare
```

## License

[MIT](LICENSE)
