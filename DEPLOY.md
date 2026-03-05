# Deployment Guide

## Prerequisites

- **Node.js** 18 or later
- **Cloudflare account** with a Workers Paid plan (required for Browser Rendering)
- **Wrangler CLI** authenticated with your Cloudflare account

## 1. Install Dependencies

```bash
npm install
```

## 2. Authenticate Wrangler

If you haven't already:

```bash
npx wrangler login
```

This opens a browser window for OAuth. Once authenticated, Wrangler stores the token locally.

## 3. Create the KV Namespace

```bash
npx wrangler kv namespace create CACHE
```

This will output something like:

```
✨ Success!
Add the following to your configuration file:
[[kv_namespaces]]
binding = "CACHE"
id = "abc123def456..."
```

Copy the `id` value.

## 4. Configure wrangler.toml

Open `wrangler.toml` and fill in your values:

```toml
name = "cert-inspector"
main = "src/index.ts"
account_id = "YOUR_ACCOUNT_ID"          # ← Your Cloudflare account ID
compatibility_date = "2025-09-15"
compatibility_flags = ["nodejs_compat"]

[browser]
binding = "BROWSER"

[[kv_namespaces]]
binding = "CACHE"
id = "YOUR_KV_NAMESPACE_ID"             # ← From step 3

[assets]
directory = "./public"
```

**Finding your account ID:** Run `npx wrangler whoami` or check the Cloudflare dashboard URL — it's the hex string after `/accounts/`.

## 5. Deploy

```bash
npm run deploy
```

Wrangler will bundle the TypeScript, upload static assets, and deploy the Worker. It will print the live URL:

```
Deployed cert-inspector triggers
  https://cert-inspector.<your-subdomain>.workers.dev
```

## 6. Custom Domain (Optional)

To serve from your own domain, add a Custom Domain in the Cloudflare dashboard:

1. Go to **Workers & Pages** → **cert-inspector** → **Settings** → **Domains & Routes**
2. Click **Add** → **Custom Domain**
3. Enter your domain (e.g., `certs.example.com`)

The domain must be on a Cloudflare zone in your account.

## Local Development

```bash
npm run dev
```

This runs `wrangler dev --remote`, which is required because Browser Rendering is not available locally. The dev server proxies to Cloudflare's infrastructure while serving your local code.

Open `http://localhost:8787` to test.

## Updating

After making changes:

```bash
npm run typecheck  # Verify TypeScript compiles
npm run deploy     # Deploy changes
```

Only modified static assets are re-uploaded; the Worker bundle is always rebuilt.

## Troubleshooting

### "More than one account available"

Add `account_id` to `wrangler.toml` or set the `CLOUDFLARE_ACCOUNT_ID` environment variable.

### Browser Rendering not working

Browser Rendering requires a **Workers Paid plan**. Check your plan at **Cloudflare Dashboard** → **Workers & Pages** → **Plans**.

### KV namespace errors

Make sure the `id` in `wrangler.toml` matches the namespace you created. List your namespaces with:

```bash
npx wrangler kv namespace list
```

### "Stream was cancelled" for some domains

This is expected for domains behind Cloudflare's CDN. The app automatically falls back to Certificate Transparency logs for these domains (indicated by a Cloudflare logo in the UI).
