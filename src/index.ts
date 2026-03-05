import { Env, InspectionResult, InspectionSummary, DomainResult } from './types';
import { discoverDomains } from './inspector';
import { inspectAllCerts } from './tls';
import { resolveAllDns } from './dns';

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function jsonResponse(data: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(), ...extra },
  });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

function isValidUrl(input: string): boolean {
  try {
    const u = new URL(input);
    return (u.protocol === 'http:' || u.protocol === 'https:') && input.length <= 2048;
  } catch {
    return false;
  }
}

function cacheKey(url: string): string {
  return `inspect:${new URL(url).hostname}${new URL(url).pathname}`;
}

function buildSummary(domains: DomainResult[]): InspectionSummary {
  const summary: InspectionSummary = {
    totalDomains: domains.length,
    healthy: 0,
    expiring: 0,
    expired: 0,
    noHttps: 0,
  };

  for (const d of domains) {
    const status = d.cert?.status ?? 'no-https';
    if (status === 'healthy') summary.healthy++;
    else if (status === 'expiring') summary.expiring++;
    else if (status === 'expired') summary.expired++;
    else summary.noHttps++;
  }

  return summary;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // API routes
    if (url.pathname === '/api/inspect' && request.method === 'POST') {
      return handleInspect(request, env, ctx);
    }
    if (url.pathname === '/api/cache' && request.method === 'DELETE') {
      return handleCacheClear(request, env);
    }

    // Static assets
    return env.ASSETS.fetch(request);
  },
};

async function handleCacheClear(request: Request, env: Env): Promise<Response> {
  let body: { url?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const targetUrl = body.url;
  if (!targetUrl || typeof targetUrl !== 'string' || !isValidUrl(targetUrl)) {
    return errorResponse('Missing or invalid "url" field', 400);
  }

  await env.CACHE.delete(cacheKey(targetUrl));
  return jsonResponse({ cleared: true }, 200);
}

async function handleInspect(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  let body: { url?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const targetUrl = body.url;
  if (!targetUrl || typeof targetUrl !== 'string') {
    return errorResponse('Missing "url" field', 400);
  }
  if (!isValidUrl(targetUrl)) {
    return errorResponse('Invalid URL. Must be http/https and ≤2048 characters.', 400);
  }

  // Check KV cache
  const key = cacheKey(targetUrl);
  const cached = await env.CACHE.get(key, 'json');
  if (cached) {
    return jsonResponse(cached, 200, { 'X-Cache': 'HIT' });
  }

  // Discover all domains the page contacts
  const domains = await discoverDomains(env, targetUrl);

  // Inspect TLS certs and resolve DNS in parallel
  const [certsMap, dnsMap] = await Promise.all([
    inspectAllCerts(domains),
    resolveAllDns(domains),
  ]);

  // Assemble results
  const domainResults: DomainResult[] = domains
    .map((domain) => ({
      domain,
      cert: certsMap.get(domain) ?? null,
      dns: dnsMap.get(domain) ?? { a: [], aaaa: [], cname: [] },
    }))
    .sort((a, b) => {
      const order = { expired: 0, expiring: 1, 'no-https': 2, healthy: 3 };
      const sa = a.cert?.status ?? 'no-https';
      const sb = b.cert?.status ?? 'no-https';
      return order[sa] - order[sb];
    });

  const result: InspectionResult = {
    url: targetUrl,
    inspectedAt: new Date().toISOString(),
    domains: domainResults,
    summary: buildSummary(domainResults),
  };

  // Cache in background (1 hour TTL)
  ctx.waitUntil(env.CACHE.put(key, JSON.stringify(result), { expirationTtl: 3600 }));

  return jsonResponse(result, 200, { 'X-Cache': 'MISS' });
}
