import { DnsRecords } from './types';

interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DnsResponse {
  Answer?: DnsAnswer[];
}

const DNS_TYPES = { A: 1, AAAA: 28, CNAME: 5 } as const;

async function queryDns(domain: string, type: string): Promise<string[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
    const resp = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
      signal: controller.signal,
    });

    if (!resp.ok) return [];

    const data = (await resp.json()) as DnsResponse;
    const typeNum = DNS_TYPES[type as keyof typeof DNS_TYPES];
    return (data.Answer ?? [])
      .filter((a) => a.type === typeNum)
      .map((a) => a.data.replace(/\.$/,  ''));
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

export async function resolveDns(domain: string): Promise<DnsRecords> {
  const [a, aaaa, cname] = await Promise.all([
    queryDns(domain, 'A'),
    queryDns(domain, 'AAAA'),
    queryDns(domain, 'CNAME'),
  ]);
  return { a, aaaa, cname };
}

export async function resolveAllDns(domains: string[]): Promise<Map<string, DnsRecords>> {
  const results = new Map<string, DnsRecords>();
  const batchSize = 10;

  for (let i = 0; i < domains.length; i += batchSize) {
    const batch = domains.slice(i, i + batchSize);
    const resolved = await Promise.all(batch.map((d) => resolveDns(d)));
    batch.forEach((domain, idx) => results.set(domain, resolved[idx]));
  }

  return results;
}
