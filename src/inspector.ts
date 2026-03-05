import puppeteer from '@cloudflare/puppeteer';
import { Env } from './types';

export async function discoverDomains(env: Env, url: string): Promise<string[]> {
  const domainSet = new Set<string>();

  const browser = await puppeteer.launch(env.BROWSER);
  const page = await browser.newPage();

  page.on('response', (response) => {
    try {
      domainSet.add(new URL(response.url()).hostname);
    } catch {}
  });

  try {
    await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });
  } catch {
    // Non-fatal — return whatever was captured
  }

  // Catch late async requests
  await new Promise((r) => setTimeout(r, 2000));
  await browser.close();

  return Array.from(domainSet);
}
