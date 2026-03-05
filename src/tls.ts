import { connect } from 'cloudflare:sockets';
import { CertInfo, CertStatus } from './types';

// ===== ASN.1 DER Parser =====

interface DerElement {
  tagByte: number;
  tagNumber: number;
  cls: number;
  constructed: boolean;
  contents: Uint8Array;
  totalLength: number;
}

function parseDer(data: Uint8Array, offset: number = 0): DerElement | null {
  if (offset >= data.length) return null;

  const start = offset;
  const tagByte = data[offset++];
  const cls = (tagByte >> 6) & 3;
  const constructed = !!(tagByte & 0x20);
  let tagNumber = tagByte & 0x1f;

  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let b: number;
    do {
      if (offset >= data.length) return null;
      b = data[offset++];
      tagNumber = (tagNumber << 7) | (b & 0x7f);
    } while (b & 0x80);
  }

  if (offset >= data.length) return null;
  let length = data[offset++];
  if (length & 0x80) {
    const n = length & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) {
      if (offset >= data.length) return null;
      length = (length << 8) | data[offset++];
    }
  }

  if (offset + length > data.length) return null;

  return {
    tagByte,
    tagNumber,
    cls,
    constructed,
    contents: data.subarray(offset, offset + length),
    totalLength: (offset - start) + length,
  };
}

function parseChildren(data: Uint8Array): DerElement[] {
  const result: DerElement[] = [];
  let offset = 0;
  while (offset < data.length) {
    const el = parseDer(data, offset);
    if (!el) break;
    result.push(el);
    offset += el.totalLength;
  }
  return result;
}

function derOidToString(data: Uint8Array): string {
  if (data.length === 0) return '';
  const parts: number[] = [Math.floor(data[0] / 40), data[0] % 40];
  let val = 0;
  for (let i = 1; i < data.length; i++) {
    val = (val << 7) | (data[i] & 0x7f);
    if (!(data[i] & 0x80)) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join('.');
}

function derToString(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

function derToTime(tagByte: number, data: Uint8Array): Date {
  const s = derToString(data);
  if (tagByte === 0x17) {
    const y = parseInt(s.slice(0, 2));
    return new Date(
      `${y >= 50 ? 1900 + y : 2000 + y}-${s.slice(2, 4)}-${s.slice(4, 6)}T${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}Z`,
    );
  }
  return new Date(
    `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`,
  );
}

// ===== X.509 Certificate Parser =====

interface X509Info {
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
  sans: string[];
}

function extractNameField(nameData: Uint8Array, oid: string): string {
  for (const rdnSet of parseChildren(nameData)) {
    if (rdnSet.tagByte !== 0x31) continue;
    for (const atv of parseChildren(rdnSet.contents)) {
      if (atv.tagByte !== 0x30) continue;
      const parts = parseChildren(atv.contents);
      if (parts.length >= 2 && parts[0].tagByte === 0x06) {
        if (derOidToString(parts[0].contents) === oid) {
          return derToString(parts[1].contents);
        }
      }
    }
  }
  return '';
}

function extractSANs(extensionsData: Uint8Array): string[] {
  const sans: string[] = [];
  for (const ext of parseChildren(extensionsData)) {
    if (ext.tagByte !== 0x30) continue;
    const parts = parseChildren(ext.contents);
    if (parts.length < 2 || parts[0].tagByte !== 0x06) continue;
    if (derOidToString(parts[0].contents) !== '2.5.29.17') continue;

    const valuePart = parts[parts.length - 1];
    if (valuePart.tagByte !== 0x04) continue;

    const sanSeq = parseDer(valuePart.contents);
    if (!sanSeq || sanSeq.tagByte !== 0x30) continue;

    for (const name of parseChildren(sanSeq.contents)) {
      if (name.cls === 2 && name.tagNumber === 2) {
        sans.push(derToString(name.contents));
      }
    }
  }
  return sans;
}

function parseX509(certDer: Uint8Array): X509Info | null {
  const cert = parseDer(certDer);
  if (!cert || cert.tagByte !== 0x30) return null;

  const certParts = parseChildren(cert.contents);
  if (certParts.length < 1) return null;

  const tbs = certParts[0];
  if (tbs.tagByte !== 0x30) return null;

  const fields = parseChildren(tbs.contents);
  let idx = 0;

  // version [0] EXPLICIT — optional
  if (fields[idx]?.cls === 2 && fields[idx]?.tagNumber === 0) idx++;
  // serialNumber
  idx++;
  // signature AlgorithmIdentifier
  idx++;

  // issuer
  const issuerEl = fields[idx++];
  const issuer =
    issuerEl
      ? extractNameField(issuerEl.contents, '2.5.4.10') ||
        extractNameField(issuerEl.contents, '2.5.4.3')
      : '';

  // validity
  const validityEl = fields[idx++];
  let validFrom = new Date(0);
  let validTo = new Date(0);
  if (validityEl) {
    const times = parseChildren(validityEl.contents);
    if (times.length >= 2) {
      validFrom = derToTime(times[0].tagByte, times[0].contents);
      validTo = derToTime(times[1].tagByte, times[1].contents);
    }
  }

  // subject
  const subjectEl = fields[idx++];
  const subject =
    subjectEl
      ? extractNameField(subjectEl.contents, '2.5.4.3') ||
        extractNameField(subjectEl.contents, '2.5.4.10')
      : '';

  // subjectPublicKeyInfo
  idx++;

  // skip optional issuerUniqueID [1], subjectUniqueID [2]
  while (idx < fields.length && fields[idx].cls === 2 && fields[idx].tagNumber <= 2) idx++;

  // extensions [3]
  let sans: string[] = [];
  if (idx < fields.length && fields[idx].cls === 2 && fields[idx].tagNumber === 3) {
    const extSeq = parseDer(fields[idx].contents);
    if (extSeq && extSeq.tagByte === 0x30) {
      sans = extractSANs(extSeq.contents);
    }
  }

  return { subject, issuer, validFrom, validTo, sans };
}

// ===== TLS ClientHello Builder =====

function u8(v: number): Uint8Array {
  return new Uint8Array([v]);
}
function u16(v: number): Uint8Array {
  return new Uint8Array([(v >> 8) & 0xff, v & 0xff]);
}
function u24(v: number): Uint8Array {
  return new Uint8Array([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
}
function cat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
function ext(type: number, data: Uint8Array): Uint8Array {
  return cat([u16(type), u16(data.length), data]);
}

function buildClientHello(hostname: string): Uint8Array {
  const host = new TextEncoder().encode(hostname);

  const sni = ext(
    0x0000,
    cat([u16(host.length + 3), u8(0), u16(host.length), host]),
  );
  const sigAlgs = ext(
    0x000d,
    cat([u16(8), u16(0x0401), u16(0x0403), u16(0x0501), u16(0x0601)]),
  );
  const groups = ext(0x000a, cat([u16(6), u16(0x0017), u16(0x0018), u16(0x001d)]));
  const ecPf = ext(0x000b, cat([u8(1), u8(0)]));

  const extensions = cat([sni, sigAlgs, groups, ecPf]);

  const ciphers = cat([
    u16(0xc02f), u16(0xc02b), u16(0x009c),
    u16(0xc030), u16(0xc02c), u16(0x009d),
  ]);

  const random = new Uint8Array(32);
  crypto.getRandomValues(random);

  const body = cat([
    u16(0x0303), random, u8(0),
    u16(ciphers.length), ciphers,
    u8(1), u8(0),
    u16(extensions.length), extensions,
  ]);

  const hs = cat([u8(0x01), u24(body.length), body]);

  return cat([u8(0x16), u16(0x0301), u16(hs.length), hs]);
}

// ===== TLS Response Parser =====

interface TlsParseResult {
  certDer: Uint8Array;
  protocol: string;
}

const VERSION_NAMES: Record<number, string> = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
};

function extractFromTls(data: Uint8Array): TlsParseResult | null {
  // Collect handshake payload from all handshake records
  const hsBuf: Uint8Array[] = [];
  let off = 0;

  while (off + 5 <= data.length) {
    const ctype = data[off];
    const rlen = (data[off + 3] << 8) | data[off + 4];
    off += 5;
    if (off + rlen > data.length) break;
    if (ctype === 0x16) hsBuf.push(data.subarray(off, off + rlen));
    else if (ctype === 0x15) return null; // alert
    off += rlen;
  }

  const hs = cat(hsBuf);

  let protocol = 'TLS 1.2';
  let certDer: Uint8Array | null = null;
  let hsOff = 0;

  while (hsOff + 4 <= hs.length) {
    const msgType = hs[hsOff];
    const msgLen = (hs[hsOff + 1] << 16) | (hs[hsOff + 2] << 8) | hs[hsOff + 3];
    hsOff += 4;
    if (hsOff + msgLen > hs.length) break;

    if (msgType === 0x02) {
      // ServerHello — first 2 bytes are version
      const ver = (hs[hsOff] << 8) | hs[hsOff + 1];
      protocol = VERSION_NAMES[ver] ?? `TLS 0x${ver.toString(16)}`;
    }

    if (msgType === 0x0b) {
      // Certificate message
      const cData = hs.subarray(hsOff, hsOff + msgLen);
      if (cData.length >= 6) {
        const firstLen = (cData[3] << 16) | (cData[4] << 8) | cData[5];
        if (cData.length >= 6 + firstLen) {
          certDer = cData.subarray(6, 6 + firstLen);
        }
      }
    }

    hsOff += msgLen;
  }

  if (!certDer) return null;
  return { certDer, protocol };
}

// ===== Public API =====

function computeStatus(validTo: Date): { status: CertStatus; daysUntilExpiry: number } {
  const days = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);
  const status: CertStatus = days < 0 ? 'expired' : days <= 30 ? 'expiring' : 'healthy';
  return { status, daysUntilExpiry: days };
}

export interface InspectDiag {
  stage: string;
  bytesRead: number;
  firstBytes: string;
  error?: string;
}

// --- CT Log Fallback (crt.sh) ---

interface CrtShEntry {
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
}

function certCoversHostname(nameValue: string, hostname: string): boolean {
  const names = nameValue.split('\n').map((s) => s.trim()).filter(Boolean);
  return names.some((name) => {
    if (name === hostname) return true;
    if (name.startsWith('*.')) {
      const wildcard = name.slice(2);
      const parent = hostname.split('.').slice(1).join('.');
      return parent === wildcard;
    }
    return false;
  });
}

async function ctFetch(query: string, signal: AbortSignal): Promise<CrtShEntry[]> {
  try {
    const resp = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(query)}&output=json&exclude=expired`,
      { signal },
    );
    if (!resp.ok) return [];
    return (await resp.json()) as CrtShEntry[];
  } catch {
    return [];
  }
}

async function ctLookup(hostname: string): Promise<CertInfo | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    // Try exact hostname first, then parent domain
    let entries = await ctFetch(hostname, controller.signal);

    if (!entries.length) {
      const parts = hostname.split('.');
      if (parts.length > 2) {
        const parent = parts.slice(1).join('.');
        entries = await ctFetch(parent, controller.signal);
      }
    }

    if (!entries.length) return null;

    // Filter to certs that actually cover this hostname
    const matching = entries.filter((e) => certCoversHostname(e.name_value, hostname));
    const pool = matching.length ? matching : entries;

    // Most recently issued cert first
    pool.sort(
      (a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime(),
    );

    const e = pool[0];
    const validTo = new Date(e.not_after);
    const { status, daysUntilExpiry } = computeStatus(validTo);

    const issuerMatch = e.issuer_name.match(/O=([^,]+)/);
    const issuer = issuerMatch
      ? issuerMatch[1].trim()
      : (e.issuer_name.match(/CN=([^,]+)/)?.[1]?.trim() ?? e.issuer_name);

    const sans = e.name_value
      .split(/\n/)
      .map((s) => s.trim())
      .filter(Boolean);

    return {
      subjectName: e.common_name,
      issuer,
      validFrom: new Date(e.not_before).toISOString(),
      validTo: validTo.toISOString(),
      protocol: 'TLS (CT)',
      sans,
      status,
      daysUntilExpiry,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// --- Raw TLS handshake ---

async function rawTlsInspect(hostname: string, d: InspectDiag): Promise<CertInfo | null> {
  try {
    d.stage = 'connecting';
    const socket = connect(
      { hostname, port: 443 },
      { secureTransport: 'off', allowHalfOpen: false },
    );
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    try {
      d.stage = 'sending-hello';
      await writer.write(buildClientHello(hostname));

      d.stage = 'reading';
      const chunks: Uint8Array[] = [];
      let total = 0;
      const deadline = Date.now() + 5000;

      while (total < 65536) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          d.stage = 'timeout';
          break;
        }

        const sleepTimer = new Promise<ReadableStreamReadResult<Uint8Array>>((resolve) => {
          setTimeout(() => resolve({ value: undefined as any, done: true }), remaining);
        });

        const { value, done } = await Promise.race([reader.read(), sleepTimer]);
        if (done || !value) break;
        chunks.push(value);
        total += value.length;

        const combined = cat(chunks);
        d.bytesRead = total;
        d.firstBytes = Array.from(combined.slice(0, 20))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(' ');

        const result = extractFromTls(combined);
        if (result) {
          d.stage = 'parsing-x509';
          const x509 = parseX509(result.certDer);
          if (x509) {
            d.stage = 'done';
            const { status, daysUntilExpiry } = computeStatus(x509.validTo);
            return {
              subjectName: x509.subject,
              issuer: x509.issuer,
              validFrom: x509.validFrom.toISOString(),
              validTo: x509.validTo.toISOString(),
              protocol: result.protocol,
              sans: x509.sans,
              status,
              daysUntilExpiry,
            };
          }
        }
      }

      d.stage = total === 0 ? 'no-data' : `no-cert-in-${total}-bytes`;
      return null;
    } finally {
      try { reader.cancel(); } catch {}
      try { writer.close(); } catch {}
      try { socket.close(); } catch {}
    }
  } catch (err) {
    d.stage = 'error';
    d.error = String(err);
    return null;
  }
}

// --- Public API: raw TLS first, CT fallback ---

export interface InspectDiag {
  stage: string;
  bytesRead: number;
  firstBytes: string;
  error?: string;
}

export async function inspectCert(
  hostname: string,
  diag?: InspectDiag,
): Promise<CertInfo | null> {
  const d = diag ?? { stage: '', bytesRead: 0, firstBytes: '' };

  const cert = await rawTlsInspect(hostname, d);
  if (cert) return cert;

  // Fallback to Certificate Transparency logs
  d.stage = 'ct-fallback';
  const ctCert = await ctLookup(hostname);
  if (ctCert) d.stage = 'done-ct';
  return ctCert;
}

export async function inspectAllCerts(domains: string[]): Promise<Map<string, CertInfo>> {
  const results = new Map<string, CertInfo>();
  const batchSize = 5;

  for (let i = 0; i < domains.length; i += batchSize) {
    const batch = domains.slice(i, i + batchSize);
    const certs = await Promise.all(batch.map((d) => inspectCert(d)));
    batch.forEach((domain, idx) => {
      const cert = certs[idx];
      if (cert) results.set(domain, cert);
    });
  }

  return results;
}
