export type CertStatus = 'healthy' | 'expiring' | 'expired' | 'no-https';

export interface CertInfo {
  subjectName: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  protocol: string;
  sans: string[];
  status: CertStatus;
  daysUntilExpiry: number;
}

export interface DnsRecords {
  a: string[];
  aaaa: string[];
  cname: string[];
}

export interface DomainResult {
  domain: string;
  cert: CertInfo | null;
  dns: DnsRecords;
}

export interface InspectionSummary {
  totalDomains: number;
  healthy: number;
  expiring: number;
  expired: number;
  noHttps: number;
}

export interface InspectionResult {
  url: string;
  inspectedAt: string;
  domains: DomainResult[];
  summary: InspectionSummary;
}

export interface Env {
  BROWSER: Fetcher;
  CACHE: KVNamespace;
  ASSETS: Fetcher;
}
