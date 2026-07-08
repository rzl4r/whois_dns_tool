export interface DnsRecords {
  A?: Array<string | { address: string; ttl: number }>;
  AAAA?: Array<string | { address: string; ttl: number }>;
  MX?: Array<{ exchange: string; priority: number }>;
  NS?: string[];
  TXT?: string[][];
  CNAME?: string[];
  SOA?: {
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
  };
}

export interface GeolocationData {
  status: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  isp: string;
  org: string;
  as: string;
  query: string;
}

export interface SslInfo {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  protocol?: string;
  cipher?: string;
  error?: string;
}

export interface HeaderFinding {
  header: string;
  status: "missing" | "present";
  value?: string;
  score: number;
  maxScore: number;
  description: string;
}

export interface HeadersCheck {
  status: number;
  headers: Record<string, string>;
  grade: string;
  findings: HeaderFinding[];
}

export interface PortScanResult {
  port: number;
  service: string;
  open: boolean;
}

export interface WhoisData {
  domain_name?: string;
  registrar?: string;
  whois_server?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  name_servers?: string[];
  status?: string[];
  emails?: string[];
  org?: string;
  name?: string;
  country?: string;
}

export interface ThreatAssessment {
  registrar_lock_status?: string;
  domain_age_days?: number;
  email_spoofing_risk?: string;
  dnssec_enabled?: boolean;
  reputation_status?: string;
  risk_score?: number;
  security_recommendations?: string[];
}

export interface DomainAnalysis {
  domain: string;
  ip: string;
  timestamp: string;
  dns: DnsRecords;
  reverseDns: string[];
  geolocation?: GeolocationData | null;
  ssl?: SslInfo;
  headers?: HeadersCheck | null;
  ports?: PortScanResult[];
  whois: WhoisData;
  threatAssessment: ThreatAssessment;
}
