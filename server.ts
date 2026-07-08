import express from "express";
import path from "path";
import dns from "dns";
import net from "net";
import tls from "tls";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini Client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

// Normalize domain helper
function cleanDomain(input: string): string {
  let cleaned = input.trim().toLowerCase();
  cleaned = cleaned.replace(/^(https?:\/\/)?(www\.)?/, "");
  cleaned = cleaned.split("/")[0].split(":")[0];
  return cleaned;
}

// Timeout helper for promises
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, defaultValue: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(defaultValue), timeoutMs))
  ]);
}

// 1. Resolve DNS records
async function getDnsRecords(domain: string) {
  const recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"] as const;
  const results: Record<string, any> = {};

  const promises = recordTypes.map(async (rtype) => {
    try {
      const records = await dns.promises.resolve(domain, rtype);
      results[rtype] = records;
    } catch (e: any) {
      results[rtype] = [];
    }
  });

  await Promise.all(promises);
  return results;
}

// 2. Resolve primary IP
async function getPrimaryIp(domain: string): Promise<string | null> {
  try {
    const lookup = await dns.promises.lookup(domain);
    return lookup.address;
  } catch (e) {
    return null;
  }
}

// 3. Reverse DNS (PTR)
async function getReverseDns(ip: string): Promise<string[]> {
  try {
    return await dns.promises.reverse(ip);
  } catch (e) {
    return [];
  }
}

// 4. IP Geolocation via ip-api.com
async function getIpGeo(ip: string) {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    if (response.ok) {
      const data = await response.json();
      if (data.status === "success") {
        return data;
      }
    }
  } catch (e) {
    console.error("Geo lookup failed:", e);
  }
  return null;
}

// 5. SSL Certificate Inspection
interface SslResult {
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

function inspectSsl(domain: string): Promise<SslResult> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false // We inspect self-signed/invalid certs too
    }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();

        if (!cert || !Object.keys(cert).length) {
          resolve({ valid: false, error: "No SSL certificate returned" });
          socket.destroy();
          return;
        }

        const validFrom = cert.valid_from;
        const validTo = cert.valid_to;
        const daysRemaining = Math.max(0, Math.round((new Date(validTo).getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
        const valid = socket.authorized && daysRemaining > 0;

        const formatCertField = (field: any): string | undefined => {
          if (!field) return undefined;
          if (typeof field === 'string') return field;
          const val = field.O || field.CN;
          if (Array.isArray(val)) return val.join(", ");
          return val;
        };

        resolve({
          valid,
          issuer: formatCertField(cert.issuer),
          subject: formatCertField(cert.subject),
          validFrom,
          validTo,
          daysRemaining,
          protocol: protocol || undefined,
          cipher: cipher ? `${cipher.name} (${cipher.version})` : undefined
        });
      } catch (err: any) {
        resolve({ valid: false, error: err.message });
      }
      socket.destroy();
    });

    socket.setTimeout(3500);
    socket.on("timeout", () => {
      resolve({ valid: false, error: "TLS handshake connection timed out" });
      socket.destroy();
    });

    socket.on("error", (err) => {
      resolve({ valid: false, error: err.message });
      socket.destroy();
    });
  });
}

// 6. Security Headers Check
interface HeadersResult {
  status: number;
  headers: Record<string, string>;
  grade: string;
  findings: Array<{ header: string; status: "missing" | "present"; value?: string; score: number; maxScore: number; description: string }>;
}

async function checkSecurityHeaders(domain: string): Promise<HeadersResult | null> {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 4000);
    
    const response = await fetch(`https://${domain}`, {
      method: "GET",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WHOIS-DNS-Scanner/1.0" },
      signal: controller.signal
    }).catch(async () => {
      // Retry HTTP if HTTPS fails
      return await fetch(`http://${domain}`, {
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WHOIS-DNS-Scanner/1.0" },
        signal: controller.signal
      });
    });

    clearTimeout(id);

    const headersObj: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headersObj[key.toLowerCase()] = value;
    });

    const checklist = [
      {
        key: "strict-transport-security",
        name: "Strict-Transport-Security (HSTS)",
        description: "Enforces secure HTTPS connections",
        maxScore: 20
      },
      {
        key: "content-security-policy",
        name: "Content-Security-Policy (CSP)",
        description: "Prevents XSS and injection attacks",
        maxScore: 25
      },
      {
        key: "x-frame-options",
        name: "X-Frame-Options",
        description: "Protects against clickjacking",
        maxScore: 15
      },
      {
        key: "x-content-type-options",
        name: "X-Content-Type-Options",
        description: "Prevents MIME-sniffing exploits",
        maxScore: 15
      },
      {
        key: "referrer-policy",
        name: "Referrer-Policy",
        description: "Controls referrer leakage",
        maxScore: 15
      },
      {
        key: "permissions-policy",
        name: "Permissions-Policy",
        description: "Restricts access to browser APIs",
        maxScore: 10
      }
    ];

    let score = 0;
    const findings = checklist.map((item) => {
      const val = headersObj[item.key];
      const present = !!val;
      const itemScore = present ? item.maxScore : 0;
      score += itemScore;

      return {
        header: item.name,
        status: present ? "present" as const : "missing" as const,
        value: val,
        score: itemScore,
        maxScore: item.maxScore,
        description: item.description
      };
    });

    // Calculate Letter Grade
    let grade = "F";
    if (score >= 90) grade = "A+";
    else if (score >= 80) grade = "A";
    else if (score >= 65) grade = "B";
    else if (score >= 45) grade = "C";
    else if (score >= 20) grade = "D";

    return {
      status: response.status,
      headers: headersObj,
      grade,
      findings
    };
  } catch (e) {
    return null;
  }
}

// 7. Light/Safe Port Scanner
interface PortResult {
  port: number;
  service: string;
  open: boolean;
}

const COMMON_PORTS = [
  { port: 21, service: "FTP" },
  { port: 22, service: "SSH" },
  { port: 25, service: "SMTP" },
  { port: 53, service: "DNS" },
  { port: 80, service: "HTTP" },
  { port: 110, service: "POP3" },
  { port: 143, service: "IMAP" },
  { port: 443, service: "HTTPS" },
  { port: 3306, service: "MySQL" },
  { port: 8080, service: "HTTP-ALT" }
];

function scanPort(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isFinished = false;

    socket.connect(port, host, () => {
      if (!isFinished) {
        isFinished = true;
        resolve(true);
        socket.destroy();
      }
    });

    socket.setTimeout(1200);

    socket.on("timeout", () => {
      if (!isFinished) {
        isFinished = true;
        resolve(false);
        socket.destroy();
      }
    });

    socket.on("error", () => {
      if (!isFinished) {
        isFinished = true;
        resolve(false);
        socket.destroy();
      }
    });
  });
}

async function performPortScan(host: string): Promise<PortResult[]> {
  const promises = COMMON_PORTS.map(async (p) => {
    const open = await scanPort(host, p.port);
    return {
      port: p.port,
      service: p.service,
      open
    };
  });
  return Promise.all(promises);
}

// 8. Fetch WHOIS & Intelligence via Gemini API Grounded Search
async function getWhoisAndIntelligence(domain: string) {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: `You are an expert Cybersecurity Intelligence agent. Your task is to extract real-time WHOIS registration data and formulate a domain threat assessment for the domain: "${domain}".

Conduct a live web search to acquire actual WHOIS information for "${domain}". Return a structured JSON matching this schema exactly.

Expected schema format:
{
  "whois": {
    "domain_name": "string",
    "registrar": "string",
    "whois_server": "string",
    "creation_date": "string (YYYY-MM-DD)",
    "expiration_date": "string (YYYY-MM-DD)",
    "updated_date": "string (YYYY-MM-DD)",
    "name_servers": ["string"],
    "status": ["string"],
    "emails": ["string"],
    "org": "string",
    "name": "string",
    "country": "string"
  },
  "threat_assessment": {
    "registrar_lock_status": "string (Active/Inactive/Unknown)",
    "domain_age_days": number,
    "email_spoofing_risk": "string (High/Medium/Low with brief justification)",
    "dnssec_enabled": boolean,
    "reputation_status": "string (Clean/Flagged/Suspicious)",
    "risk_score": number (0 to 100),
    "security_recommendations": ["string"]
  }
}

Do not add markdown formatting or extra text outside the JSON. Return only the parsable JSON string.`,
      config: {
        tools: [{ googleSearch: {} }],
        responseMimeType: "application/json"
      }
    });

    const rawText = response.text || "";
    return JSON.parse(rawText.trim());
  } catch (err: any) {
    console.error("Gemini lookup failed:", err);
    // Return standard fallback
    return {
      whois: {
        domain_name: domain,
        registrar: "Unavailable",
        whois_server: "Unavailable",
        creation_date: "Unavailable",
        expiration_date: "Unavailable",
        updated_date: "Unavailable",
        name_servers: [],
        status: [],
        emails: [],
        org: "Unavailable",
        name: "Unavailable",
        country: "Unavailable"
      },
      threat_assessment: {
        registrar_lock_status: "Unknown",
        domain_age_days: 0,
        email_spoofing_risk: "Unknown",
        dnssec_enabled: false,
        reputation_status: "Clean",
        risk_score: 15,
        security_recommendations: [
          "Enable DNSSEC on your DNS registry to prevent cache poisoning.",
          "Ensure your registrar lock is enabled to avoid unauthorized domain transfers.",
          "Establish robust SPF, DKIM, and DMARC TXT records."
        ]
      }
    };
  }
}

// REST API endpoint for domain analysis
app.post("/api/analyze", async (req, res) => {
  const { target } = req.body;
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Missing or invalid domain parameter" });
  }

  const domain = cleanDomain(target);
  if (!domain) {
    return res.status(400).json({ error: "Invalid domain format" });
  }

  try {
    // Stage 1: Resolve IP & simple checks
    const primaryIp = await getPrimaryIp(domain);
    if (!primaryIp) {
      return res.status(404).json({ error: "Could not resolve domain IP. Ensure target is correct." });
    }

    // Run parallel analyses
    const [
      dnsRecords,
      reverseDns,
      geolocation,
      sslInfo,
      headersCheck,
      portScan,
      intelligence
    ] = await Promise.all([
      getDnsRecords(domain),
      getReverseDns(primaryIp),
      getIpGeo(primaryIp),
      inspectSsl(domain),
      checkSecurityHeaders(domain),
      performPortScan(primaryIp),
      getWhoisAndIntelligence(domain)
    ]);

    res.json({
      domain,
      ip: primaryIp,
      timestamp: new Date().toISOString(),
      dns: dnsRecords,
      reverseDns,
      geolocation,
      ssl: sslInfo,
      headers: headersCheck,
      ports: portScan,
      whois: intelligence.whois || {},
      threatAssessment: intelligence.threat_assessment || {}
    });

  } catch (error: any) {
    console.error("Analysis handler failed:", error);
    res.status(500).json({ error: "Internal server scanning error: " + error.message });
  }
});

// Configure Vite middleware in development
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
if (!process.env.VERCEL) {
  startServer();
}

export default app;


