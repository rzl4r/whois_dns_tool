import React from "react";
import { 
  Globe, 
  MapPin, 
  Clock, 
  Cpu, 
  ShieldAlert, 
  CheckCircle, 
  XCircle, 
  Layers, 
  Zap, 
  FileText, 
  Download, 
  Copy, 
  Check, 
  Info,
  ExternalLink
} from "lucide-react";
import { DomainAnalysis } from "../types";

interface ResultsPresenterProps {
  data: DomainAnalysis;
}

export default function ResultsPresenter({ data }: ResultsPresenterProps) {
  const [copiedSection, setCopiedSection] = React.useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(label);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const downloadReport = () => {
    const reportText = `WHOIS & DNS SECURITY RECON REPORT
========================================
Target Domain : ${data.domain}
Primary IP    : ${data.ip}
Report Time   : ${new Date(data.timestamp).toLocaleString()}
========================================

[+] GEOLOCATION INFORMATION
---------------------------
Country       : ${data.geolocation?.country || "N/A"} (${data.geolocation?.countryCode || "N/A"})
City / Region : ${data.geolocation?.city || "N/A"}, ${data.geolocation?.regionName || "N/A"}
ZIP / Latitude: ${data.geolocation?.zip || "N/A"} (Lat: ${data.geolocation?.lat}, Lon: ${data.geolocation?.lon})
ISP           : ${data.geolocation?.isp || "N/A"}
ASN / Org     : ${data.geolocation?.as || "N/A"} / ${data.geolocation?.org || "N/A"}
Timezone      : ${data.geolocation?.timezone || "N/A"}

[+] THREAT & COMPLIANCE ASSESSMENT
---------------------------
Risk Score    : ${data.threatAssessment?.risk_score ?? "N/A"}/100
Reputation    : ${data.threatAssessment?.reputation_status || "N/A"}
Domain Age    : ${data.threatAssessment?.domain_age_days ?? "N/A"} days
Spoofing Risk : ${data.threatAssessment?.email_spoofing_risk || "N/A"}
DNSSEC        : ${data.threatAssessment?.dnssec_enabled ? "Enabled" : "Disabled"}
Registrar Lock: ${data.threatAssessment?.registrar_lock_status || "N/A"}

[+] WHOIS INFORMATION
---------------------------
Registrar     : ${data.whois?.registrar || "N/A"}
Created Date  : ${data.whois?.creation_date || "N/A"}
Expires Date  : ${data.whois?.expiration_date || "N/A"}
Updated Date  : ${data.whois?.updated_date || "N/A"}
Org Name      : ${data.whois?.org || "N/A"}
Admin Email   : ${data.whois?.emails ? (Array.isArray(data.whois.emails) ? data.whois.emails.join(", ") : data.whois.emails) : "N/A"}
Name Servers  : ${data.whois?.name_servers ? (Array.isArray(data.whois.name_servers) ? data.whois.name_servers.join(", ") : data.whois.name_servers) : "N/A"}

[+] DNS RECORDS
---------------------------
A Records     : ${JSON.stringify(data.dns?.A || [], null, 2)}
AAAA Records  : ${JSON.stringify(data.dns?.AAAA || [], null, 2)}
MX Records    : ${JSON.stringify(data.dns?.MX || [], null, 2)}
NS Records    : ${JSON.stringify(data.dns?.NS || [], null, 2)}
TXT Records   : ${JSON.stringify(data.dns?.TXT || [], null, 2)}
CNAME Records : ${JSON.stringify(data.dns?.CNAME || [], null, 2)}
SOA Record    : ${JSON.stringify(data.dns?.SOA || {}, null, 2)}
Reverse DNS   : ${data.reverseDns?.join(", ") || "None"}

[+] SSL CERTIFICATE INSPECTION
---------------------------
Certificate   : ${data.ssl?.valid ? "VALID" : "INVALID"}
Issuer        : ${data.ssl?.issuer || "N/A"}
Subject       : ${data.ssl?.subject || "N/A"}
Valid From    : ${data.ssl?.validFrom || "N/A"}
Valid To      : ${data.ssl?.validTo || "N/A"}
Days Left     : ${data.ssl?.daysRemaining ?? 0} days
Cipher / Proto: ${data.ssl?.cipher || "N/A"} / ${data.ssl?.protocol || "N/A"}
Error Msg     : ${data.ssl?.error || "None"}

[+] OPEN PORT SCANNER
---------------------------
${data.ports?.map(p => `Port ${p.port} (${p.service}): ${p.open ? "OPEN" : "CLOSED"}`).join("\n") || "No ports scanned"}

[+] SECURITY RECOMMENDATIONS
---------------------------
${data.threatAssessment?.security_recommendations?.map((r, i) => `${i + 1}. ${r}`).join("\n") || "No custom recommendations"}
`;

    const blob = new Blob([reportText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${data.domain}_recon_report.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getRiskColor = (score: number) => {
    if (score < 25) return "text-brand-success bg-brand-success/10 border-brand-success/20";
    if (score < 60) return "text-brand-warning bg-brand-warning/10 border-brand-warning/20";
    return "text-brand-danger bg-brand-danger/10 border-brand-danger/20";
  };

  const getRiskRing = (score: number) => {
    if (score < 25) return "stroke-brand-success";
    if (score < 60) return "stroke-brand-warning";
    return "stroke-brand-danger";
  };

  const getHeaderGradeColor = (grade: string) => {
    if (grade.startsWith("A")) return "text-brand-success bg-brand-success/10 border-brand-success/20";
    if (grade.startsWith("B")) return "text-brand-success/80 bg-brand-success/10 border-brand-success/20";
    if (grade.startsWith("C")) return "text-brand-warning bg-brand-warning/10 border-brand-warning/20";
    if (grade.startsWith("D")) return "text-brand-warning/80 bg-brand-warning/10 border-brand-warning/20";
    return "text-brand-danger bg-brand-danger/10 border-brand-danger/20";
  };

  return (
    <div className="space-y-6">
      {/* Target Status Header Card */}
      <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-brand-accent/15 text-brand-accent rounded-xl border border-brand-accent/25">
            <Globe className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl md:text-2xl font-black text-brand-main tracking-tight">{data.domain}</h2>
              <span className="px-2.5 py-0.5 text-xs font-bold text-brand-success bg-brand-success/10 border border-brand-success/20 rounded-full flex items-center gap-1 uppercase tracking-wider">
                <CheckCircle className="w-3.5 h-3.5" /> Scanned
              </span>
            </div>
            <p className="text-sm text-brand-dim mt-1">
              Primary IP Address: <span className="font-mono bg-brand-bg text-brand-main border border-brand-border px-2 py-0.5 rounded text-xs">{data.ip}</span>
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => copyToClipboard(JSON.stringify(data, null, 2), "json")}
            className="px-4 py-2.5 text-xs font-bold text-brand-main bg-brand-bg hover:bg-brand-bg/80 border border-brand-border rounded-xl transition flex items-center gap-2 cursor-pointer uppercase tracking-wider"
          >
            {copiedSection === "json" ? (
              <>
                <Check className="w-4 h-4 text-brand-success" />
                <span>Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-4 h-4 text-brand-dim" />
                <span>Copy Raw JSON</span>
              </>
            )}
          </button>

          <button
            onClick={downloadReport}
            className="px-4 py-2.5 text-xs font-bold text-brand-bg bg-brand-accent hover:bg-brand-accent/90 border border-brand-accent/30 rounded-xl transition shadow-xs flex items-center gap-2 cursor-pointer uppercase tracking-wider"
          >
            <Download className="w-4 h-4" />
            <span>Download Report (.txt)</span>
          </button>
        </div>
      </div>

      {/* Grid: Risk Dial & Quick Intel Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Risk Dial Card */}
        <div className="lg:col-span-4 bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-brand-main uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-brand-dim" /> Security Risk Score
            </h3>
            <p className="text-xs text-brand-dim mb-6">Aggregated vulnerability, compliance, and threat intelligence score.</p>
          </div>

          <div className="relative flex items-center justify-center my-4">
            <svg className="w-40 h-40 transform -rotate-90">
              <circle
                cx="80"
                cy="80"
                r="70"
                className="stroke-brand-bg fill-none"
                strokeWidth="10"
              />
              <circle
                cx="80"
                cy="80"
                r="70"
                className={`fill-none transition-all duration-1000 ${getRiskRing(data.threatAssessment.risk_score ?? 15)}`}
                strokeWidth="12"
                strokeDasharray={439.8}
                strokeDashoffset={439.8 - (439.8 * (data.threatAssessment.risk_score ?? 15)) / 100}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="text-4xl font-black text-brand-main tracking-tight font-mono">{data.threatAssessment.risk_score ?? 15}</span>
              <span className="text-[10px] font-bold text-brand-dim uppercase tracking-wider">/ 100 Risk</span>
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-brand-border text-center">
            <span className={`inline-block text-xs font-black px-3.5 py-1.5 rounded-lg border ${getRiskColor(data.threatAssessment.risk_score ?? 15)}`}>
              {(data.threatAssessment.risk_score ?? 15) < 25 ? "LOW SECURITY THREAT" : (data.threatAssessment.risk_score ?? 15) < 60 ? "MEDIUM SECURITY RISK" : "HIGH SECURITY RISK"}
            </span>
          </div>
        </div>

        {/* IP Geolocation and Network Details */}
        <div className="lg:col-span-8 bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-brand-main uppercase tracking-wider mb-4 flex items-center gap-1.5">
              <MapPin className="w-4 h-4 text-brand-accent" /> IP Geolocation & ASN Intelligence
            </h3>
            
            {data.geolocation ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4 text-sm">
                <div className="space-y-3">
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">Country</span>
                    <span className="text-brand-main font-semibold">{data.geolocation.country} ({data.geolocation.countryCode})</span>
                  </div>
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">City / Region</span>
                    <span className="text-brand-main font-semibold">{data.geolocation.city}, {data.geolocation.regionName}</span>
                  </div>
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">ZIP Code</span>
                    <span className="text-brand-main font-mono font-semibold">{data.geolocation.zip || "N/A"}</span>
                  </div>
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">Timezone</span>
                    <span className="text-brand-main font-semibold">{data.geolocation.timezone}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">ISP Provider</span>
                    <span className="text-brand-main font-semibold text-right truncate max-w-[180px]" title={data.geolocation.isp}>{data.geolocation.isp}</span>
                  </div>
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">ASN Number</span>
                    <span className="text-brand-accent font-mono font-semibold truncate max-w-[180px]">{data.geolocation.as.split(" ")[0]}</span>
                  </div>
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">Coordinates</span>
                    <span className="text-brand-main font-semibold">{data.geolocation.lat.toFixed(4)}, {data.geolocation.lon.toFixed(4)}</span>
                  </div>
                  <div className="flex justify-between border-b border-brand-border/40 pb-2">
                    <span className="text-brand-dim font-medium">Reverse DNS (PTR)</span>
                    <span className="text-brand-main font-mono text-xs truncate max-w-[180px]" title={data.reverseDns?.join(", ") || "None"}>
                      {data.reverseDns?.[0] || "None resolved"}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-brand-dim text-sm">
                No Geolocation data found for this IP.
              </div>
            )}
          </div>

          {/* Simple Static Mini-Map View */}
          {data.geolocation && (
            <div className="mt-6 p-4 bg-brand-bg border border-brand-border rounded-xl flex items-center justify-between text-xs text-brand-dim">
              <span className="flex items-center gap-1.5">
                <Clock className="w-4 h-4 text-brand-dim" />
                <span>Geographic Local Scan Node Time: {new Date().toLocaleTimeString()}</span>
              </span>
              <a
                href={`https://www.google.com/maps?q=${data.geolocation.lat},${data.geolocation.lon}`}
                target="_blank"
                referrerPolicy="no-referrer"
                rel="noreferrer"
                className="text-brand-accent hover:text-brand-accent/80 font-bold flex items-center gap-1"
              >
                <span>Google Maps View</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          )}
        </div>
      </div>

      {/* Grid: Threat Intelligence & SSL Inspection */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Assessment Summary */}
        <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md">
          <h3 className="text-base font-bold text-brand-main mb-4 pb-2 border-b border-brand-border flex items-center gap-1.5">
            <Cpu className="w-5 h-5 text-brand-accent" /> Security Assessment Intel
          </h3>

          <div className="grid grid-cols-2 gap-4 mb-6">
            <div className="p-3 bg-brand-bg border border-brand-border rounded-xl">
              <span className="text-xs text-brand-dim block font-medium">Domain Age</span>
              <span className="text-lg font-bold text-brand-main mt-1 block font-mono">
                {data.threatAssessment.domain_age_days ? `${data.threatAssessment.domain_age_days} days` : "Unknown"}
              </span>
            </div>
            
            <div className="p-3 bg-brand-bg border border-brand-border rounded-xl">
              <span className="text-xs text-brand-dim block font-medium">Spoofing Risk</span>
              <span className="text-lg font-bold text-brand-main mt-1 block capitalize">
                {data.threatAssessment.email_spoofing_risk || "Low"}
              </span>
            </div>

            <div className="p-3 bg-brand-bg border border-brand-border rounded-xl">
              <span className="text-xs text-brand-dim block font-medium">DNSSEC Status</span>
              <span className={`text-base font-bold mt-1 block flex items-center gap-1 ${data.threatAssessment.dnssec_enabled ? "text-brand-success" : "text-brand-warning"}`}>
                {data.threatAssessment.dnssec_enabled ? (
                  <CheckCircle className="w-4 h-4 inline" />
                ) : (
                  <XCircle className="w-4 h-4 inline" />
                )}
                {data.threatAssessment.dnssec_enabled ? "Enabled" : "Disabled"}
              </span>
            </div>

            <div className="p-3 bg-brand-bg border border-brand-border rounded-xl">
              <span className="text-xs text-brand-dim block font-medium">Registry Lock</span>
              <span className="text-base font-bold text-brand-main mt-1 block">
                {data.threatAssessment.registrar_lock_status || "Active / Safe"}
              </span>
            </div>
          </div>

          <h4 className="text-xs font-bold text-brand-dim uppercase tracking-wider mb-2.5">Security Recommendations</h4>
          <ul className="space-y-2">
            {(data.threatAssessment.security_recommendations || [
              "Enable registrar-level transfer lock configuration.",
              "Enforce strict Content Security Policy headers.",
              "Sign DNS records with DNSSEC security protocols."
            ]).map((rec, idx) => (
              <li key={idx} className="text-sm text-brand-main flex items-start gap-2.5">
                <span className="mt-0.5 w-5 h-5 bg-brand-accent/10 text-brand-accent border border-brand-accent/20 rounded-full flex items-center justify-center text-xs font-bold shrink-0">
                  {idx + 1}
                </span>
                <span className="mt-0.5 text-brand-dim">{rec}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* SSL Certificate Verification */}
        <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md">
          <h3 className="text-base font-bold text-brand-main mb-4 pb-2 border-b border-brand-border flex items-center gap-1.5">
            <CheckCircle className="w-5 h-5 text-brand-accent" /> SSL Certificate Inspection
          </h3>

          {data.ssl && !data.ssl.error ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 bg-brand-success/10 border border-brand-success/20 rounded-xl">
                <CheckCircle className="w-6 h-6 text-brand-success shrink-0" />
                <div>
                  <h4 className="text-sm font-bold text-brand-success">SSL Handshake Authorized</h4>
                  <p className="text-xs text-brand-dim mt-0.5">TLS Connection securely established on Port 443 with valid cipher configuration.</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm pt-2">
                <div className="space-y-2">
                  <div>
                    <span className="text-xs text-brand-dim block font-medium">Subject CN (Common Name)</span>
                    <span className="text-brand-main font-semibold truncate block font-mono text-xs" title={data.ssl.subject}>{data.ssl.subject || "N/A"}</span>
                  </div>
                  <div>
                    <span className="text-xs text-brand-dim block font-medium">Certificate Authority Issuer</span>
                    <span className="text-brand-main font-semibold truncate block font-mono text-xs" title={data.ssl.issuer}>{data.ssl.issuer || "N/A"}</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <div>
                    <span className="text-xs text-brand-dim block font-medium">Expiration Date</span>
                    <span className="text-brand-main font-semibold block">{data.ssl.validTo ? new Date(data.ssl.validTo).toLocaleDateString() : "N/A"}</span>
                  </div>
                  <div>
                    <span className="text-xs text-brand-dim block font-medium">Days Left Until Expiry</span>
                    <span className={`font-mono font-bold ${data.ssl.daysRemaining && data.ssl.daysRemaining < 30 ? "text-brand-danger" : "text-brand-success"}`}>
                      {data.ssl.daysRemaining ?? 0} Days
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-4 p-3 bg-brand-bg border border-brand-border rounded-xl space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-brand-dim font-medium">Protocol Version:</span>
                  <span className="text-brand-main font-mono font-semibold">{data.ssl.protocol || "N/A"}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-brand-dim font-medium">Active Cryptographic Cipher:</span>
                  <span className="text-brand-main font-mono text-right truncate max-w-[220px] text-[11px]" title={data.ssl.cipher}>{data.ssl.cipher || "N/A"}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 bg-brand-danger/10 border border-brand-danger/20 rounded-xl">
                <XCircle className="w-6 h-6 text-brand-danger shrink-0" />
                <div>
                  <h4 className="text-sm font-bold text-brand-danger">SSL Validation Error</h4>
                  <p className="text-xs text-brand-dim mt-0.5">TLS Certificate is self-signed, invalid, or port 443 is blocked/closed.</p>
                </div>
              </div>
              <p className="text-xs font-semibold text-brand-dim mt-2">Error Log Trace:</p>
              <div className="p-3 bg-brand-bg border border-brand-border rounded-xl text-xs font-mono text-brand-danger leading-normal">
                {data.ssl?.error || "Connection timed out during handshake."}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Security Headers Card */}
      {data.headers && (
        <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-brand-border gap-4 mb-6">
            <div>
              <h3 className="text-base font-bold text-brand-main flex items-center gap-1.5">
                <Layers className="w-5 h-5 text-brand-accent" /> HTTP Security Headers Check
              </h3>
              <p className="text-xs text-brand-dim mt-1">Validation of web defense mechanisms preventing frame injection and clickjacking.</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-brand-dim font-medium">Compliance Score Grade:</span>
              <span className={`text-xl font-black px-3.5 py-1 rounded-xl shadow-xs border ${getHeaderGradeColor(data.headers.grade)}`}>
                {data.headers.grade}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {data.headers.findings.map((item, idx) => (
              <div 
                key={idx} 
                className={`p-4 border rounded-xl flex items-start gap-3 transition hover:shadow-xs ${
                  item.status === "present" 
                    ? "bg-brand-bg/40 border-brand-border/60" 
                    : "bg-brand-warning/5 border-brand-warning/15"
                }`}
              >
                <div className="mt-0.5">
                  {item.status === "present" ? (
                    <CheckCircle className="w-5 h-5 text-brand-success shrink-0" />
                  ) : (
                    <XCircle className="w-5 h-5 text-brand-warning shrink-0" />
                  )}
                </div>
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <h4 className="text-sm font-bold text-brand-main truncate font-mono">{item.header}</h4>
                    <span className="text-[10px] font-mono font-bold text-brand-dim bg-brand-bg px-2 py-0.5 border border-brand-border rounded shrink-0">
                      {item.score}/{item.maxScore} pts
                    </span>
                  </div>
                  <p className="text-xs text-brand-dim font-medium">{item.description}</p>
                  {item.status === "present" && item.value && (
                    <div className="p-1.5 bg-brand-bg/85 border border-brand-border rounded text-[10px] font-mono text-brand-accent truncate" title={item.value}>
                      {item.value}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* WHOIS Core Display */}
      <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md">
        <div className="flex justify-between items-center pb-4 border-b border-brand-border mb-6">
          <h3 className="text-base font-bold text-brand-main flex items-center gap-1.5">
            <FileText className="w-5 h-5 text-brand-accent" /> WHOIS Domain Records
          </h3>
          <button
            onClick={() => copyToClipboard(JSON.stringify(data.whois, null, 2), "whois")}
            className="text-xs text-brand-accent hover:text-brand-accent/80 font-bold flex items-center gap-1 cursor-pointer uppercase tracking-wider"
          >
            {copiedSection === "whois" ? "Copied WHOIS!" : "Copy Raw WHOIS"}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-y-4 gap-x-8 text-sm">
          <div className="space-y-2">
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Domain Name</span>
              <span className="text-brand-main font-semibold font-mono">{data.whois?.domain_name || data.domain}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Domain Registrar</span>
              <span className="text-brand-main font-semibold">{data.whois?.registrar || "Unavailable"}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">WHOIS Server</span>
              <span className="text-brand-main font-mono font-semibold text-xs">{data.whois?.whois_server || "Unavailable"}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Creation Date</span>
              <span className="text-brand-main font-semibold font-mono text-xs">{data.whois?.creation_date || "Unavailable"}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Expiration Date</span>
              <span className="text-brand-main font-semibold font-mono text-xs">{data.whois?.expiration_date || "Unavailable"}</span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Updated Date</span>
              <span className="text-brand-main font-semibold font-mono text-xs">{data.whois?.updated_date || "Unavailable"}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Organization</span>
              <span className="text-brand-main font-semibold text-right max-w-[200px] truncate" title={data.whois?.org}>{data.whois?.org || "Protected / Hidden"}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Admin Country</span>
              <span className="text-brand-main font-semibold">{data.whois?.country || "Protected / Hidden"}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Admin Emails</span>
              <span className="text-brand-main font-semibold truncate max-w-[220px] text-xs font-mono" title={Array.isArray(data.whois?.emails) ? data.whois?.emails.join(", ") : data.whois?.emails}>
                {data.whois?.emails ? (Array.isArray(data.whois.emails) ? data.whois.emails[0] : data.whois.emails) : "Hidden"}
              </span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Name Servers</span>
              <span className="text-brand-accent text-xs font-mono text-right max-w-[220px] truncate" title={Array.isArray(data.whois?.name_servers) ? data.whois?.name_servers.join(", ") : data.whois?.name_servers}>
                {Array.isArray(data.whois?.name_servers) ? data.whois.name_servers.slice(0, 2).join(", ") : data.whois?.name_servers || "Protected"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* DNS Records Tabular View */}
      <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md">
        <h3 className="text-base font-bold text-brand-main pb-4 border-b border-brand-border mb-6 flex items-center gap-1.5">
          <Globe className="w-5 h-5 text-brand-accent" /> DNS Record Set
        </h3>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            {/* A and AAAA */}
            <div>
              <h4 className="text-xs font-bold text-brand-dim uppercase tracking-wider mb-2 font-mono">A Records (IPv4 Resolved Mapping)</h4>
              <div className="bg-brand-bg border border-brand-border rounded-xl p-3 max-h-40 overflow-y-auto">
                {data.dns?.A && data.dns.A.length > 0 ? (
                  <ul className="space-y-1 text-xs font-mono text-brand-main">
                    {data.dns.A.map((rec: any, idx) => (
                      <li key={idx} className="flex justify-between py-1 border-b border-brand-border/40 last:border-0">
                        <span>{typeof rec === 'string' ? rec : rec.address}</span>
                        {typeof rec !== 'string' && rec.ttl && <span className="text-brand-dim">TTL: {rec.ttl}s</span>}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-brand-dim">No IPv4 mapping records parsed.</p>
                )}
              </div>
            </div>

            {/* MX and TXT */}
            <div>
              <h4 className="text-xs font-bold text-brand-dim uppercase tracking-wider mb-2 font-mono">MX Records (Mail Server Delivery Agents)</h4>
              <div className="bg-brand-bg border border-brand-border rounded-xl p-3 max-h-40 overflow-y-auto">
                {data.dns?.MX && data.dns.MX.length > 0 ? (
                  <ul className="space-y-1.5 text-xs font-mono text-brand-main">
                    {data.dns.MX.map((rec: any, idx) => (
                      <li key={idx} className="flex justify-between py-1 border-b border-brand-border/40 last:border-0">
                        <span className="truncate max-w-[240px]" title={rec.exchange}>{rec.exchange}</span>
                        <span className="text-brand-accent font-semibold shrink-0">Priority: {rec.priority}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-brand-dim">No MX mail records mapped.</p>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {/* NS and TXT */}
            <div>
              <h4 className="text-xs font-bold text-brand-dim uppercase tracking-wider mb-2 font-mono">NS Records (Domain Authoritative Nameservers)</h4>
              <div className="bg-brand-bg border border-brand-border rounded-xl p-3 max-h-40 overflow-y-auto">
                {data.dns?.NS && data.dns.NS.length > 0 ? (
                  <ul className="space-y-1 text-xs font-mono text-brand-accent">
                    {data.dns.NS.map((ns: string, idx) => (
                      <li key={idx} className="py-1 border-b border-brand-border/40 last:border-0">{ns}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-brand-dim">No NS records mapped.</p>
                )}
              </div>
            </div>

            <div>
              <h4 className="text-xs font-bold text-brand-dim uppercase tracking-wider mb-2 font-mono">TXT Records (SPF, DKIM & Site Verification Labels)</h4>
              <div className="bg-brand-bg border border-brand-border rounded-xl p-3 max-h-40 overflow-y-auto">
                {data.dns?.TXT && data.dns.TXT.length > 0 ? (
                  <ul className="space-y-2 text-[10px] font-mono text-brand-main leading-normal">
                    {data.dns.TXT.map((txt: string[], idx) => (
                      <li key={idx} className="p-2 bg-brand-surface border border-brand-border rounded-lg break-all">
                        {txt.join(" ")}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-brand-dim">No TXT tags discovered.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Open Ports Scanner & Diagnostic Info */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Open Port Mapping */}
        <div className="lg:col-span-2 bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md">
          <h3 className="text-base font-bold text-brand-main pb-4 border-b border-brand-border mb-6 flex items-center gap-1.5">
            <Zap className="w-5 h-5 text-brand-accent" /> Active Diagnostic Ports Mapping
          </h3>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {data.ports?.map((p, idx) => (
              <div 
                key={idx} 
                className={`p-3 border rounded-xl flex flex-col items-center justify-center text-center transition ${
                  p.open 
                    ? "bg-brand-success/10 border-brand-success/20 text-brand-success shadow-xs" 
                    : "bg-brand-bg border-brand-border text-brand-dim"
                }`}
              >
                <span className="font-mono text-xs font-bold block">{p.port}</span>
                <span className="text-[10px] uppercase font-bold text-brand-dim mt-1 block">{p.service}</span>
                <span className={`text-[10px] font-extrabold px-1.5 py-0.5 rounded-md mt-2 ${
                  p.open ? "bg-brand-success/20 text-brand-success" : "bg-brand-surface border border-brand-border text-brand-dim"
                }`}>
                  {p.open ? "OPEN" : "CLOSED"}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* System Scanner Diagnostic Metatags */}
        <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-md flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-brand-main uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Info className="w-4 h-4 text-brand-dim" /> Scanning Diagnostics
            </h3>
            <p className="text-xs text-brand-dim">Low-footprint non-intrusive diagnostic metadata records.</p>
          </div>

          <div className="space-y-2 mt-4 text-xs">
            <div className="flex justify-between py-1 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Recon Method</span>
              <span className="text-brand-main font-semibold font-mono">Server TCP Lookup</span>
            </div>
            <div className="flex justify-between py-1 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">SSL Client Agent</span>
              <span className="text-brand-main font-semibold font-mono">TLS-SNI socket</span>
            </div>
            <div className="flex justify-between py-1 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">DNS Lookup Mode</span>
              <span className="text-brand-main font-semibold font-mono">System Node DNS resolver</span>
            </div>
            <div className="flex justify-between py-1 border-b border-brand-border/40">
              <span className="text-brand-dim font-medium">Port Scan Footprint</span>
              <span className="text-brand-main font-semibold font-mono">10 Common TCP Ports</span>
            </div>
          </div>

          <div className="p-3 bg-brand-accent/10 border border-brand-accent/20 rounded-xl mt-4">
            <p className="text-[10px] text-brand-accent font-medium leading-relaxed">
              This analyzer issues active socket probing solely on common service endpoints. Geolocation lookup resolves the primary resolved domain IP securely.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
