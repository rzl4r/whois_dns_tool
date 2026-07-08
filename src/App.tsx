import React from "react";
import { 
  Search, 
  Globe, 
  HelpCircle, 
  ShieldAlert, 
  CheckCircle2, 
  Activity, 
  Cpu, 
  History, 
  Bookmark, 
  MapPin, 
  AlertTriangle 
} from "lucide-react";
import { DomainAnalysis } from "./types";
import ResultsPresenter from "./components/ResultsPresenter";

// Some starter presets for exploration
const POPULAR_DOMAINS = [
  "google.com",
  "github.com",
  "wikipedia.org",
  "cloudflare.com",
  "apple.com",
  "microsoft.com"
];

export default function App() {
  const [target, setTarget] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [scanResult, setScanResult] = React.useState<DomainAnalysis | null>(null);
  const [history, setHistory] = React.useState<Array<{ domain: string; ip: string; timestamp: string; risk: number }>>([]);

  // Load scan history on component mount
  React.useEffect(() => {
    const saved = localStorage.getItem("whois_dns_scan_history");
    if (saved) {
      try {
        setHistory(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to parse history", e);
      }
    }
  }, []);

  const saveToHistory = (analysis: DomainAnalysis) => {
    const newEntry = {
      domain: analysis.domain,
      ip: analysis.ip,
      timestamp: new Date().toISOString(),
      risk: analysis.threatAssessment?.risk_score ?? 15
    };
    // Deduplicate history entries
    const filtered = history.filter(h => h.domain !== analysis.domain);
    const updated = [newEntry, ...filtered].slice(0, 10); // Keep last 10
    setHistory(updated);
    localStorage.setItem("whois_dns_scan_history", JSON.stringify(updated));
  };

  const handleScan = async (domainToScan: string) => {
    if (!domainToScan.trim()) return;
    setLoading(true);
    setError(null);
    setScanResult(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ target: domainToScan })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to scan target domain.");
      }

      setScanResult(data);
      saveToHistory(data);
    } catch (err: any) {
      setError(err.message || "An unexpected network or diagnostic error occurred.");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleScan(target);
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("whois_dns_scan_history");
  };

  return (
    <div className="min-h-screen bg-brand-bg text-brand-main font-sans">
      {/* Top Banner/Header Section */}
      <header className="bg-brand-surface border-b border-brand-border sticky top-0 z-50 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-brand-accent text-brand-bg rounded-xl shadow-xs">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg font-black tracking-tight text-brand-main uppercase flex items-center gap-1">
                NETSCAN<span className="text-brand-accent">_</span>RECON
              </h1>
              <p className="text-[10px] text-brand-dim font-semibold tracking-wider uppercase mt-0.5">Real-time threat compliance intelligence & diagnostic scanning</p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 font-semibold text-brand-dim bg-brand-bg border border-brand-border px-3 py-1.5 rounded-lg">
              <span className="w-2 h-2 bg-brand-success rounded-full animate-ping"></span>
              <span>Intelligence scanner server operational</span>
            </div>
            <div className="hidden sm:block text-brand-dim font-medium uppercase tracking-wider text-[11px]">
              Latency <span className="text-brand-success font-mono font-bold">24ms</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        
        {/* Search and Input Stage */}
        <section className="bg-brand-surface border border-brand-border text-brand-main rounded-3xl p-6 md:p-10 shadow-lg relative overflow-hidden">
          {/* Abstract Grid Overlays */}
          <div className="absolute inset-0 opacity-5 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:16px_16px]"></div>
          
          <div className="relative z-10 max-w-3xl space-y-6">
            <div className="space-y-2">
              <span className="px-3 py-1 bg-brand-accent/10 border border-brand-accent/20 text-brand-accent text-xs font-bold rounded-full uppercase tracking-wider">
                Authorized Security Assessment Node
              </span>
              <h2 className="text-2xl md:text-4xl font-extrabold tracking-tight">
                WHOIS, DNS & Real-Time Port/SSL Diagnostic Analyzer
              </h2>
              <p className="text-brand-dim text-sm md:text-base font-normal leading-relaxed">
                Analyze domain namespace records, registrar WHOIS registry data, IP Geolocation, open network ports, TLS/SSL authenticity compliance, and security HTTP headers instantaneously.
              </p>
            </div>

            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 text-brand-dim w-5 h-5" />
                <input
                  type="text"
                  placeholder="Enter a domain to analyze (e.g., cloudflare.com, github.com)..."
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full pl-12 pr-4 py-3.5 bg-brand-bg text-brand-main font-mono placeholder-brand-dim text-sm border border-brand-border rounded-xl focus:outline-hidden focus:ring-4 focus:ring-brand-accent/20 transition shadow-xs"
                  required
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-3.5 bg-brand-accent hover:bg-brand-accent/95 active:bg-brand-accent text-brand-bg text-sm font-bold rounded-xl transition flex items-center justify-center gap-2 shrink-0 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer shadow-xs"
              >
                {loading ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin" />
                    <span>Resolving Diagnostics...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Initiate Scan</span>
                  </>
                )}
              </button>
            </form>

            {/* Quick Explore Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-brand-main">
              <span className="font-semibold text-brand-dim">Popular Targets:</span>
              {POPULAR_DOMAINS.map((domain) => (
                <button
                  key={domain}
                  type="button"
                  onClick={() => {
                    setTarget(domain);
                    handleScan(domain);
                  }}
                  className="px-2.5 py-1 bg-brand-bg/60 hover:bg-brand-bg border border-brand-border rounded-lg font-medium text-brand-main transition cursor-pointer"
                >
                  {domain}
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* Diagnostic Results Section */}
        {loading && (
          <div className="bg-brand-surface border border-brand-border rounded-3xl p-12 text-center shadow-xs flex flex-col items-center justify-center gap-4">
            <div className="p-4 bg-brand-accent/10 text-brand-accent rounded-2xl animate-bounce">
              <Activity className="w-8 h-8 animate-spin" />
            </div>
            <div className="space-y-1.5 max-w-md">
              <h3 className="text-base font-bold text-brand-main">Conducting Target Namespace Analysis</h3>
              <p className="text-xs text-brand-dim">
                Contacting DNS servers, querying root TLDs via Gemini intelligence search, and probing network port handshake states. This will take a moment...
              </p>
            </div>
            
            {/* Visual scan indicators */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 w-full max-w-2xl mt-4">
              <div className="p-3 bg-brand-bg rounded-xl text-left border border-brand-border">
                <span className="text-[10px] uppercase font-bold text-brand-dim block">Stage 1</span>
                <span className="text-xs font-semibold text-brand-main block mt-1">Primary IP Lookup</span>
                <div className="h-1 bg-brand-border rounded-full mt-2 overflow-hidden">
                  <div className="h-full bg-brand-accent w-2/3 animate-pulse rounded-full"></div>
                </div>
              </div>

              <div className="p-3 bg-brand-bg rounded-xl text-left border border-brand-border">
                <span className="text-[10px] uppercase font-bold text-brand-dim block">Stage 2</span>
                <span className="text-xs font-semibold text-brand-main block mt-1">DNS Record Set resolution</span>
                <div className="h-1 bg-brand-border rounded-full mt-2 overflow-hidden">
                  <div className="h-full bg-brand-accent w-1/2 animate-pulse rounded-full"></div>
                </div>
              </div>

              <div className="p-3 bg-brand-bg rounded-xl text-left border border-brand-border">
                <span className="text-[10px] uppercase font-bold text-brand-dim block">Stage 3</span>
                <span className="text-xs font-semibold text-brand-main block mt-1">TCP Port Handshake</span>
                <div className="h-1 bg-brand-border rounded-full mt-2 overflow-hidden">
                  <div className="h-full bg-brand-accent w-1/3 animate-pulse rounded-full"></div>
                </div>
              </div>

              <div className="p-3 bg-brand-bg rounded-xl text-left border border-brand-border">
                <span className="text-[10px] uppercase font-bold text-brand-dim block">Stage 4</span>
                <span className="text-xs font-semibold text-brand-main block mt-1">Gemini WHOIS Extraction</span>
                <div className="h-1 bg-brand-border rounded-full mt-2 overflow-hidden">
                  <div className="h-full bg-brand-accent w-4/5 animate-pulse rounded-full"></div>
                </div>
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="bg-brand-danger/10 border border-brand-danger/20 rounded-2xl p-5 flex items-start gap-3 text-sm text-brand-danger">
            <AlertTriangle className="w-5 h-5 shrink-0 text-brand-danger mt-0.5" />
            <div className="space-y-1">
              <h4 className="font-bold">Scan Execution Blocked</h4>
              <p className="text-xs text-brand-danger/90 font-medium leading-relaxed">{error}</p>
              <p className="text-[10px] text-brand-dim pt-1">
                Please double-check the domain spelling, verify you did not include protocols like ftp://, and ensure your system is connected to an active network interface.
              </p>
            </div>
          </div>
        )}

        {scanResult && <ResultsPresenter data={scanResult} />}

        {/* Sidebar & History Logs Panel */}
        {!scanResult && !loading && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Quick Informational Tool Tips */}
            <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-sm lg:col-span-2 space-y-4">
              <h3 className="text-base font-bold text-brand-main flex items-center gap-1.5 pb-2 border-b border-brand-border">
                <HelpCircle className="w-5 h-5 text-brand-accent" /> Scanner Capabilities & Information
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-brand-main flex items-center gap-1.5">
                    <CheckCircle2 className="w-4.5 h-4.5 text-brand-success shrink-0" />
                    <span>Real-Time DNS Records Lookup</span>
                  </h4>
                  <p className="text-xs text-brand-dim leading-normal pl-6">
                    Resolves the domain's A (IPv4), AAAA (IPv6), MX (Mail Exchange), NS (Nameserver), TXT, and CNAME records live using high-performance standard resolvers.
                  </p>
                </div>

                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-brand-main flex items-center gap-1.5">
                    <CheckCircle2 className="w-4.5 h-4.5 text-brand-success shrink-0" />
                    <span>Intel Geolocation Mapping</span>
                  </h4>
                  <p className="text-xs text-brand-dim leading-normal pl-6">
                    Maps the resolved destination IP address to its physical location, including country, city, coordinates, and internet service provider (ISP).
                  </p>
                </div>

                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-brand-main flex items-center gap-1.5">
                    <CheckCircle2 className="w-4.5 h-4.5 text-brand-success shrink-0" />
                    <span>Active TCP Socket Scanning</span>
                  </h4>
                  <p className="text-xs text-brand-dim leading-normal pl-6">
                    Analyzes the operational status of the 10 most common network service ports (FTP, SSH, HTTP, HTTPS, CNAME etc.) to trace structural surface vulnerabilities.
                  </p>
                </div>

                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-brand-main flex items-center gap-1.5">
                    <CheckCircle2 className="w-4.5 h-4.5 text-brand-success shrink-0" />
                    <span>Compliance Auditing</span>
                  </h4>
                  <p className="text-xs text-brand-dim leading-normal pl-6">
                    Inspects crucial SSL/TLS certificates and extracts missing security HTTP Headers (such as CSP, HSTS, X-Frame-Options) to yield a performance defense compliance letter grade.
                  </p>
                </div>
              </div>

              <div className="p-3.5 bg-brand-warning/10 border border-brand-warning/20 rounded-xl text-xs text-brand-warning leading-relaxed">
                <span className="font-bold block mb-1">⚠️ Security Policy & Compliance Notice</span>
                The WHOIS & DNS Analyzer executes harmless, non-intrusive diagnostic probes strictly designed for legitimate server status checks, personal administration, and authorized evaluation.
              </div>
            </div>

            {/* Scan History Panel */}
            <div className="bg-brand-surface border border-brand-border rounded-2xl p-6 shadow-sm flex flex-col justify-between">
              <div>
                <div className="flex justify-between items-center pb-2 border-b border-brand-border mb-4">
                  <h3 className="text-sm font-bold text-brand-main flex items-center gap-1.5 uppercase tracking-wider">
                    <History className="w-4.5 h-4.5 text-brand-dim" /> Recent Scans
                  </h3>
                  {history.length > 0 && (
                    <button
                      onClick={clearHistory}
                      className="text-xs text-brand-danger hover:text-brand-danger/80 font-bold transition hover:underline cursor-pointer"
                    >
                      Clear Logs
                    </button>
                  )}
                </div>

                {history.length === 0 ? (
                  <div className="py-12 text-center text-brand-dim text-xs">
                    <Bookmark className="w-8 h-8 mx-auto mb-2 opacity-30 text-brand-dim" />
                    <span>No recent scans found. Search for a domain above to begin.</span>
                  </div>
                ) : (
                  <div className="space-y-3 max-h-[280px] overflow-y-auto pr-1">
                    {history.map((entry, idx) => (
                      <div
                        key={idx}
                        onClick={() => {
                          setTarget(entry.domain);
                          handleScan(entry.domain);
                        }}
                        className="p-3 bg-brand-bg hover:bg-brand-bg/85 border border-brand-border rounded-xl cursor-pointer transition flex justify-between items-center"
                      >
                        <div className="min-w-0">
                          <span className="text-sm font-bold text-brand-main truncate block">{entry.domain}</span>
                          <span className="text-[10px] font-mono text-brand-dim mt-0.5 block">{entry.ip}</span>
                        </div>
                        <div className="text-right shrink-0">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            entry.risk < 25 
                              ? "bg-brand-success/10 text-brand-success border border-brand-success/25" 
                              : entry.risk < 60 
                                ? "bg-brand-warning/10 text-brand-warning border border-brand-warning/25" 
                                : "bg-brand-danger/10 text-brand-danger border border-brand-danger/25"
                          }`}>
                            Risk: {entry.risk}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="pt-4 border-t border-brand-border text-[10px] text-brand-dim font-medium">
                Saves up to 10 entries locally in your browser cache.
              </div>
            </div>

          </div>
        )}

      </main>

      <footer className="bg-brand-surface border-t border-brand-border py-8 text-center text-xs text-brand-dim mt-20">
        <p className="font-semibold uppercase tracking-wider text-brand-main">WHOIS & DNS Information Gathering Tool</p>
        <p className="mt-1">Built to support secure network configuration, SSL verification, and diagnostic evaluations.</p>
        <p className="mt-4 text-[10px] text-brand-dim/50">© {new Date().getFullYear()} Security Reconnaissance Diagnostic Node. All rights reserved.</p>
      </footer>
    </div>
  );
}
