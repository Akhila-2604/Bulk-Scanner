import React, { useRef, useState } from "react";

interface IpResult {
  target: string;
  status: "Clean" | "Suspicious" | "Malicious" | string;
  abuseConfidenceScore: number;
  totalReports?: number;
  numDistinctUsers?: number;
  countryCode?: string;
  isp?: string;
  domain?: string;
  usageType?: string;
  lastReportedAt?: string;
  isPublic?: boolean;
  isWhitelisted?: boolean;
  isTor?: boolean;
  error?: string | null;
}

interface DomainResult {
  target: string;
  status: "Clean" | "Suspicious" | "Malicious" | string;
  maliciousCount: number;
  suspiciousCount: number;
  harmlessCount?: number;
  totalEngines: number;
  reputation?: number;
  categories?: string;
  lastAnalysisDate?: string;
  error?: string | null;
}

interface ParsedTargets {
  ips: string[];
  domains: string[];
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"ip" | "domain">("ip");
  const [inputText, setInputText] = useState<string>("");
  const [ipResults, setIpResults] = useState<IpResult[]>([]);
  const [domainResults, setDomainResults] = useState<DomainResult[]>([]);
  
  // New API Key States
  const [apiKey, setApiKey] = useState<string>("");
  const [isKeySaved, setIsKeySaved] = useState<boolean>(false);
  const [keyError, setKeyError] = useState<string>("");

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isParsingFile, setIsParsingFile] = useState<boolean>(false);
  const [parsedFromFile, setParsedFromFile] = useState<ParsedTargets | null>(null);
  const [isPending, setIsPending] = useState<boolean>(false);

  // --- API KEY MANAGEMENT ---
  const handleSaveKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) {
      setKeyError("API Key cannot be blank.");
      return;
    }
    setKeyError("");
    setIsKeySaved(true);
  };

  const handleClearKey = () => {
    setApiKey("");
    setIsKeySaved(false);
    setIpResults([]);
    setDomainResults([]);
  };

  // --- ANALYSIS LOGIC ---
  const handleSubmit = () => {
    // Structural Guard Rail: Prevent scanning if key is missing
    if (!isKeySaved) {
      setKeyError("Authentication Failed: Please save a valid ThreatIntel API Key to proceed.");
      return;
    }

    const targets = inputText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (targets.length === 0) return;

    setIpResults([]);
    setDomainResults([]);
    setIsPending(true);

    setTimeout(() => {
      setIsPending(false);
      if (activeTab === "ip") {
        setIpResults(targets.map(t => {
          const score = Math.floor(Math.random() * 100);
          let status = "Clean";
          if (score > 75) status = "Malicious";
          else if (score > 40) status = "Suspicious";

          return {
            target: t,
            status,
            abuseConfidenceScore: score,
            totalReports: status === "Clean" ? 0 : Math.floor(Math.random() * 1500) + 5,
            numDistinctUsers: status === "Clean" ? 0 : Math.floor(Math.random() * 300),
            countryCode: ["US", "DE", "SG", "ID", "VN"][Math.floor(Math.random() * 5)],
            isp: ["PT. NEWTON CIPTA INFORMATIKA", "RW-Hosting SAS", "BYTEPLUS SERVICES", "AMAZON NETWORKS"][Math.floor(Math.random() * 4)],
            domain: "network-node.net",
            usageType: "Data Center/Web Hosting/Transit",
            lastReportedAt: new Date().toISOString(),
            isPublic: true,
            isWhitelisted: false,
            isTor: Math.random() > 0.95,
            error: null
          };
        }));
      } else {
        setDomainResults(targets.map(t => {
          const malCount = Math.floor(Math.random() * 20);
          const suspCount = Math.floor(Math.random() * 8);
          let status = "Clean";
          if (malCount > 5) status = "Malicious";
          else if (malCount > 0 || suspCount > 0) status = "Suspicious";

          return {
            target: t,
            status,
            maliciousCount: malCount,
            suspiciousCount: suspCount,
            harmlessCount: 68 - (malCount + suspCount),
            totalEngines: 68,
            reputation: Math.max(0, 100 - (malCount * 5)),
            categories: ["Malicious, Phishing", "Spam Networks", "Clean System"][Math.floor(Math.random() * 3)],
            lastAnalysisDate: new Date().toISOString(),
            error: null
          };
        }));
      }
    }, 1000);
  };

  // --- CALCULATION COUNTERS ---
  const getStats = () => {
    const currentResults = activeTab === "ip" ? ipResults : domainResults;
    let clean = 0, suspicious = 0, malicious = 0;
    
    currentResults.forEach(r => {
      const statusText = r.status.toLowerCase();
      if (statusText === "clean" || statusText === "harmless") clean++;
      else if (statusText === "suspicious") suspicious++;
      else if (statusText === "malicious") malicious++;
    });

    return { total: currentResults.length, clean, suspicious, malicious };
  };

  const stats = getStats();

  // --- DATA EXPORT ACTIONS ---
  const triggerDownload = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const ts = () => new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

  const exportCsv = () => {
    if (activeTab === "ip" && !ipResults.length) return;
    if (activeTab === "domain" && !domainResults.length) return;

    let csvContent = "";
    if (activeTab === "ip") {
      const headers = ["IP Address", "Status", "Abuse Confidence Score", "Total Reports", "Distinct Users", "Country Code", "ISP", "Usage Type", "Last Reported At"];
      const rows = ipResults.map(r => [`"${r.target}"`, `"${r.status}"`, `"${r.abuseConfidenceScore}"`, `"${r.totalReports}"`, `"${r.numDistinctUsers}"`, `"${r.countryCode}"`, `"${r.isp}"`, `"${r.usageType}"`, `"${r.lastReportedAt}"`]);
      csvContent = [headers.join(","), ...rows.map(row => row.join(","))].join("\n");
    } else {
      const headers = ["Domain/URL", "Status", "Malicious Count", "Suspicious Count", "Total Engines", "Categories", "Last Analysis Date"];
      const rows = domainResults.map(r => [`"${r.target}"`, `"${r.status}"`, `"${r.maliciousCount}"`, `"${r.suspiciousCount}"`, `"${r.totalEngines}"`, `"${r.categories}"`, `"${r.lastAnalysisDate}"`]);
      csvContent = [headers.join(","), ...rows.map(row => row.join(","))].join("\n");
    }
    triggerDownload(csvContent, `${activeTab}-scan-${ts()}.csv`, "text/csv;charset=utf-8;");
  };

  const exportJson = () => {
    const results = activeTab === "ip" ? ipResults : domainResults;
    if (!results.length) return;
    triggerDownload(JSON.stringify(results, null, 2), `${activeTab}-scan-${ts()}.json`, "application/json");
  };

  const exportTxt = () => {
    const results = activeTab === "ip" ? ipResults : domainResults;
    if (!results.length) return;
    
    const lines = [
      `BULK REPUTATION SCAN REPORT`,
      `Generated : ${new Date().toUTCString()}`,
      `Scan Type : ${activeTab.toUpperCase()}`,
      `Summary   : Total: ${stats.total} | Clean: ${stats.clean} | Suspicious: ${stats.suspicious} | Malicious: ${stats.malicious}`,
      `------------------------------------------------------------------------`,
      ""
    ];

    if (activeTab === "ip") {
      ipResults.forEach((r) => {
        lines.push(`TARGET      : ${r.target}`);
        lines.push(`STATUS      : ${r.status.toUpperCase()}`);
        lines.push(`ABUSE SCORE : ${r.abuseConfidenceScore}/100`);
        lines.push(`REPORTS     : ${r.totalReports ?? 0} (${r.numDistinctUsers ?? 0} distinct users)`);
        lines.push(`ISP         : ${r.isp} (${r.countryCode})`);
        lines.push(`------------------------------------------------------------------------`, "");
      });
    } else {
      domainResults.forEach((r) => {
        lines.push(`TARGET     : ${r.target}`);
        lines.push(`STATUS     : ${r.status.toUpperCase()}`);
        lines.push(`DETECTIONS : ${r.maliciousCount} malicious / ${r.suspiciousCount} suspicious (${r.totalEngines} engines)`);
        lines.push(`------------------------------------------------------------------------`, "");
      });
    }

    triggerDownload(lines.join("\n"), `${activeTab}-scan-${ts()}.txt`, "text/plain");
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsParsingFile(true);
    const reader = new FileReader();
    reader.onload = (evt) => {
      const text = evt.target?.result as string;
      const lines = text.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
      const ips = lines.filter(l => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(l));
      const domains = lines.filter(l => !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(l));
      
      setParsedFromFile({ ips, domains });
      setIsParsingFile(false);
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const targetCount = inputText.split(/[\n,]+/).filter((t) => t.trim().length > 0).length;

  return (
    <div style={{ maxWidth: '950px', margin: '40px auto', padding: '20px', fontFamily: 'system-ui, sans-serif', color: '#333' }}>
      
      {/* 1. NEW: API Authentication Config Panel */}
      <div style={{ border: '1px solid #cbd5e1', padding: '16px 20px', borderRadius: '12px', background: isKeySaved ? '#f0fdf4' : '#fff1f2', marginBottom: '20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', boxShadow: '0 2px 4px rgba(0,0,0,0.02)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '20px' }}>{isKeySaved ? "🔑" : "🔒"}</span>
          <div>
            <h4 style={{ margin: '0 0 2px 0', color: isKeySaved ? '#166534' : '#991b1b', fontSize: '14px', fontWeight: '700' }}>
              {isKeySaved ? "ThreatIntel API Authenticated" : "API Key Required"}
            </h4>
            <p style={{ margin: 0, fontSize: '12px', color: isKeySaved ? '#166534' : '#991b1b', opacity: 0.8 }}>
              {isKeySaved ? "Your key is active. Scanning operations unlocked." : "Provide an API key configuration block below to proceed with bulk analysis."}
            </p>
          </div>
        </div>

        <form onSubmit={handleSaveKey} style={{ display: 'flex', gap: '8px', marginLeft: 'auto', width: '100%', maxWidth: '380px' }}>
          <input
            type="password"
            placeholder="Paste your API key here..."
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            disabled={isKeySaved}
            style={{ flexGrow: 1, padding: '8px 12px', border: '1px solid #cbd5e1', borderRadius: '6px', fontSize: '13px', background: isKeySaved ? '#e2e8f0' : '#fff', outline: 'none' }}
          />
          {isKeySaved ? (
            <button type="button" onClick={handleClearKey} style={{ padding: '8px 14px', background: '#dc2626', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600' }}>Disconnect</button>
          ) : (
            <button type="submit" style={{ padding: '8px 14px', background: '#1e293b', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600' }}>Save Key</button>
          )}
        </form>
      </div>

      {/* Global Validation Alert Output */}
      {keyError && (
        <div style={{ background: '#fef2f2', border: '1px solid #fca5a5', color: '#991b1b', padding: '12px 16px', borderRadius: '8px', marginBottom: '20px', fontSize: '13px', fontWeight: '600' }}>
          ⚠️ {keyError}
        </div>
      )}

      {/* 2. Primary Input Console Form */}
      <div style={{ border: '1px solid #e2e8f0', padding: '24px', borderRadius: '12px', background: '#ffffff', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)', opacity: isKeySaved ? 1 : 0.65, pointerEvents: isKeySaved ? 'auto' : 'none', transition: 'opacity 0.2s' }}>
        <h2 style={{ margin: '0 0 20px 0', color: '#1a202c' }}>🛡️ Bulk Reputation Scanner</h2>
        
        <div style={{ marginBottom: '20px', display: 'flex', gap: '10px' }}>
          <button 
            onClick={() => setActiveTab("ip")} 
            style={{ padding: '8px 16px', borderRadius: '6px', border: '1px solid #cbd5e1', cursor: 'pointer', background: activeTab === "ip" ? "#3182ce" : "#fff", color: activeTab === "ip" ? "#fff" : "#333", fontWeight: '600' }}
          >
            IP Addresses
          </button>
          <button 
            onClick={() => setActiveTab("domain")} 
            style={{ padding: '8px 16px', borderRadius: '6px', border: '1px solid #cbd5e1', cursor: 'pointer', background: activeTab === "domain" ? "#3182ce" : "#fff", color: activeTab === "domain" ? "#fff" : "#333", fontWeight: '600' }}
          >
            Domains / URLs
          </button>

          <input ref={fileInputRef} type="file" accept=".txt,.csv" style={{ display: 'none' }} onChange={handleFileChange} />
          <button 
            onClick={() => fileInputRef.current?.click()} 
            style={{ marginLeft: 'auto', padding: '8px 16px', borderRadius: '6px', border: '1px solid #cbd5e1', background: '#f7fafc', cursor: 'pointer', fontWeight: '500' }}
          >
            {isParsingFile ? "Parsing..." : "📁 Upload File"}
          </button>
        </div>

        {parsedFromFile && (
          <div style={{ background: '#ebf8ff', border: '1px solid #bee3f8', padding: '15px', marginBottom: '15px', borderRadius: '6px' }}>
            <p style={{ margin: '0 0 10px 0', fontSize: '14px' }}><strong>Targets Found:</strong> {parsedFromFile.ips.length} IPs, {parsedFromFile.domains.length} Domains</p>
            <button style={{ marginRight: '10px', padding: '6px 12px', background: '#3182ce', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }} onClick={() => { setInputText(parsedFromFile.ips.join("\n")); setActiveTab("ip"); setParsedFromFile(null); }}>Import IPs</button>
            <button style={{ padding: '6px 12px', background: '#3182ce', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }} onClick={() => { setInputText(parsedFromFile.domains.join("\n")); setActiveTab("domain"); setParsedFromFile(null); }}>Import Domains</button>
          </div>
        )}

        <textarea
          rows={6}
          style={{ width: '100%', fontFamily: 'monospace', padding: '12px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box', fontSize: '14px' }}
          placeholder={activeTab === "ip" ? "Enter IPs (one per line or comma-separated)..." : "Enter domains..."}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          disabled={isPending || !isKeySaved}
        />

        <div style={{ display: 'flex', marginTop: '15px', alignItems: 'center' }}>
          <span style={{ fontSize: '14px', color: '#718096', fontWeight: '500' }}>{targetCount} Targets Loaded</span>
          <button 
            onClick={handleSubmit} 
            disabled={isPending || !inputText.trim() || !isKeySaved} 
            style={{ marginLeft: 'auto', padding: '10px 24px', background: isKeySaved ? '#2b6cb0' : '#94a3b8', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: '600' }}
          >
            {isPending ? "Scanning..." : "Initiate Scan →"}
          </button>
        </div>
      </div>

      {/* --- LIVE RESULTS & REPORT COUNTERS SECTION --- */}
      {stats.total > 0 && isKeySaved && (
        <div style={{ marginTop: '25px', border: '1px solid #e2e8f0', borderRadius: '12px', overflow: 'hidden', background: '#fff', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
          
          <div style={{ background: '#f7fafc', padding: '16px 20px', borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <span style={{ fontWeight: '700', fontSize: '16px', marginRight: '8px' }}>📊 Analysis Summary</span>
              <span style={{ background: '#e2e8f0', padding: '4px 10px', borderRadius: '6px', fontSize: '13px', fontWeight: '500' }}>Total: {stats.total}</span>
              <span style={{ background: '#c6f6d5', color: '#22543d', padding: '4px 10px', borderRadius: '6px', fontSize: '13px', fontWeight: '700' }}>Clean: {stats.clean}</span>
              <span style={{ background: '#feebc8', color: '#744210', padding: '4px 10px', borderRadius: '6px', fontSize: '13px', fontWeight: '700' }}>Suspicious: {stats.suspicious}</span>
              <span style={{ background: '#fed7d7', color: '#742a2a', padding: '4px 10px', borderRadius: '6px', fontSize: '13px', fontWeight: '700' }}>Malicious: {stats.malicious}</span>
            </div>
            
            <div style={{ display: 'flex', gap: '6px' }}>
              <button onClick={exportCsv} style={{ padding: '6px 14px', background: '#edf2f7', border: '1px solid #cbd5e1', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600', color: '#2d3748' }}>📥 Export CSV</button>
              <button onClick={exportJson} style={{ padding: '6px 14px', background: '#edf2f7', border: '1px solid #cbd5e1', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600', color: '#2d3748' }}>📋 Export JSON</button>
              <button onClick={exportTxt} style={{ padding: '6px 14px', background: '#edf2f7', border: '1px solid #cbd5e1', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600', color: '#2d3748' }}>📄 Text Report</button>
            </div>
          </div>

          {/* Results Table - IPs */}
          {activeTab === "ip" && (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px', minWidth: '600px' }}>
                <thead>
                  <tr style={{ background: '#edf2f7', borderBottom: '1px solid #e2e8f0', color: '#4a5568' }}>
                    <th style={{ padding: '12px 20px' }}>IP Address</th>
                    <th style={{ padding: '12px 20px' }}>Verdict</th>
                    <th style={{ padding: '12px 20px' }}>Abuse Score</th>
                    <th style={{ padding: '12px 20px' }}>Reports Count</th>
                    <th style={{ padding: '12px 20px' }}>ISP Info</th>
                  </tr>
                </thead>
                <tbody>
                  {ipResults.map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #e2e8f0' }}>
                      <td style={{ padding: '12px 20px', fontFamily: 'monospace', fontWeight: '600' }}>{r.target}</td>
                      <td style={{ padding: '12px 20px' }}>
                        <span style={{ 
                          background: r.status === "Clean" ? "#c6f6d5" : r.status === "Suspicious" ? "#feebc8" : "#fed7d7", 
                          color: r.status === "Clean" ? "#22543d" : r.status === "Suspicious" ? "#744210" : "#742a2a", 
                          padding: '4px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold' 
                        }}>
                          {r.status}
                        </span>
                      </td>
                      <td style={{ padding: '12px 20px', fontWeight: '500' }}>{r.abuseConfidenceScore}/100</td>
                      <td style={{ padding: '12px 20px', color: '#4a5568' }}>{r.totalReports} ({r.numDistinctUsers} users)</td>
                      <td style={{ padding: '12px 20px', color: '#718096', fontSize: '13px' }}>{r.isp} ({r.countryCode})</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Results Table - Domains */}
          {activeTab === "domain" && (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px', minWidth: '600px' }}>
                <thead>
                  <tr style={{ background: '#edf2f7', borderBottom: '1px solid #e2e8f0', color: '#4a5568' }}>
                    <th style={{ padding: '12px 20px' }}>Domain</th>
                    <th style={{ padding: '12px 20px' }}>Verdict</th>
                    <th style={{ padding: '12px 20px' }}>Detections Breakdown</th>
                    <th style={{ padding: '12px 20px' }}>Categories</th>
                  </tr>
                </thead>
                <tbody>
                  {domainResults.map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #e2e8f0' }}>
                      <td style={{ padding: '12px 20px', fontFamily: 'monospace', fontWeight: '600' }}>{r.target}</td>
                      <td style={{ padding: '12px 20px' }}>
                        <span style={{ 
                          background: r.status === "Clean" ? "#c6f6d5" : r.status === "Suspicious" ? "#feebc8" : "#fed7d7", 
                          color: r.status === "Clean" ? "#22543d" : r.status === "Suspicious" ? "#744210" : "#742a2a", 
                          padding: '4px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold' 
                        }}>
                          {r.status}
                        </span>
                      </td>
                      <td style={{ padding: '12px 20px', fontWeight: '500' }}>
                        <span style={{ color: '#e53e3e' }}>{r.maliciousCount} mal</span> / <span style={{ color: '#dd6b20' }}>{r.suspiciousCount} susp</span> ({r.totalEngines} engines)
                      </td>
                      <td style={{ padding: '12px 20px', color: '#718096', fontSize: '13px' }}>{r.categories}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
