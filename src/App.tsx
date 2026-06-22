import React, { useRef, useState } from "react";

interface IpResult {
  target: string;
  status: string;
  abuseConfidenceScore: number;
  totalReports: number;
  numDistinctUsers: number;
  countryCode: string;
  isp: string;
  dataSource: string;
}

interface DomainResult {
  target: string;
  status: string;
  maliciousCount: number;
  suspiciousCount: number;
  totalEngines: number;
  categories: string;
  dataSource: string;
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
  
  // API Key Configurations
  const [abuseKey, setAbuseKey] = useState<string>("");
  const [vtKey, setVtKey] = useState<string>("");
  const [isAuthSaved, setIsAuthSaved] = useState<boolean>(false);
  const [authError, setAuthError] = useState<string>("");
  const [showInstructions, setShowInstructions] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isParsingFile, setIsParsingFile] = useState<boolean>(false);
  const [parsedFromFile, setParsedFromFile] = useState<ParsedTargets | null>(null);
  const [isPending, setIsPending] = useState<boolean>(false);

  const handleSaveKeys = (e: React.FormEvent) => {
    e.preventDefault();
    if (!abuseKey.trim() && !vtKey.trim()) {
      setAuthError("Authentication Blocked: Please enter at least one valid API Key (AbuseIPDB or VirusTotal).");
      return;
    }
    setAuthError("");
    setIsAuthSaved(true);
  };

  const handleClearKeys = () => {
    setAbuseKey("");
    setVtKey("");
    setIsAuthSaved(false);
    setIpResults([]);
    setDomainResults([]);
  };

  // --- LIVE MULTI-THREADED SCANNING LOGIC ---
  const handleSubmit = async () => {
    if (!isAuthSaved) {
      setAuthError("Triage Cancelled: Authenticate your integration keys before scanning.");
      return;
    }

    const targets = inputText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (targets.length === 0) return;

    // Check key availability before blasting network pipelines
    if (activeTab === "ip" && !abuseKey.trim() && !vtKey.trim()) {
      setAuthError("Error: IP analysis requires either an AbuseIPDB or VirusTotal API Key.");
      return;
    }
    if (activeTab === "domain" && !vtKey.trim()) {
      setAuthError("Error: Domain profiling requires a VirusTotal API Key.");
      return;
    }

    setIpResults([]);
    setDomainResults([]);
    setIsPending(true);
    setAuthError("");

    try {
      if (activeTab === "ip") {
        // Run all IP scans in parallel using Promise.all
        const results = await Promise.all(
          targets.map(async (ip) => {
            try {
              // Priority 1: Check via direct AbuseIPDB Endpoint if available
              if (abuseKey.trim()) {
                const response = await fetch(
                  `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
                  {
                    method: "GET",
                    headers: {
                      "Key": abuseKey.trim(),
                      "Accept": "application/json",
                    },
                  }
                );

                if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
                const resData = await response.json();
                const data = resData.data;

                let verdict = "Clean";
                if (data.abuseConfidenceScore > 75) verdict = "Malicious";
                else if (data.abuseConfidenceScore > 25) verdict = "Suspicious";

                return {
                  target: ip,
                  status: verdict,
                  abuseConfidenceScore: data.abuseConfidenceScore || 0,
                  totalReports: data.totalReports || 0,
                  numDistinctUsers: data.numDistinctUsers || 0,
                  countryCode: data.countryCode || "Unknown",
                  isp: data.isp || "Unknown ISP",
                  dataSource: "AbuseIPDB Core API",
                };
              } 
              
              // Priority 2: Fallback to VirusTotal IP reporting if no AbuseIPDB key exists
              else {
                const response = await fetch(
                  `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
                  {
                    method: "GET",
                    headers: { "x-apikey": vtKey.trim() },
                  }
                );

                if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
                const resData = await response.json();
                const stats = resData.data.attributes.last_analysis_stats;
                
                const mal = stats.malicious || 0;
                const susp = stats.suspicious || 0;
                let verdict = "Clean";
                if (mal > 4) verdict = "Malicious";
                else if (mal > 0 || susp > 0) verdict = "Suspicious";

                return {
                  target: ip,
                  status: verdict,
                  abuseConfidenceScore: Math.round((mal / 70) * 100),
                  totalReports: mal + susp,
                  numDistinctUsers: mal,
                  countryCode: resData.data.attributes.country || "Global",
                  isp: resData.data.attributes.as_owner || "Unknown Provider",
                  dataSource: "VirusTotal IP Engine",
                };
              }
            } catch (err) {
              return {
                target: ip,
                status: "Scan Error",
                abuseConfidenceScore: 0,
                totalReports: 0,
                numDistinctUsers: 0,
                countryCode: "N/A",
                isp: "Failed to fetch remote data",
                dataSource: "Network Fault",
              };
            }
          })
        );
        setIpResults(results);
      } else {
        // Domain profiling via VirusTotal v3 Domain Endpoints
        const results = await Promise.all(
          targets.map(async (domain) => {
            try {
              // Sanitize target input (Strip out standard browser prefixes if they paste raw web URLs)
              const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, "").split("/")[0];

              const response = await fetch(
                `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(cleanDomain)}`,
                {
                  method: "GET",
                  headers: { "x-apikey": vtKey.trim() },
                }
              );

              if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
              const resData = await response.json();
              const attrs = resData.data.attributes;
              const stats = attrs.last_analysis_stats;

              let verdict = "Clean";
              if (stats.malicious > 5) verdict = "Malicious";
              else if (stats.malicious > 0 || stats.suspicious > 0) verdict = "Suspicious";

              // Map detected threat taxonomy categories cleanly
              const catObj = attrs.categories || {};
              const catSummary = Object.values(catObj).slice(0, 2).join(", ") || "Uncategorized Network";

              return {
                target: cleanDomain,
                status: verdict,
                maliciousCount: stats.malicious || 0,
                suspiciousCount: stats.suspicious || 0,
                totalEngines: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
                categories: catSummary,
                dataSource: "VirusTotal v3 API",
              };
            } catch (err) {
              return {
                target: domain,
                status: "Scan Error",
                maliciousCount: 0,
                suspiciousCount: 0,
                totalEngines: 0,
                categories: "Check API limit quotas or target syntax",
                dataSource: "Network Fault",
              };
            }
          })
        );
        setDomainResults(results);
      }
    } catch (globalErr) {
      setAuthError("Execution Error: Failed to coordinate asynchronous routing threads.");
    } finally {
      setIsPending(false);
    }
  };

  // --- METRIC STATS CALCULATION ---
  const getStats = () => {
    const currentResults = activeTab === "ip" ? ipResults : domainResults;
    let clean = 0, suspicious = 0, malicious = 0;
    currentResults.forEach(r => {
      if (r.status === "Clean") clean++;
      else if (r.status === "Suspicious") suspicious++;
      else if (r.status === "Malicious") malicious++;
    });
    return { total: currentResults.length, clean, suspicious, malicious };
  };

  const stats = getStats();

  // --- DATA RE-EXPORT UTILITIES ---
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
      const headers = ["IP Address", "Status", "Confidence Score", "Total Reports", "Distinct Users", "Country Code", "ISP", "Data Intelligence Source"];
      const rows = ipResults.map(r => [`"${r.target}"`, `"${r.status}"`, `"${r.abuseConfidenceScore}"`, `"${r.totalReports}"`, `"${r.numDistinctUsers}"`, `"${r.countryCode}"`, `"${r.isp}"`, `"${r.dataSource}"`]);
      csvContent = [headers.join(","), ...rows.map(row => row.join(","))].join("\n");
    } else {
      const headers = ["Domain/URL", "Status", "Malicious Count", "Suspicious Count", "Total Engines", "Categories", "Data Intelligence Source"];
      const rows = domainResults.map(r => [`"${r.target}"`, `"${r.status}"`, `"${r.maliciousCount}"`, `"${r.suspiciousCount}"`, `"${r.totalEngines}"`, `"${r.categories}"`, `"${r.dataSource}"`]);
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
        lines.push(`INTEL LOG   : Resolved via ${r.dataSource}`);
        lines.push(`------------------------------------------------------------------------`, "");
      });
    } else {
      domainResults.forEach((r) => {
        lines.push(`TARGET     : ${r.target}`);
        lines.push(`STATUS     : ${r.status.toUpperCase()}`);
        lines.push(`DETECTIONS : ${r.maliciousCount} malicious / ${r.suspiciousCount} suspicious`);
        lines.push(`INTEL LOG  : Resolved via ${r.dataSource}`);
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
      
      {/* 1. Provider API Management Panel */}
      <div style={{ border: '1px solid #cbd5e1', padding: '24px', borderRadius: '12px', background: isAuthSaved ? '#f0fdf4' : '#fff1f2', marginBottom: '20px', boxShadow: '0 2px 5px rgba(0,0,0,0.02)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <span style={{ fontSize: '22px' }}>{isAuthSaved ? "🛡️" : "🔒"}</span>
          <div>
            <h4 style={{ margin: '0 0 2px 0', color: isAuthSaved ? '#166534' : '#991b1b', fontSize: '15px', fontWeight: '700' }}>
              {isAuthSaved ? "SOC ThreatIntel Providers Initialized" : "ThreatIntel Gateway Configuration Required"}
            </h4>
            <p style={{ margin: 0, fontSize: '12px', color: isAuthSaved ? '#166534' : '#991b1b', opacity: 0.85 }}>
              Provide at least one API key to unlock analytical workflows.{" "}
              <button onClick={() => setShowInstructions(!showInstructions)} type="button" style={{ background: 'none', border: 'none', color: '#2563eb', textDecoration: 'underline', cursor: 'pointer', padding: 0, font: 'inherit', fontWeight: 'bold' }}>
                {showInstructions ? "Hide instructions" : "How do I get an API key?"}
              </button>
            </p>
          </div>
        </div>

        {showInstructions && (
          <div style={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', padding: '16px', marginBottom: '16px', fontSize: '13px', lineHeight: '1.5', color: '#334155' }}>
            <h5 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#1e293b' }}>🗝️ Step-by-Step API Access Instructions:</h5>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
              <div>
                <strong style={{ color: '#0f172a' }}>1. AbuseIPDB Key (For IP Reputation)</strong>
                <ol style={{ margin: '4px 0 0 0', paddingLeft: '20px' }}>
                  <li>Go to <a href="https://www.abuseipdb.com/" target="_blank" rel="noreferrer" style={{ color: '#2563eb' }}>abuseipdb.com</a> and sign up for an account.</li>
                  <li>Log in, view your Dashboard, and navigate to the **API** tab.</li>
                  <li>Click **Create Key**, type a reference name, and save the hash.</li>
                </ol>
              </div>
              <div>
                <strong style={{ color: '#0f172a' }}>2. VirusTotal Key (For Domain/URL Scans)</strong>
                <ol style={{ margin: '4px 0 0 0', paddingLeft: '20px' }}>
                  <li>Visit <a href="https://www.virustotal.com/" target="_blank" rel="noreferrer" style={{ color: '#2563eb' }}>virustotal.com</a> and create a profile.</li>
                  <li>Click your profile avatar in the top-right corner.</li>
                  <li>Select 🔑 **API Key** from the dropdown menu and copy it.</li>
                </ol>
              </div>
            </div>
          </div>
        )}

        <form onSubmit={handleSaveKeys} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: '700', marginBottom: '4px', color: '#475569' }}>ABUSEIPDB API KEY</label>
              <input type="password" placeholder={isAuthSaved && abuseKey ? "••••••••••••••••••••" : "Enter AbuseIPDB Key..."} value={abuseKey} onChange={(e) => setAbuseKey(e.target.value)} disabled={isAuthSaved} style={{ width: '100%', boxSizing: 'border-box', padding: '10px', border: '1px solid #cbd5e1', borderRadius: '6px', fontSize: '13px', background: isAuthSaved ? '#e2e8f0' : '#fff', outline: 'none' }} />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: '700', marginBottom: '4px', color: '#475569' }}>VIRUSTOTAL API KEY</label>
              <input type="password" placeholder={isAuthSaved && vtKey ? "••••••••••••••••••••" : "Enter VirusTotal Key..."} value={vtKey} onChange={(e) => setVtKey(e.target.value)} disabled={isAuthSaved} style={{ width: '100%', boxSizing: 'border-box', padding: '10px', border: '1px solid #cbd5e1', borderRadius: '6px', fontSize: '13px', background: isAuthSaved ? '#e2e8f0' : '#fff', outline: 'none' }} />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '4px' }}>
            {isAuthSaved ? (
              <button type="button" onClick={handleClearKeys} style={{ padding: '8px 16px', background: '#dc2626', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600' }}>Modify Keys</button>
            ) : (
              <button type="submit" style={{ padding: '9px 20px', background: '#1e293b', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600' }}>Save Configurations</button>
            )}
          </div>
        </form>
      </div>

      {authError && (
        <div style={{ background: '#fef2f2', border: '1px solid #fca5a5', color: '#991b1b', padding: '12px 16px', borderRadius: '8px', marginBottom: '20px', fontSize: '13px', fontWeight: '600' }}>
          ⚠️ {authError}
        </div>
      )}

      {/* 2. Primary Input Console Form */}
      <div style={{ border: '1px solid #e2e8f0', padding: '24px', borderRadius: '12px', background: '#ffffff', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)', opacity: isAuthSaved ? 1 : 0.6, pointerEvents: isAuthSaved ? 'auto' : 'none', transition: 'opacity 0.2s' }}>
        <h2 style={{ margin: '0 0 20px 0', color: '#1a202c' }}>🛡️ Bulk Reputation Scanner</h2>
        
        <div style={{ marginBottom: '20px', display: 'flex', gap: '10px' }}>
          <button onClick={() => setActiveTab("ip")} style={{ padding: '8px 16px', borderRadius: '6px', border: '1px solid #cbd5e1', cursor: 'pointer', background: activeTab === "ip" ? "#3182ce" : "#fff", color: activeTab === "ip" ? "#fff" : "#333", fontWeight: '600' }}>IP Addresses</button>
          <button onClick={() => setActiveTab("domain")} style={{ padding: '8px 16px', borderRadius: '6px', border: '1px solid #cbd5e1', cursor: 'pointer', background: activeTab === "domain" ? "#3182ce" : "#fff", color: activeTab === "domain" ? "#fff" : "#333", fontWeight: '600' }}>Domains / URLs</button>
          <input ref={fileInputRef} type="file" accept=".txt,.csv" style={{ display: 'none' }} onChange={handleFileChange} />
          <button onClick={() => fileInputRef.current?.click()} style={{ marginLeft: 'auto', padding: '8px 16px', borderRadius: '6px', border: '1px solid #cbd5e1', background: '#f7fafc', cursor: 'pointer', fontWeight: '500' }}>{isParsingFile ? "Parsing..." : "📁 Upload Log"}</button>
        </div>

        {parsedFromFile && (
          <div style={{ background: '#ebf8ff', border: '1px solid #bee3f8', padding: '15px', marginBottom: '15px', borderRadius: '6px' }}>
            <p style={{ margin: '0 0 10px 0', fontSize: '14px' }}><strong>Targets Found:</strong> {parsedFromFile.ips.length} IPs, {parsedFromFile.domains.length} Domains</p>
            <button style={{ marginRight: '10px', padding: '6px 12px', background: '#3182ce', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }} onClick={() => { setInputText(parsedFromFile.ips.join("\n")); setActiveTab("ip"); setParsedFromFile(null); }}>Import IPs</button>
            <button style={{ padding: '6px 12px', background: '#3182ce', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }} onClick={() => { setInputText(parsedFromFile.domains.join("\n")); setActiveTab("domain"); setParsedFromFile(null); }}>Import Domains</button>
          </div>
        )}

        <textarea rows={6} style={{ width: '100%', fontFamily: 'monospace', padding: '12px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box', fontSize: '14px' }} placeholder={activeTab === "ip" ? "Enter raw IPs (one per line or comma-separated)..." : "Enter malicious domain domains..."} value={inputText} onChange={(e) => setInputText(e.target.value)} disabled={isPending || !isAuthSaved} />

        <div style={{ display: 'flex', marginTop: '15px', alignItems: 'center' }}>
          <span style={{ fontSize: '14px', color: '#718096', fontWeight: '500' }}>{targetCount} IOCs Loaded</span>
          <button onClick={handleSubmit} disabled={isPending || !inputText.trim() || !isAuthSaved} style={{ marginLeft: 'auto', padding: '10px 24px', background: isAuthSaved ? '#2b6cb0' : '#94a3b8', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: '600' }}>
            {isPending ? "Evaluating IOCs..." : "Initiate Threat Intel Scan →"}
          </button>
        </div>
      </div>

      {/* --- LIVE RESULTS & REPORT COUNTERS SECTION --- */}
      {stats.total > 0 && isAuthSaved && (
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
              <button onClick={exportCsv} style={{ padding: '6px 14px', background: '#edf2f7', border: '1px solid #cbd5e1', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600', color: '#2d3748' }}>Export CSV</button>
              <button onClick={exportJson} style={{ padding: '6px 14px', background: '#edf2f7', border: '1px solid #cbd5e1', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600', color: '#2d3748' }}>JSON</button>
              <button onClick={exportTxt} style={{ padding: '6px 14px', background: '#edf2f7', border: '1px solid #cbd5e1', borderRadius: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: '600', color: '#2d3748' }}>Text Report</button>
            </div>
          </div>

          {activeTab === "ip" && (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px', minWidth: '600px' }}>
                <thead>
                  <tr style={{ background: '#edf2f7', borderBottom: '1px solid #e2e8f0', color: '#4a5568' }}>
                    <th style={{ padding: '12px 20px' }}>IP Address</th>
                    <th style={{ padding: '12px 20px' }}>Verdict</th>
                    <th style={{ padding: '12px 20px' }}>Abuse Score</th>
                    <th style={{ padding: '12px 20px' }}>Triage Meta</th>
                    <th style={{ padding: '12px 20px' }}>Intelligence Origin</th>
                  </tr>
                </thead>
                <tbody>
                  {ipResults.map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #e2e8f0' }}>
                      <td style={{ padding: '12px 20px', fontFamily: 'monospace', fontWeight: '600' }}>{r.target}</td>
                      <td style={{ padding: '12px 20px' }}>
                        <span style={{ background: r.status === "Clean" ? "#c6f6d5" : r.status === "Suspicious" ? "#feebc8" : r.status === "Scan Error" ? "#e2e8f0" : "#fed7d7", color: r.status === "Clean" ? "#22543d" : r.status === "Suspicious" ? "#744210" : r.status === "Scan Error" ? "#475569" : "#742a2a", padding: '4px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold' }}>{r.status}</span>
                      </td>
                      <td style={{ padding: '12px 20px', fontWeight: '500' }}>{r.abuseConfidenceScore}/100</td>
                      <td style={{ padding: '12px 20px', color: '#4a5568' }}>{r.totalReports} alerts ({r.isp})</td>
                      <td style={{ padding: '12px 20px', color: '#2b6cb0', fontSize: '13px', fontWeight: '600' }}>🔍 {r.dataSource}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === "domain" && (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px', minWidth: '600px' }}>
                <thead>
                  <tr style={{ background: '#edf2f7', borderBottom: '1px solid #e2e8f0', color: '#4a5568' }}>
                    <th style={{ padding: '12px 20px' }}>Domain</th>
                    <th style={{ padding: '12px 20px' }}>Verdict</th>
                    <th style={{ padding: '12px 20px' }}>Detections Breakdown</th>
                    <th style={{ padding: '12px 20px' }}>Intelligence Origin</th>
                  </tr>
                </thead>
                <tbody>
                  {domainResults.map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #e2e8f0' }}>
                      <td style={{ padding: '12px 20px', fontFamily: 'monospace', fontWeight: '600' }}>{r.target}</td>
                      <td style={{ padding: '12px 20px' }}>
                        <span style={{ background: r.status === "Clean" ? "#c6f6d5" : r.status === "Suspicious" ? "#feebc8" : r.status === "Scan Error" ? "#e2e8f0" : "#fed7d7", color: r.status === "Clean" ? "#22543d" : r.status === "Suspicious" ? "#744210" : r.status === "Scan Error" ? "#475569" : "#742a2a", padding: '4px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold' }}>{r.status}</span>
                      </td>
                      <td style={{ padding: '12px 20px', fontWeight: '500' }}>
                        <span style={{ color: '#e53e3e' }}>{r.maliciousCount} mal</span> / <span style={{ color: '#dd6b20' }}>{r.suspiciousCount} susp</span> ({r.totalEngines} engines)
                      </td>
                      <td style={{ padding: '12px 20px', color: '#2b6cb0', fontSize: '13px', fontWeight: '600' }}>🔍 {r.dataSource}</td>
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
