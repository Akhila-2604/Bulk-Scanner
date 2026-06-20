import { useRef, useState } from "react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Terminal, Globe, Loader2, Download, Upload, FileText, FileJson, FileSpreadsheet, ChevronDown, RotateCcw } from "lucide-react";
import {
  useScanIps,
  useScanDomains,
  getGetScanHistoryQueryKey,
  getGetScanStatsQueryKey,
  IpResult,
  DomainResult,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { IpResultsTable } from "./ip-results";
import { DomainResultsTable } from "./domain-results";
import { useToast } from "@/hooks/use-toast";
import { parseFile, ACCEPTED_EXTENSIONS, ParsedTargets } from "@/lib/file-parser";

export function ScannerForm() {
  const [activeTab, setActiveTab] = useState<"ip" | "domain">("ip");
  const [inputText, setInputText] = useState("");
  const [ipResults, setIpResults] = useState<IpResult[]>([]);
  const [domainResults, setDomainResults] = useState<DomainResult[]>([]);

  // File upload state
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isParsingFile, setIsParsingFile] = useState(false);
  const [parsedFromFile, setParsedFromFile] = useState<ParsedTargets | null>(null);
  const [parsedFileName, setParsedFileName] = useState("");

  const queryClient = useQueryClient();
  const { toast } = useToast();

  const scanIpsMutation = useScanIps({
    mutation: {
      onSuccess: (data) => {
        setIpResults(data);
        queryClient.invalidateQueries({ queryKey: getGetScanHistoryQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
        toast({ title: "IP Scan Complete", description: `Scanned ${data.length} IPs.` });
      },
      onError: () => {
        toast({ title: "Scan Failed", description: "An error occurred during IP scanning.", variant: "destructive" });
      },
    },
  });

  const scanDomainsMutation = useScanDomains({
    mutation: {
      onSuccess: (data) => {
        setDomainResults(data);
        queryClient.invalidateQueries({ queryKey: getGetScanHistoryQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
        toast({ title: "Domain Scan Complete", description: `Scanned ${data.length} domains.` });
      },
      onError: () => {
        toast({ title: "Scan Failed", description: "An error occurred during Domain scanning.", variant: "destructive" });
      },
    },
  });

  const isPending = scanIpsMutation.isPending || scanDomainsMutation.isPending;

  const handleSubmit = () => {
    const targets = inputText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (targets.length === 0) {
      toast({ title: "Input Required", description: "Please enter targets to scan.", variant: "destructive" });
      return;
    }

    // Clear previous results so only the current scan is shown
    setIpResults([]);
    setDomainResults([]);

    if (activeTab === "ip") {
      scanIpsMutation.mutate({ data: { targets } });
    } else {
      scanDomainsMutation.mutate({ data: { targets } });
    }
  };

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
    const results = activeTab === "ip" ? ipResults : domainResults;
    if (!results.length) return;
    const headers = Object.keys(results[0]).join(",");
    const rows = results
      .map((r) => Object.values(r).map((v) => `"${v ?? ""}"`).join(","))
      .join("\n");
    triggerDownload(`${headers}\n${rows}`, `${activeTab}-scan-${ts()}.csv`, "text/csv");
  };

  const exportJson = () => {
    const results = activeTab === "ip" ? ipResults : domainResults;
    if (!results.length) return;
    triggerDownload(
      JSON.stringify(results, null, 2),
      `${activeTab}-scan-${ts()}.json`,
      "application/json",
    );
  };

  const exportTxt = () => {
    const results = activeTab === "ip" ? ipResults : domainResults;
    if (!results.length) return;
    const lines: string[] = [
      `BULK REPUTATION SCAN REPORT`,
      `Generated : ${new Date().toUTCString()}`,
      `Scan type : ${activeTab === "ip" ? "IP Addresses" : "Domains / URLs"}`,
      `Targets   : ${results.length}`,
      ``,
      `${"─".repeat(72)}`,
      ``,
    ];

    if (activeTab === "ip") {
      for (const r of ipResults) {
        lines.push(`TARGET  : ${r.target}`);
        lines.push(`STATUS  : ${r.status.toUpperCase()}`);
        if (r.abuseConfidenceScore != null) lines.push(`SCORE   : ${r.abuseConfidenceScore}/100`);
        if (r.totalReports != null)         lines.push(`REPORTS : ${r.totalReports} (${r.numDistinctUsers ?? 0} distinct users)`);
        if (r.countryCode)                  lines.push(`COUNTRY : ${r.countryCode}`);
        if (r.isp)                          lines.push(`ISP     : ${r.isp}`);
        if (r.usageType)                    lines.push(`USAGE   : ${r.usageType}`);
        if (r.isTor)                        lines.push(`TOR     : YES`);
        if (r.lastReportedAt)               lines.push(`LAST    : ${r.lastReportedAt}`);
        if (r.error)                        lines.push(`ERROR   : ${r.error}`);
        lines.push(`${"─".repeat(72)}`);
        lines.push(``);
      }
    } else {
      for (const r of domainResults) {
        lines.push(`TARGET     : ${r.target}`);
        lines.push(`STATUS     : ${r.status.toUpperCase()}`);
        if (r.maliciousCount != null)  lines.push(`MALICIOUS  : ${r.maliciousCount} engines`);
        if (r.suspiciousCount != null) lines.push(`SUSPICIOUS : ${r.suspiciousCount} engines`);
        if (r.harmlessCount != null)   lines.push(`HARMLESS   : ${r.harmlessCount} engines`);
        if (r.totalEngines != null)    lines.push(`TOTAL ENG. : ${r.totalEngines}`);
        if (r.reputation != null)      lines.push(`REPUTATION : ${r.reputation}`);
        if (r.categories)              lines.push(`CATEGORIES : ${r.categories}`);
        if (r.lastAnalysisDate)        lines.push(`LAST SCAN  : ${r.lastAnalysisDate}`);
        if (r.error)                   lines.push(`ERROR      : ${r.error}`);
        lines.push(`${"─".repeat(72)}`);
        lines.push(``);
      }
    }

    triggerDownload(lines.join("\n"), `${activeTab}-scan-${ts()}.txt`, "text/plain");
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    // Reset input so same file can be re-selected
    e.target.value = "";

    setIsParsingFile(true);
    try {
      const parsed = await parseFile(file);
      setParsedFileName(file.name);
      setParsedFromFile(parsed);

      if (parsed.ips.length === 0 && parsed.domains.length === 0) {
        toast({
          title: "No targets found",
          description: "The file was parsed but no IP addresses or domains were detected.",
          variant: "destructive",
        });
      }
    } catch (err) {
      toast({
        title: "File Error",
        description: String(err),
        variant: "destructive",
      });
    } finally {
      setIsParsingFile(false);
    }
  };

  const applyParsed = (type: "ips" | "domains") => {
    if (!parsedFromFile) return;
    const targets = type === "ips" ? parsedFromFile.ips : parsedFromFile.domains;
    setInputText(targets.join("\n"));
    setActiveTab(type === "ips" ? "ip" : "domain");
    setParsedFromFile(null);
  };

  const handleNewScan = () => {
    setIpResults([]);
    setDomainResults([]);
    setInputText("");
  };

  const targetCount = inputText.split(/[\n,]+/).filter((t) => t.trim().length > 0).length;

  return (
    <div className="space-y-6">
      {/* File parse result dialog */}
      <Dialog open={!!parsedFromFile} onOpenChange={(open) => { if (!open) setParsedFromFile(null); }}>
        <DialogContent className="bg-card border-border font-mono max-w-md">
          <DialogHeader>
            <DialogTitle className="text-primary flex items-center gap-2 text-sm">
              <FileText className="w-4 h-4" />
              FILE_PARSED: {parsedFileName}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-xs text-muted-foreground">Targets detected in file. Choose which to load into the scanner:</p>
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => applyParsed("ips")}
                disabled={!parsedFromFile?.ips.length}
                className="flex flex-col items-center gap-1 rounded border border-border bg-background hover:border-primary hover:bg-accent/30 disabled:opacity-40 disabled:cursor-not-allowed p-4 transition-colors"
              >
                <Terminal className="w-5 h-5 text-primary" />
                <span className="text-lg font-bold text-foreground">{parsedFromFile?.ips.length ?? 0}</span>
                <span className="text-xs text-muted-foreground">IP ADDRESSES</span>
              </button>
              <button
                onClick={() => applyParsed("domains")}
                disabled={!parsedFromFile?.domains.length}
                className="flex flex-col items-center gap-1 rounded border border-border bg-background hover:border-primary hover:bg-accent/30 disabled:opacity-40 disabled:cursor-not-allowed p-4 transition-colors"
              >
                <Globe className="w-5 h-5 text-primary" />
                <span className="text-lg font-bold text-foreground">{parsedFromFile?.domains.length ?? 0}</span>
                <span className="text-xs text-muted-foreground">DOMAINS / URLS</span>
              </button>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" size="sm" className="text-xs" onClick={() => setParsedFromFile(null)}>
              CANCEL
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card className="border-border bg-card">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as "ip" | "domain")}>
              <TabsList className="grid grid-cols-2 max-w-sm bg-background border border-border">
                <TabsTrigger
                  value="ip"
                  className="font-mono text-xs data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
                  data-testid="tab-ip"
                >
                  <Terminal className="w-4 h-4 mr-2" />
                  IP ADDRESSES
                </TabsTrigger>
                <TabsTrigger
                  value="domain"
                  className="font-mono text-xs data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
                  data-testid="tab-domain"
                >
                  <Globe className="w-4 h-4 mr-2" />
                  DOMAINS / URLS
                </TabsTrigger>
              </TabsList>
            </Tabs>

            {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              accept={ACCEPTED_EXTENSIONS}
              className="hidden"
              onChange={handleFileChange}
            />
            <Button
              variant="outline"
              size="sm"
              className="font-mono text-xs h-8 border-border hover:border-primary"
              onClick={() => fileInputRef.current?.click()}
              disabled={isParsingFile || isPending}
              title="Upload .txt, .csv, .docx, .xlsx"
            >
              {isParsingFile ? (
                <Loader2 className="w-3 h-3 mr-2 animate-spin" />
              ) : (
                <Upload className="w-3 h-3 mr-2" />
              )}
              {isParsingFile ? "PARSING..." : "UPLOAD FILE"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder={
              activeTab === "ip"
                ? "Enter IPs (one per line or comma-separated)...\n192.168.1.1\n10.0.0.1"
                : "Enter domains or URLs (one per line or comma-separated)...\nexample.com\nhttps://malicious-site.net"
            }
            className="min-h-[160px] font-mono text-sm bg-background border-border focus-visible:ring-primary focus-visible:border-primary resize-y"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            disabled={isPending}
            data-testid="input-targets"
          />
          <div className="flex justify-between items-center">
            <span className="text-xs font-mono text-muted-foreground">
              {targetCount} TARGETS DETECTED
              {targetCount > 0 && (
                <span className="ml-3 text-muted-foreground/60">
                  (accepts .txt, .csv, .docx, .xlsx)
                </span>
              )}
            </span>
            <Button
              onClick={handleSubmit}
              disabled={isPending || inputText.trim().length === 0}
              className="font-mono font-bold px-8"
              data-testid="button-scan"
            >
              {isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Terminal className="w-4 h-4 mr-2" />
              )}
              INITIATE SCAN
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results Section */}
      {(ipResults.length > 0 || domainResults.length > 0) && (
        <Card className="border-border bg-card overflow-hidden">
          <CardHeader className="flex flex-row items-center justify-between py-3 border-b border-border bg-muted/50">
            <CardTitle className="text-sm font-mono text-primary flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              SCAN_RESULTS
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleNewScan}
                className="font-mono text-xs h-8 border-border hover:border-primary hover:text-primary"
              >
                <RotateCcw className="w-3 h-3 mr-1" />
                NEW SCAN
              </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="font-mono text-xs h-8"
                  data-testid="button-export"
                >
                  <Download className="w-3 h-3 mr-1" />
                  EXPORT
                  <ChevronDown className="w-3 h-3 ml-1" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="bg-card border-border font-mono text-xs w-44">
                <DropdownMenuLabel className="text-muted-foreground text-xs">DOWNLOAD AS</DropdownMenuLabel>
                <DropdownMenuSeparator className="bg-border" />
                <DropdownMenuItem onClick={exportCsv} className="cursor-pointer gap-2 text-xs hover:text-primary focus:text-primary">
                  <FileSpreadsheet className="w-3 h-3" />
                  CSV Spreadsheet
                </DropdownMenuItem>
                <DropdownMenuItem onClick={exportJson} className="cursor-pointer gap-2 text-xs hover:text-primary focus:text-primary">
                  <FileJson className="w-3 h-3" />
                  JSON Data
                </DropdownMenuItem>
                <DropdownMenuItem onClick={exportTxt} className="cursor-pointer gap-2 text-xs hover:text-primary focus:text-primary">
                  <FileText className="w-3 h-3" />
                  Text Report
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {activeTab === "ip" && ipResults.length > 0 && <IpResultsTable results={ipResults} />}
            {activeTab === "domain" && domainResults.length > 0 && <DomainResultsTable results={domainResults} />}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
