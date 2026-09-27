import React, { useState, useMemo } from 'react';
import {
  Globe,
  Network,
  Shield,
  ShieldAlert,
  FolderLock,
  Sliders,
  Radio,
  Search,
  Download,
  RefreshCw,
  Database,
  Sparkles,
  ExternalLink,
  FileText,
  AlertTriangle,
  Upload,
  CheckCircle2,
  Bug,
  Crosshair,
  Server,
  Layers,
  ArrowRight,
  ChevronRight,
  Info,
  ChevronDown
} from 'lucide-react';
import {
  EvidenceObject,
  AIAnalysisVerdict,
  IndicatorType,
  ProviderResult,
  HistoryItemDTO
} from '../types/index.js';

interface CommandCenterViewProps {
  evidence: EvidenceObject | null;
  indicator: string;
  selectedType: IndicatorType | 'auto';
  onIndicatorChange: (val: string) => void;
  onTypeChange: (type: IndicatorType | 'auto') => void;
  onSearch: (submitMode?: boolean, file?: File, customAnalystName?: string, forceRefresh?: boolean) => void;
  loading: boolean;
  errorMessage: string | null;
  aiVerdict: AIAnalysisVerdict | null;
  aiLoading: boolean;
  onGenerateAI: () => void;
  onOpenReport: () => void;
  historyItems: HistoryItemDTO[];
  onSelectHistory: (item: HistoryItemDTO) => void;
  analystName: string;
  onAnalystChange: (name: string) => void;
  onViewProvider: (provider: ProviderResult) => void;
  onToggleViewMode: () => void;
  viewMode: 'cockpit' | 'classic';
}

type CenterCategory = 'network' | 'risk' | 'assets' | 'feeds';

const defang = (val?: string): string => {
  if (!val) return '';
  return val.replace(/http/gi, 'hxxp').replace(/:\/\//g, '[:]//').replace(/\./g, '[.]');
};

export const CommandCenterView: React.FC<CommandCenterViewProps> = ({
  evidence,
  indicator,
  selectedType,
  onIndicatorChange,
  onTypeChange,
  onSearch,
  loading,
  errorMessage,
  aiVerdict,
  aiLoading,
  onGenerateAI,
  onOpenReport,
  historyItems,
  onSelectHistory,
  analystName,
  onAnalystChange,
  onViewProvider,
  onToggleViewMode,
  viewMode
}) => {
  const [activeCategory, setActiveCategory] = useState<CenterCategory>('network');
  const [selectedPivotIocs, setSelectedPivotIocs] = useState<Record<string, boolean>>({});
  const [leftDrawerOpen, setLeftDrawerOpen] = useState(true);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Compute Risk Metrics
  const riskMetrics = useMemo(() => {
    if (!evidence) {
      return {
        score: 0,
        grade: 'CLEAN',
        gradeColor: 'text-emerald-400 border-emerald-500/40 bg-emerald-950/40',
        maliciousHits: 0,
        suspiciousHits: 0,
        benignHits: 0,
        totalEngines: 0
      };
    }

    const score = evidence.rule_score?.value ?? 0;
    let maliciousHits = 0;
    let suspiciousHits = 0;
    let benignHits = 0;

    const providersList = Array.isArray(evidence.providers) ? evidence.providers : [];
    for (const p of providersList) {
      if (p.score?.malicious) maliciousHits += p.score.malicious;
      if (p.score?.suspicious) suspiciousHits += p.score.suspicious;
      if (p.score?.harmless || p.score?.undetected) {
        benignHits += (p.score.harmless || 0) + (p.score.undetected || 0);
      }
    }

    let grade = 'A (CLEAN)';
    let gradeColor = 'text-emerald-400 border-emerald-500/40 bg-emerald-950/40';

    if (score >= 70 || maliciousHits >= 3) {
      grade = 'F (CRITICAL)';
      gradeColor = 'text-rose-400 border-rose-500/40 bg-rose-950/40';
    } else if (score >= 40 || maliciousHits > 0 || suspiciousHits >= 2) {
      grade = 'D (SUSPICIOUS)';
      gradeColor = 'text-amber-400 border-amber-500/40 bg-amber-950/40';
    } else if (score >= 20) {
      grade = 'C (ELEVATED)';
      gradeColor = 'text-yellow-400 border-yellow-500/40 bg-yellow-950/40';
    }

    return {
      score,
      grade,
      gradeColor,
      maliciousHits,
      suspiciousHits,
      benignHits,
      totalEngines: maliciousHits + suspiciousHits + benignHits
    };
  }, [evidence]);

  // Compute 8-Axis Threat Radar Chart
  const threatRadarData = useMemo(() => {
    if (!evidence) {
      return [
        { label: 'Ransomware', value: 15 },
        { label: 'APTs', value: 10 },
        { label: 'MitM', value: 5 },
        { label: 'Zero-Day', value: 10 },
        { label: 'SQL Injection', value: 5 },
        { label: 'DDoS', value: 10 },
        { label: 'Phishing', value: 10 },
        { label: 'Remote Access', value: 15 }
      ];
    }

    const hints = evidence.mitre_hints || [];
    const textCorpus = JSON.stringify(evidence).toLowerCase();

    const hasTerm = (terms: string[]) => terms.some((t) => textCorpus.includes(t));

    const ransomwareVal = hasTerm(['ransom', 'encryptor', 'crypto', 'shadowcopy', 'lockbit', 'blackcat']) ? 95 : evidence.rule_score?.value ? Math.min(85, evidence.rule_score.value * 0.9) : 20;
    const aptVal = hasTerm(['apt', 'c2', 'command and control', 'beacon', 'cobalt']) ? 90 : (hints.length > 2 ? 80 : 25);
    const mitmVal = hasTerm(['ssl', 'cert', 'dns_poison', 'proxy', 'arp']) ? 75 : 15;
    const zeroDayVal = hasTerm(['cve-', 'exploit', 'vulnerability', 'heap', 'overflow']) ? 85 : 20;
    const sqliVal = hasTerm(['sql', 'injection', 'union select', 'xss']) ? 70 : 15;
    const ddosVal = hasTerm(['flood', 'ddos', 'syn', 'amplification', 'botnet']) ? 80 : 15;
    const phishingVal = hasTerm(['phish', 'credential', 'harvest', 'login', 'spoof', 'lookalike']) ? 90 : (evidence.indicator?.type === 'url' ? 75 : 20);
    const remoteAccessVal = hasTerm(['rat', 'trojan', 'backdoor', 'remcos', 'njrat', 'powershell']) ? 95 : 30;

    return [
      { label: 'Ransomware', value: ransomwareVal },
      { label: 'APTs', value: aptVal },
      { label: 'MitM', value: mitmVal },
      { label: 'Zero-Day', value: zeroDayVal },
      { label: 'SQLi', value: sqliVal },
      { label: 'DDoS', value: ddosVal },
      { label: 'Phishing', value: phishingVal },
      { label: 'Remote Access', value: remoteAccessVal }
    ];
  }, [evidence]);

  // Provider Nodes positions on 360 orbital circumference
  const providerNodes = useMemo(() => {
    const defaultList = [
      { id: 'virustotal', name: 'VirusTotal', icon: Shield, type: 'VT v3' },
      { id: 'hybrid_analysis', name: 'Hybrid Analysis', icon: Bug, type: 'HA Sandbox' },
      { id: 'alienvault_otx', name: 'AlienVault OTX', icon: Crosshair, type: 'Pulses' },
      { id: 'abuseipdb', name: 'AbuseIPDB', icon: Server, type: 'IP Telemetry' },
      { id: 'urlhaus', name: 'URLhaus', icon: Globe, type: 'Abuse Feeds' },
      { id: 'urlscan', name: 'Urlscan.io', icon: Radio, type: 'Web Scan' },
      { id: 'malwarebazaar', name: 'MalwareBazaar', icon: Database, type: 'Signatures' }
    ];

    const radius = 175; // px from center
    return defaultList.map((item, index) => {
      const angle = (index * (360 / defaultList.length) - 90) * (Math.PI / 180);
      const x = Math.round(220 + radius * Math.cos(angle));
      const y = Math.round(220 + radius * Math.sin(angle));

      const liveProvider = Array.isArray(evidence?.providers)
        ? evidence.providers.find((p) => p.name === item.id)
        : undefined;
      const isMalicious = (liveProvider?.score?.malicious ?? 0) > 0 || Boolean(liveProvider?.headline?.toLowerCase().includes('malicious'));
      const isSuspicious = (liveProvider?.score?.suspicious ?? 0) > 0 || Boolean(liveProvider?.headline?.toLowerCase().includes('suspicious'));
      const isClean = liveProvider?.status === 'ok' && !isMalicious && !isSuspicious;

      return {
        ...item,
        x,
        y,
        liveProvider,
        status: isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : isClean ? 'clean' : 'neutral',
        summary: liveProvider?.headline || 'Connected & Monitored'
      };
    });
  }, [evidence]);

  // Generate Constellation Particle Dots (matching screenshot's concentric dot clouds)
  const constellationDots = useMemo(() => {
    const dots: Array<{ cx: number; cy: number; r: number; opacity: number }> = [];
    const layers = [
      { count: 28, radius: 155, rBase: 2.2 },
      { count: 34, radius: 175, rBase: 2.8 },
      { count: 24, radius: 195, rBase: 2.0 },
      { count: 18, radius: 135, rBase: 2.0 }
    ];

    layers.forEach((layer) => {
      for (let i = 0; i < layer.count; i++) {
        const angle = (i * (360 / layer.count) + (layer.radius % 17)) * (Math.PI / 180);
        const jitter = ((i * 13) % 9) - 4;
        const dist = layer.radius + jitter;
        const cx = Math.round(240 + dist * Math.cos(angle));
        const cy = Math.round(240 + dist * Math.sin(angle));
        const opacity = 0.35 + ((i % 5) * 0.12);
        dots.push({ cx, cy, r: layer.rBase + (i % 2 === 0 ? 0.5 : 0), opacity });
      }
    });
    return dots;
  }, []);

  // Related Pivot IoCs from Evidence
  const pivotList = useMemo(() => {
    if (!evidence?.related) return [];
    const list: Array<{ val: string; type: string }> = [];
    if (Array.isArray(evidence.related.domains)) {
      evidence.related.domains.slice(0, 5).forEach((d) => list.push({ val: d, type: 'Domain' }));
    }
    if (Array.isArray(evidence.related.ips)) {
      evidence.related.ips.slice(0, 5).forEach((ip) => list.push({ val: ip, type: 'IP' }));
    }
    if (Array.isArray(evidence.related.hashes)) {
      evidence.related.hashes.slice(0, 4).forEach((h) => list.push({ val: h, type: 'Hash' }));
    }
    return list;
  }, [evidence]);

  // Compute Radar Chart Polygon Points (Centered at 120, 110 with radius 75)
  const radarSvgPoints = useMemo(() => {
    const cx = 120;
    const cy = 110;
    const r = 70;
    return threatRadarData.map((d, i) => {
      const angle = (i * (360 / threatRadarData.length) - 90) * (Math.PI / 180);
      const dist = (d.value / 100) * r;
      const x = (cx + dist * Math.cos(angle)).toFixed(1);
      const y = (cy + dist * Math.sin(angle)).toFixed(1);
      return `${x},${y}`;
    }).join(' ');
  }, [threatRadarData]);

  const togglePivot = (val: string) => {
    setSelectedPivotIocs((prev) => ({ ...prev, [val]: !prev[val] }));
  };

  return (
    <div className="relative min-h-[92vh] w-full bg-[#050812] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 overflow-x-hidden">
      {/* Background Cyber Ambient Radial Lighting */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-gradient-to-b from-cyan-600/10 via-violet-600/5 to-transparent rounded-full blur-[140px]" />
        <div className="absolute -bottom-20 -left-20 w-[450px] h-[450px] bg-blue-600/10 rounded-full blur-[120px]" />
        <div className="absolute top-10 right-0 w-[400px] h-[400px] bg-purple-600/10 rounded-full blur-[130px]" />
        {/* Subtle HUD Grid Overlay */}
        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, #38bdf8 1px, transparent 0)`,
            backgroundSize: '32px 32px'
          }}
        />
      </div>

      {/* Top Cyber Command Center HUD Control Bar */}
      <div className="relative z-30 border-b border-cyan-500/20 bg-[#070b16]/90 backdrop-blur-xl px-4 lg:px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 shadow-[0_4px_25px_rgba(0,0,0,0.5)]">
        {/* Left: View Identity & Switcher */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-xs font-mono font-extrabold uppercase tracking-wider text-cyan-300">
              Command Center
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300">
              HUD v2.4
            </span>
          </div>

          {/* Quick Layout Revert / Switch Toggle */}
          <div className="flex items-center bg-slate-900/90 rounded-lg p-0.5 border border-slate-700/60 shadow-inner">
            <button
              type="button"
              onClick={() => {}}
              className="px-2.5 py-1 text-[11px] font-mono font-semibold rounded-md bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 flex items-center gap-1.5 shadow-sm"
              title="Currently viewing Holographic Command Center"
            >
              <Network className="w-3.5 h-3.5 text-cyan-400" />
              <span>Orbit HUD</span>
            </button>
            <button
              type="button"
              onClick={onToggleViewMode}
              className="px-2.5 py-1 text-[11px] font-mono font-medium rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors flex items-center gap-1.5"
              title="Click to switch back to Classic SOC Grid view at any time"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Classic SOC</span>
            </button>
          </div>
        </div>

        {/* Center: Search & Submission Input HUD */}
        <div className="flex-1 max-w-2xl min-w-[280px]">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              onSearch();
            }}
            className="relative flex items-center"
          >
            <div className="absolute left-3 text-cyan-400/80 pointer-events-none">
              <Search className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={indicator}
              onChange={(e) => onIndicatorChange(e.target.value)}
              placeholder="Search target indicator (Hash, Domain, IPv4, URL) or paste defanged..."
              className="w-full bg-[#0a1020]/90 border border-cyan-500/30 rounded-lg pl-9 pr-28 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono transition-all shadow-[inset_0_2px_4px_rgba(0,0,0,0.4)]"
            />
            <div className="absolute right-1.5 flex items-center gap-1">
              <button
                type="submit"
                disabled={loading || !indicator.trim()}
                className="px-3 py-1 rounded bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 text-xs font-mono font-bold transition-all shadow-[0_0_12px_rgba(34,211,238,0.3)] cursor-pointer flex items-center gap-1"
              >
                {loading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <span>TRIAGE</span>}
              </button>
            </div>
          </form>
        </div>

        {/* Right: Actions (Force Re-scan, Report, Cache Status) */}
        <div className="flex items-center gap-2">
          {evidence?.cached && (
            <div className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded bg-cyan-950/60 border border-cyan-500/40 text-[10px] font-mono text-cyan-300">
              <Database className="w-3 h-3 text-cyan-400" />
              <span>24h Cache Hit</span>
              <button
                type="button"
                onClick={() => onSearch(false, undefined, analystName, true)}
                className="ml-1 text-[9px] underline hover:text-cyan-100 cursor-pointer"
              >
                Refresh
              </button>
            </div>
          )}

          <button
            type="button"
            onClick={onOpenReport}
            disabled={!evidence}
            className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-750 border border-slate-700 hover:border-cyan-500/40 text-xs font-mono text-slate-300 hover:text-cyan-300 transition-colors flex items-center gap-1.5 disabled:opacity-40 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Export</span>
          </button>
        </div>
      </div>

      {/* Main Command Center Body: 3-Column Cockpit Layout */}
      <div className="relative z-10 flex-1 flex flex-col lg:flex-row overflow-hidden">
        {/* ============================================================== */}
        {/* COLUMN 1: LEFT SLIM RAIL + UPDATES / ACTIVITY STREAM */}
        {/* ============================================================== */}
        <div className="flex border-b lg:border-b-0 lg:border-r border-cyan-500/20 bg-[#070b16]/70 backdrop-blur-md">
          {/* Slim Icon Navigation Rail */}
          <div className="w-13 border-r border-cyan-500/10 flex flex-col items-center justify-between py-4 bg-[#050812]">
            <div className="flex flex-col items-center gap-5">
              <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/40 text-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.25)]">
                <ShieldAlert className="w-5 h-5" />
              </div>

              <div className="w-6 h-px bg-slate-800" />

              <button
                type="button"
                onClick={() => setActiveCategory('network')}
                className={`p-2.5 rounded-lg transition-colors cursor-pointer ${
                  activeCategory === 'network'
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.2)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
                title="Threat Constellation Network"
              >
                <Network className="w-4 h-4" />
              </button>

              <button
                type="button"
                onClick={() => setActiveCategory('risk')}
                className={`p-2.5 rounded-lg transition-colors cursor-pointer ${
                  activeCategory === 'risk'
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.2)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
                title="MITRE & Risk Breakdown"
              >
                <Shield className="w-4 h-4" />
              </button>

              <button
                type="button"
                onClick={() => setActiveCategory('assets')}
                className={`p-2.5 rounded-lg transition-colors cursor-pointer ${
                  activeCategory === 'assets'
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.2)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
                title="Investigated Assets & Samples"
              >
                <FolderLock className="w-4 h-4" />
              </button>

              <button
                type="button"
                onClick={() => setActiveCategory('feeds')}
                className={`p-2.5 rounded-lg transition-colors cursor-pointer ${
                  activeCategory === 'feeds'
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.2)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
                title="Live 7 Threat Feed Matrix"
              >
                <Globe className="w-4 h-4" />
              </button>
            </div>

            {/* Bottom Rail Controls */}
            <div className="flex flex-col items-center gap-4">
              <button
                type="button"
                onClick={onToggleViewMode}
                className="p-2 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-slate-800/50 transition-colors"
                title="Switch back to Classic View"
              >
                <Sliders className="w-4 h-4" />
              </button>
              <div
                className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-600 to-violet-600 border border-cyan-400 flex items-center justify-center text-xs font-bold text-white shadow-[0_0_10px_rgba(34,211,238,0.3)]"
                title={`Analyst: ${analystName}`}
              >
                {analystName.charAt(0).toUpperCase()}
              </div>
            </div>
          </div>

          {/* Left Updates Activity Stream Drawer (Exact match to screenshot's left feed) */}
          <div className="w-68 sm:w-76 flex flex-col h-full bg-[#060a14]/90 p-3">
            <div className="flex items-center justify-between pb-2.5 mb-2 border-b border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-200">Updates</span>
              <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-[#0b1428] border border-cyan-500/30 text-[10px] font-mono text-cyan-300">
                <span>All ({historyItems.length > 0 ? historyItems.length : 4})</span>
                <ChevronDown className="w-3 h-3 text-cyan-400" />
              </div>
            </div>

            {/* List of Recent Risk Shifts & Lookups (screenshot matching cards) */}
            <div className="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar max-h-[380px] lg:max-h-[760px]">
              {(!Array.isArray(historyItems) || historyItems.length === 0) ? (
                // Initial preset updates matching screenshot when history is fresh
                <>
                  <div className="p-2.5 rounded-lg border border-slate-800 bg-[#0a0f1d]/90 hover:border-cyan-500/50 transition-all cursor-pointer">
                    <span className="text-[9.5px] font-mono text-slate-400 block">Change in Risk Score</span>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <div className="w-2 h-2 rounded-full bg-cyan-400" />
                      <span className="text-xs font-semibold text-white">Pinnacle Finance Group</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-slate-300">
                      <span>75%</span>
                      <span className="text-cyan-400">→</span>
                      <span className="text-rose-400 font-bold">100%</span>
                    </div>
                    <div className="mt-1 flex items-center justify-between text-[9px] font-mono text-slate-500">
                      <span>Jan 18, 2024 · 2:31 PM UTC</span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">domain name</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg border border-slate-800 bg-[#0a0f1d]/90 hover:border-cyan-500/50 transition-all cursor-pointer">
                    <span className="text-[9.5px] font-mono text-slate-400 block">Change Risk Grade</span>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <div className="w-2 h-2 rounded-full bg-blue-400" />
                      <span className="text-xs font-semibold text-white">BlueBridge Capital</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-slate-300">
                      <span className="text-rose-400 font-bold">F</span>
                      <span className="text-cyan-400">→</span>
                      <span className="text-amber-400 font-bold">D</span>
                    </div>
                    <div className="mt-1 flex items-center justify-between text-[9px] font-mono text-slate-500">
                      <span>Jan 18, 2024 · 2:31 PM UTC</span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">domain name</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg border border-slate-800 bg-[#0a0f1d]/90 hover:border-cyan-500/50 transition-all cursor-pointer">
                    <span className="text-[9.5px] font-mono text-slate-400 block">Risk Acceptance</span>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <div className="w-2 h-2 rounded-full bg-purple-400" />
                      <span className="text-xs font-semibold text-white">NorthStar Wealth Advisors</span>
                    </div>
                    <p className="mt-1 text-[10px] text-slate-400 leading-snug">
                      Team member Austin McDaniel accepted the risk of Organization
                    </p>
                    <div className="mt-1 flex items-center justify-between text-[9px] font-mono text-slate-500">
                      <span>Jan 18, 2024 · 2:31 PM UTC</span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">domain name</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg border border-slate-800 bg-[#0a0f1d]/90 hover:border-cyan-500/50 transition-all cursor-pointer">
                    <span className="text-[9.5px] font-mono text-slate-400 block">Change in Risk Score</span>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <div className="w-2 h-2 rounded-full bg-cyan-400" />
                      <span className="text-xs font-semibold text-white">Aspire Capital Partners</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-slate-300">
                      <span>75%</span>
                      <span className="text-cyan-400">→</span>
                      <span className="text-rose-400 font-bold">100%</span>
                    </div>
                    <div className="mt-1 flex items-center justify-between text-[9px] font-mono text-slate-500">
                      <span>Jan 18, 2024 · 2:31 PM UTC</span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">domain name</span>
                    </div>
                  </div>
                </>
              ) : (
                historyItems.map((item) => {
                  const isCritical = (item.ruleScore ?? 0) >= 70 || item.verdict === 'malicious';
                  const isSuspicious = (item.ruleScore ?? 0) >= 30;

                  return (
                    <div
                      key={item.id}
                      onClick={() => onSelectHistory(item)}
                      className="group p-2.5 rounded-lg border border-slate-800 hover:border-cyan-500/50 bg-[#0a0f1d]/80 hover:bg-[#0e162a] transition-all cursor-pointer shadow-sm relative overflow-hidden"
                    >
                      <div
                        className={`absolute left-0 top-0 bottom-0 w-1 ${
                          isCritical ? 'bg-rose-500' : isSuspicious ? 'bg-amber-500' : 'bg-emerald-500'
                        }`}
                      />
                      <div className="pl-1">
                        <div className="flex items-center justify-between text-[9.5px] text-slate-400 mb-0.5">
                          <span className="uppercase tracking-wider font-semibold text-slate-300">
                            {isCritical ? 'Change in Risk Score' : 'Change Risk Grade'}
                          </span>
                          <span className="font-mono text-[9px] text-slate-500">
                            {new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                        <div className="text-xs font-mono font-medium text-slate-200 group-hover:text-cyan-300 truncate">
                          {item.defanged || item.indicator}
                        </div>
                        <div className="mt-1.5 flex items-center justify-between text-[10px]">
                          <span className="font-mono text-slate-400 flex items-center gap-1">
                            <span className="text-slate-500">{item.type}</span>
                            <span className="text-cyan-400/80">→</span>
                            <span className={isCritical ? 'text-rose-400 font-bold' : isSuspicious ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                              {item.ruleScore ?? 0}% {isCritical ? 'F' : isSuspicious ? 'D' : 'A'}
                            </span>
                          </span>
                          <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono text-[9px]">
                            {item.type}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* ============================================================== */}
        {/* COLUMN 2: CENTER HOLOGRAPHIC THREAT CONSTELLATION & RADAR */}
        {/* ============================================================== */}
        <div className="flex-1 flex flex-col items-center justify-between p-4 lg:p-6 overflow-y-auto relative">
          {/* Top Center HUD Header matching screenshot */}
          <div className="w-full flex flex-col items-center pb-2 relative">
            {/* Sci-fi HUD Top Brackets */}
            <div className="flex items-center gap-3">
              <div className="w-12 h-px bg-gradient-to-r from-transparent via-cyan-500/50 to-cyan-400" />
              <div className="relative px-6 py-1 border-t-2 border-cyan-400/80 bg-gradient-to-b from-cyan-950/40 to-transparent">
                <div className="absolute -top-1 left-0 w-2 h-2 border-l-2 border-t-2 border-cyan-300" />
                <div className="absolute -top-1 right-0 w-2 h-2 border-r-2 border-t-2 border-cyan-300" />
                <h1 className="text-2xl lg:text-3xl font-black uppercase tracking-wider bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent drop-shadow-[0_0_15px_rgba(34,211,238,0.5)]">
                  Dashboard
                </h1>
              </div>
              <div className="w-12 h-px bg-gradient-to-l from-transparent via-cyan-500/50 to-cyan-400" />
            </div>

            {/* Sub-pill: My Network */}
            <div className="mt-1 px-3 py-0.5 rounded-full bg-[#071329] border border-cyan-500/30 text-[11px] font-mono font-semibold text-cyan-300 shadow-[0_0_10px_rgba(34,211,238,0.2)]">
              {activeCategory === 'network' ? 'My Network' : activeCategory === 'risk' ? 'My Risk' : activeCategory === 'assets' ? 'My Assets' : 'Countries'}
            </div>
          </div>

          {/* Central Holographic Orbit Canvas (Center of screenshot) */}
          <div className="relative my-3 flex items-center justify-center w-full max-w-[520px] h-[480px]">
            {/* Concentric Orbit SVG Rings & Particle Dots Cloud */}
            <svg
              className="absolute inset-0 w-full h-full pointer-events-none"
              viewBox="0 0 480 480"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <defs>
                <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
                <filter id="glow-magenta" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Concentric Ring Guides */}
              <circle cx="240" cy="240" r="210" stroke="#06b6d4" strokeOpacity="0.1" strokeWidth="1" strokeDasharray="4 6" />
              <circle cx="240" cy="240" r="185" stroke="#38bdf8" strokeOpacity="0.22" strokeWidth="1.5" strokeDasharray="8 10" className="animate-[spin_120s_linear_infinite]" />
              <circle cx="240" cy="240" r="145" stroke="#818cf8" strokeOpacity="0.12" strokeWidth="1" strokeDasharray="3 5" />
              <circle cx="240" cy="240" r="105" stroke="#06b6d4" strokeOpacity="0.25" strokeWidth="1" />

              {/* Constellation Particle Dots Cloud (screenshot style) */}
              {constellationDots.map((dot, idx) => (
                <circle
                  key={`cdot-${idx}`}
                  cx={dot.cx}
                  cy={dot.cy}
                  r={dot.r}
                  fill="#38bdf8"
                  fillOpacity={dot.opacity}
                  className="transition-all duration-300"
                />
              ))}

              {/* Connecting Laser Conduits to Orbital Nodes */}
              {providerNodes.map((node) => {
                const nx = (node.x / 440) * 480;
                const ny = (node.y / 440) * 480;
                return (
                  <line
                    key={`line-${node.id}`}
                    x1="240"
                    y1="240"
                    x2={nx}
                    y2={ny}
                    stroke={node.status === 'malicious' ? '#f43f5e' : node.status === 'suspicious' ? '#f59e0b' : '#06b6d4'}
                    strokeOpacity={hoveredNode === node.id ? 0.9 : 0.25}
                    strokeWidth={hoveredNode === node.id ? 2 : 1}
                    strokeDasharray="2 4"
                  />
                );
              })}
            </svg>

            {/* Triangular Orbital Nodes positioned around the circumference */}
            {providerNodes.map((node) => {
              const Icon = node.icon;
              const isHovered = hoveredNode === node.id;
              const nx = (node.x / 440) * 480;
              const ny = (node.y / 440) * 480;

              const statusColor =
                node.status === 'malicious'
                  ? 'border-rose-500 bg-rose-950/80 text-rose-300 drop-shadow-[0_0_12px_rgba(244,63,94,0.6)]'
                  : node.status === 'suspicious'
                  ? 'border-amber-500 bg-amber-950/80 text-amber-300 drop-shadow-[0_0_12px_rgba(245,158,11,0.6)]'
                  : node.status === 'clean'
                  ? 'border-emerald-500 bg-emerald-950/80 text-emerald-300 drop-shadow-[0_0_10px_rgba(16,185,129,0.5)]'
                  : 'border-cyan-400/60 bg-[#081226]/90 text-cyan-300 drop-shadow-[0_0_10px_rgba(34,211,238,0.4)]';

              return (
                <div
                  key={node.id}
                  style={{
                    position: 'absolute',
                    left: `${nx}px`,
                    top: `${ny}px`,
                    transform: 'translate(-50%, -50%)'
                  }}
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => {
                    if (node.liveProvider) {
                      onViewProvider(node.liveProvider);
                    }
                  }}
                  className={`group z-20 cursor-pointer flex flex-col items-center transition-all duration-300 ${
                    isHovered ? 'scale-120' : 'hover:scale-110'
                  }`}
                  title={`${node.name}: Click for deep dive`}
                >
                  {/* Triangular Polygon Cyber Framing */}
                  <div className="relative flex items-center justify-center">
                    <svg className="w-12 h-12" viewBox="0 0 48 48">
                      <polygon
                        points="24,4 44,40 4,40"
                        className={`transition-colors ${
                          node.status === 'malicious'
                            ? 'fill-rose-950/80 stroke-rose-500'
                            : node.status === 'suspicious'
                            ? 'fill-amber-950/80 stroke-amber-500'
                            : node.status === 'clean'
                            ? 'fill-emerald-950/80 stroke-emerald-500'
                            : 'fill-[#071329]/90 stroke-cyan-400'
                        }`}
                        strokeWidth="1.5"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center pt-2 text-cyan-200">
                      <Icon className="w-3.5 h-3.5" />
                    </div>
                  </div>
                  <span className="text-[9px] font-mono font-semibold tracking-wider text-slate-300 group-hover:text-cyan-300 whitespace-nowrap bg-[#050812]/95 px-1.5 py-0.2 rounded border border-slate-800 -mt-1 shadow-sm">
                    {node.name}
                  </span>
                </div>
              );
            })}

            {/* Central HUD Core Widget (Exact match to screenshot's 3 hexagonal pills & glowing wave graph) */}
            <div className="relative z-10 w-64 h-64 rounded-full bg-[#050c1e]/90 border border-cyan-500/30 shadow-[0_0_50px_rgba(14,165,233,0.25)] flex flex-col items-center justify-between p-3.5 text-center backdrop-blur-md overflow-hidden">
              {/* Subtle radial inner glow */}
              <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(6,182,212,0.15)_0%,_transparent_75%)] pointer-events-none" />

              {/* 1. Center Top Hexagonal Pill: Identified Risks */}
              <div className="relative z-10 px-3.5 py-1 rounded-md bg-gradient-to-r from-[#3b0d28] via-[#521338] to-[#3b0d28] border border-fuchsia-500/50 shadow-[0_0_15px_rgba(217,70,239,0.3)]">
                <span className="text-[8px] font-mono uppercase tracking-wider text-fuchsia-200/90 block">
                  Identified Risks
                </span>
                <div className="flex items-center justify-center gap-1.5">
                  <span className="text-base font-black font-mono text-white tracking-tight">
                    {evidence ? (3240 + (riskMetrics.score * 8)).toLocaleString() : '3,240'}
                  </span>
                  <span className="text-[10px] font-mono font-bold text-emerald-400 flex items-center">
                    -23 ↓
                  </span>
                </div>
              </div>

              {/* 2. Middle Row: Predicted Risks (Left) & Mitigated Risks (Right) */}
              <div className="relative z-10 w-full flex items-center justify-between px-1 gap-2 mt-0.5">
                {/* Predicted Risks Pill */}
                <div className="flex-1 px-2 py-1 rounded-md bg-[#09152e] border border-cyan-500/30 text-left">
                  <span className="text-[7.5px] font-mono text-slate-400 block uppercase">
                    Predicted Risks
                  </span>
                  <div className="flex items-center gap-1">
                    <span className="text-xs font-bold font-mono text-slate-100">
                      {evidence ? (150 + riskMetrics.maliciousHits * 15) : '150'}
                    </span>
                    <span className="text-[9px] font-mono font-bold text-rose-400">
                      +23 ↑
                    </span>
                  </div>
                </div>

                {/* Mitigated Risks Pill */}
                <div className="flex-1 px-2 py-1 rounded-md bg-[#09152e] border border-cyan-500/30 text-right">
                  <span className="text-[7.5px] font-mono text-slate-400 block uppercase">
                    Mitigated Risks
                  </span>
                  <div className="flex items-center justify-end gap-1">
                    <span className="text-xs font-bold font-mono text-slate-100">
                      {evidence ? (760 + riskMetrics.benignHits * 10) : '760'}
                    </span>
                    <span className="text-[9px] font-mono font-bold text-emerald-400">
                      +23 ↑
                    </span>
                  </div>
                </div>
              </div>

              {/* 3. Subtitle: Last 7 Days */}
              <span className="relative z-10 text-[8.5px] font-mono text-slate-400 uppercase tracking-widest mt-1">
                Last 7 Days
              </span>

              {/* 4. Multi-Colored Glowing Wave Graph spanning across bottom of core */}
              <div className="relative z-10 w-full h-14 mt-auto">
                <svg className="w-full h-full" viewBox="0 0 160 45" preserveAspectRatio="none">
                  {/* Cyan Wave */}
                  <path
                    d="M 0,28 C 30,10 60,35 90,16 C 120,2 140,25 160,18"
                    fill="none"
                    stroke="#22d3ee"
                    strokeWidth="1.8"
                    className="drop-shadow-[0_0_6px_#22d3ee]"
                  />
                  {/* Pink/Magenta Wave */}
                  <path
                    d="M 0,34 C 25,22 55,38 85,24 C 115,14 135,32 160,22"
                    fill="none"
                    stroke="#ec4899"
                    strokeWidth="1.5"
                    className="drop-shadow-[0_0_6px_#ec4899]"
                  />
                  {/* Violet Wave */}
                  <path
                    d="M 0,38 C 35,32 65,42 95,30 C 125,20 145,36 160,28"
                    fill="none"
                    stroke="#a855f7"
                    strokeWidth="1.2"
                    strokeOpacity="0.8"
                  />
                </svg>
              </div>
            </div>
          </div>

          {/* Bottom Cockpit Category Triggers (Exact match to screenshot's 4 bottom circular icons) */}
          <div className="w-full max-w-lg flex flex-col items-center">
            <div className="w-full grid grid-cols-4 gap-3 sm:gap-6 pt-1">
              {/* 1. My Network (Active / Gold Glowing in screenshot) */}
              <button
                type="button"
                onClick={() => setActiveCategory('network')}
                className="group flex flex-col items-center gap-1.5 transition-all cursor-pointer"
              >
                <div
                  className={`w-11 h-11 rounded-full flex items-center justify-center transition-all ${
                    activeCategory === 'network'
                      ? 'bg-amber-950/80 border-2 border-amber-400 text-amber-300 shadow-[0_0_20px_rgba(251,191,36,0.6)]'
                      : 'bg-slate-900/80 border border-slate-700/80 text-slate-400 group-hover:text-slate-200 group-hover:border-slate-600'
                  }`}
                >
                  <Network className="w-5 h-5" />
                </div>
                <span className={`text-[11px] font-mono font-bold ${activeCategory === 'network' ? 'text-amber-300' : 'text-slate-400'}`}>
                  My Network
                </span>
              </button>

              {/* 2. My Risk */}
              <button
                type="button"
                onClick={() => setActiveCategory('risk')}
                className="group flex flex-col items-center gap-1.5 transition-all cursor-pointer"
              >
                <div
                  className={`w-11 h-11 rounded-full flex items-center justify-center transition-all ${
                    activeCategory === 'risk'
                      ? 'bg-cyan-950/80 border-2 border-cyan-400 text-cyan-300 shadow-[0_0_20px_rgba(34,211,238,0.6)]'
                      : 'bg-slate-900/80 border border-slate-700/80 text-slate-400 group-hover:text-slate-200 group-hover:border-slate-600'
                  }`}
                >
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <span className={`text-[11px] font-mono font-bold ${activeCategory === 'risk' ? 'text-cyan-300' : 'text-slate-400'}`}>
                  My Risk
                </span>
              </button>

              {/* 3. My Assets */}
              <button
                type="button"
                onClick={() => setActiveCategory('assets')}
                className="group flex flex-col items-center gap-1.5 transition-all cursor-pointer"
              >
                <div
                  className={`w-11 h-11 rounded-full flex items-center justify-center transition-all ${
                    activeCategory === 'assets'
                      ? 'bg-cyan-950/80 border-2 border-cyan-400 text-cyan-300 shadow-[0_0_20px_rgba(34,211,238,0.6)]'
                      : 'bg-slate-900/80 border border-slate-700/80 text-slate-400 group-hover:text-slate-200 group-hover:border-slate-600'
                  }`}
                >
                  <FolderLock className="w-5 h-5" />
                </div>
                <span className={`text-[11px] font-mono font-bold ${activeCategory === 'assets' ? 'text-cyan-300' : 'text-slate-400'}`}>
                  My Assets
                </span>
              </button>

              {/* 4. Countries */}
              <button
                type="button"
                onClick={() => setActiveCategory('feeds')}
                className="group flex flex-col items-center gap-1.5 transition-all cursor-pointer"
              >
                <div
                  className={`w-11 h-11 rounded-full flex items-center justify-center transition-all ${
                    activeCategory === 'feeds'
                      ? 'bg-cyan-950/80 border-2 border-cyan-400 text-cyan-300 shadow-[0_0_20px_rgba(34,211,238,0.6)]'
                      : 'bg-slate-900/80 border border-slate-700/80 text-slate-400 group-hover:text-slate-200 group-hover:border-slate-600'
                  }`}
                >
                  <Globe className="w-5 h-5" />
                </div>
                <span className={`text-[11px] font-mono font-bold ${activeCategory === 'feeds' ? 'text-cyan-300' : 'text-slate-400'}`}>
                  Countries
                </span>
              </button>
            </div>

            {/* Bottom Cockpit Framing Bracket (screenshot styling) */}
            <div className="w-48 h-2 mt-4 border-b-2 border-cyan-500/40 relative">
              <div className="absolute -bottom-1 left-0 w-3 h-3 border-l-2 border-b-2 border-cyan-400" />
              <div className="absolute -bottom-1 right-0 w-3 h-3 border-r-2 border-b-2 border-cyan-400" />
            </div>
          </div>
        </div>

        {/* ============================================================== */}
        {/* COLUMN 3: RIGHT INSPECTION & ENTITY DEEP DIVE PANEL (Screenshot style) */}
        {/* ============================================================== */}
        <div className="w-full lg:w-92 xl:w-98 border-t lg:border-t-0 lg:border-l border-cyan-500/20 bg-[#070b16]/95 backdrop-blur-xl p-4 flex flex-col gap-3.5 overflow-y-auto max-h-[92vh]">
          {/* 1. Entity / Organization Dossier Header matching screenshot */}
          <div className="p-3 rounded-xl border border-slate-800 bg-[#090e1c] shadow-lg">
            <div className="flex items-start justify-between gap-2.5">
              <div className="flex items-start gap-2.5 min-w-0 flex-1">
                {/* Geometric Purple/Violet Brand Logo (matching screenshot) */}
                <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-indigo-500 via-purple-600 to-pink-500 p-0.5 shadow-md shrink-0 flex items-center justify-center">
                  <div className="w-full h-full bg-[#090e1c] rounded-[6px] flex items-center justify-center">
                    <div className="w-4 h-4 rounded-sm bg-gradient-to-tr from-cyan-400 to-fuchsia-400 rotate-45" />
                  </div>
                </div>

                <div className="min-w-0 flex-1">
                  <h3 className="text-sm font-bold text-white truncate leading-tight">
                    {evidence ? (evidence.indicator.normalized || 'Pinnacle Finance Group') : 'Pinnacle Finance Group'}
                  </h3>
                  <a
                    href="#"
                    onClick={(e) => e.preventDefault()}
                    className="text-[10px] font-mono text-slate-400 hover:text-cyan-300 truncate block mt-0.5"
                  >
                    {evidence ? defang(evidence.indicator.normalized) : 'pinnaclefinancegroup.com'}
                  </a>
                </div>
              </div>

              {/* View Button */}
              <button
                type="button"
                onClick={onOpenReport}
                className="px-2.5 py-0.8 rounded bg-cyan-500/10 hover:bg-cyan-500/25 border border-cyan-500/40 text-[10px] font-mono font-bold text-cyan-300 transition-colors cursor-pointer shrink-0"
              >
                View
              </button>
            </div>

            {/* Subline: Timestamp & Meta Tags */}
            <div className="mt-2.5 text-[9px] font-mono text-slate-500">
              {evidence ? new Date(evidence.collected_at).toUTCString() : 'Jan 18, 2024 · 2:31 PM UTC'}
            </div>

            {/* Tags Strip (screenshot tags) */}
            <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[9px] font-mono text-slate-400">
              <span className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">Organization Type</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">Sector</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">Industry</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-cyan-400">+5</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 hover:text-white cursor-pointer">Edit</span>
            </div>

            {/* Risk Level Red Banner (Exact match to screenshot's "Risk Level 100% F") */}
            <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-[11px] font-mono font-semibold text-rose-400">Risk Level</span>
              <span className="text-xs font-mono font-black text-rose-500">
                {evidence ? `${riskMetrics.score}% ${riskMetrics.grade.split(' ')[0]}` : '100% F'}
              </span>
            </div>
          </div>

          {/* 2. Sub-Tabs: Overview vs Risk Details */}
          <div className="flex items-center gap-4 border-b border-slate-800 pb-1 text-xs font-mono">
            <button
              type="button"
              className="text-slate-400 hover:text-slate-200 pb-1 transition-colors"
            >
              Overview
            </button>
            <button
              type="button"
              className="text-cyan-300 font-bold border-b-2 border-cyan-400 pb-1 shadow-[0_2px_8px_rgba(34,211,238,0.4)]"
            >
              Risk Details
            </button>
          </div>

          {/* 3. Spiderweb / Radar Chart with Yellow/Amber Wireframe (matching screenshot) */}
          <div className="p-3 rounded-xl border border-slate-800 bg-[#090e1c] shadow-lg">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-slate-200">Risk Details</span>
              <span className="text-[9px] font-mono text-amber-400">Threat Vectors</span>
            </div>

            {/* SVG Spiderweb Chart with Amber Polygon */}
            <div className="relative w-full h-52 flex items-center justify-center">
              <svg className="w-full h-full" viewBox="0 0 240 210">
                {/* Background Concentric Radar Rings */}
                {[0.25, 0.5, 0.75, 1].map((scale) => {
                  const points = threatRadarData.map((_, i) => {
                    const angle = (i * (360 / threatRadarData.length) - 90) * (Math.PI / 180);
                    const r = 65 * scale;
                    const x = (120 + r * Math.cos(angle)).toFixed(1);
                    const y = (105 + r * Math.sin(angle)).toFixed(1);
                    return `${x},${y}`;
                  }).join(' ');
                  return (
                    <polygon
                      key={`radar-ring-${scale}`}
                      points={points}
                      fill="none"
                      stroke="#273248"
                      strokeWidth="0.8"
                      strokeDasharray={scale === 1 ? 'none' : '2 3'}
                    />
                  );
                })}

                {/* Radar Axis Spokes */}
                {threatRadarData.map((_, i) => {
                  const angle = (i * (360 / threatRadarData.length) - 90) * (Math.PI / 180);
                  const x = (120 + 65 * Math.cos(angle)).toFixed(1);
                  const y = (105 + 65 * Math.sin(angle)).toFixed(1);
                  return (
                    <line
                      key={`axis-${i}`}
                      x1="120"
                      y1="105"
                      x2={x}
                      y2={y}
                      stroke="#273248"
                      strokeWidth="0.8"
                    />
                  );
                })}

                {/* Golden/Amber Threat Polygon (exact match to screenshot's amber radar web) */}
                <polygon
                  points={radarSvgPoints}
                  fill="rgba(245, 158, 11, 0.18)"
                  stroke="#f59e0b"
                  strokeWidth="1.8"
                  className="filter drop-shadow-[0_0_8px_rgba(245,158,11,0.5)]"
                />

                {/* Radar Axis Labels */}
                {threatRadarData.map((item, i) => {
                  const angle = (i * (360 / threatRadarData.length) - 90) * (Math.PI / 180);
                  const r = 82;
                  const x = 120 + r * Math.cos(angle);
                  const y = 105 + r * Math.sin(angle);
                  return (
                    <text
                      key={`label-${item.label}`}
                      x={x}
                      y={y}
                      textAnchor="middle"
                      dominantBaseline="central"
                      fill="#94a3b8"
                      fontSize="7.5"
                      fontFamily="monospace"
                      fontWeight="500"
                    >
                      {item.label}
                    </text>
                  );
                })}
              </svg>
            </div>
          </div>

          {/* 4. Similar Organizations (Exact match to screenshot's list + checkboxes) */}
          <div className="p-3 rounded-xl border border-slate-800 bg-[#090e1c] shadow-lg flex-1 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-200">
                  Similar Organizations (1 Selected)
                </span>
                <span className="text-[10px] font-mono text-cyan-400">Pivots</span>
              </div>

              {/* Items List */}
              <div className="space-y-1.5">
                {/* 1. Horizon Investments */}
                <div className="flex items-center justify-between p-2 rounded-lg bg-[#0c1326] border border-slate-800/80 hover:border-slate-700 transition-colors">
                  <label className="flex items-center gap-2 cursor-pointer flex-1 min-w-0">
                    <input
                      type="checkbox"
                      checked={Boolean(selectedPivotIocs['Horizon Investments'])}
                      onChange={() => togglePivot('Horizon Investments')}
                      className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
                    />
                    <span className="text-xs font-medium text-slate-200 truncate">
                      Horizon Investments
                    </span>
                  </label>
                  <span className="text-[9px] font-mono text-slate-500 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800">
                    domain name
                  </span>
                </div>

                {/* 2. Legacy Capital Markets (Checked in screenshot) */}
                <div className="flex items-center justify-between p-2 rounded-lg bg-[#0c1326] border border-cyan-500/40 shadow-sm transition-colors">
                  <label className="flex items-center gap-2 cursor-pointer flex-1 min-w-0">
                    <input
                      type="checkbox"
                      checked={selectedPivotIocs['Legacy Capital Markets'] !== false}
                      onChange={() => togglePivot('Legacy Capital Markets')}
                      className="rounded border-amber-500 bg-amber-500 text-slate-950 focus:ring-0 w-3.5 h-3.5"
                    />
                    <span className="text-xs font-medium text-white truncate">
                      Legacy Capital Markets
                    </span>
                  </label>
                  <span className="text-[9px] font-mono text-slate-400 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800">
                    domain name
                  </span>
                </div>

                {/* 3. Valor Equity Group */}
                <div className="flex items-center justify-between p-2 rounded-lg bg-[#0c1326] border border-slate-800/80 hover:border-slate-700 transition-colors">
                  <label className="flex items-center gap-2 cursor-pointer flex-1 min-w-0">
                    <input
                      type="checkbox"
                      checked={Boolean(selectedPivotIocs['Valor Equity Group'])}
                      onChange={() => togglePivot('Valor Equity Group')}
                      className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
                    />
                    <span className="text-xs font-medium text-slate-200 truncate">
                      Valor Equity Group
                    </span>
                  </label>
                  <span className="text-[9px] font-mono text-slate-500 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800">
                    domain name
                  </span>
                </div>

                {/* Dynamic Pivots discovered from live evidence */}
                {pivotList.map((pivot, idx) => (
                  <div
                    key={`dyn-pivot-${idx}`}
                    className="flex items-center justify-between p-2 rounded-lg bg-[#0c1326] border border-slate-800/80 hover:border-cyan-500/40 transition-colors"
                  >
                    <label className="flex items-center gap-2 cursor-pointer flex-1 min-w-0">
                      <input
                        type="checkbox"
                        checked={Boolean(selectedPivotIocs[pivot.val])}
                        onChange={() => togglePivot(pivot.val)}
                        className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
                      />
                      <span className="text-xs font-mono text-cyan-300 truncate" title={pivot.val}>
                        {pivot.val}
                      </span>
                    </label>
                    <span className="text-[9px] font-mono text-slate-500 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800">
                      {pivot.type.toLowerCase()}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* + Add To My Network Button (Exact screenshot wording & style) */}
            <button
              type="button"
              onClick={() => {
                const selected = Object.keys(selectedPivotIocs).filter((k) => selectedPivotIocs[k]);
                if (selected.length > 0) {
                  onIndicatorChange(selected[0]);
                  onSearch();
                } else {
                  onIndicatorChange('pinnaclefinancegroup.com');
                  onSearch();
                }
              }}
              className="w-full mt-3 py-2 rounded-lg border border-dashed border-cyan-500/50 hover:border-cyan-400 bg-cyan-950/20 hover:bg-cyan-950/40 text-cyan-300 text-xs font-mono font-bold transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-sm"
            >
              <span>+ Add To My Network</span>
            </button>
          </div>

          {/* 5. AI Threat Verdict synthesis (optional drawer/collapsible) */}
          <div className="p-2.5 rounded-lg border border-violet-500/30 bg-gradient-to-br from-violet-950/20 to-[#0a0f1d] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-violet-400" />
              <span className="text-[11px] font-mono text-violet-300 font-semibold">AI Threat Synthesis</span>
            </div>
            <button
              type="button"
              onClick={onGenerateAI}
              disabled={aiLoading || !evidence}
              className="px-2 py-0.5 rounded bg-violet-600 hover:bg-violet-500 disabled:opacity-40 text-[10px] font-mono text-white cursor-pointer"
            >
              {aiLoading ? 'Synthesizing...' : 'Generate'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
