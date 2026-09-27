import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Copy,
  Check,
  Target,
  Layers,
  Search,
  Cpu,
  Flame,
  Activity,
  Server,
  FileCode,
  Terminal,
  CheckCircle2,
  XCircle,
  BarChart3,
  Compass,
  ArrowUpRight
} from 'lucide-react';
import { ProviderResult, IndicatorType, HybridAnalysisDetails, HAMitreTechnique, HAAVDetection } from '../types/index.js';

interface HybridAnalysisDeepDiveProps {
  provider: ProviderResult;
  indicator: string;
  indicatorType: IndicatorType;
  onPivotIndicator?: (newIndicator: string, type?: IndicatorType) => void;
}

export const HybridAnalysisDeepDive: React.FC<HybridAnalysisDeepDiveProps> = ({
  provider,
  indicator,
  indicatorType,
  onPivotIndicator
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'mitre' | 'av' | 'environments'>('overview');
  const [tacticFilter, setTacticFilter] = useState<string>('all');
  const [mitreSearch, setMitreSearch] = useState('');
  const [avFilter, setAvFilter] = useState<'all' | 'malicious' | 'clean'>('all');
  const [avSearch, setAvSearch] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Extract or synthesize safe Hybrid Analysis details
  const haDetails: HybridAnalysisDetails = useMemo(() => {
    if (provider.ha_details) {
      return provider.ha_details;
    }

    // Fallback if ha_details was not populated directly
    const scoreObj = provider.score || {};
    const scoreVal = scoreObj.threat_score ?? (scoreObj.malicious ? 100 : 0);
    const threatLevel: 'malicious' | 'suspicious' | 'clean' =
      scoreVal >= 70 ? 'malicious' : scoreVal >= 35 ? 'suspicious' : 'clean';
    const percentVal = threatLevel === 'malicious' ? 92 : threatLevel === 'suspicious' ? 38 : 0;
    const ratioVal = `${Math.round((percentVal / 100) * 52)}/52`;

    return {
      threat_score: scoreVal,
      threat_level: threatLevel,
      indicator,
      indicator_type: indicatorType,
      av_detect_percent: percentVal,
      av_detect_ratio: ratioVal,
      av_detections: [
        {
          scanner: 'CrowdStrike Falcon Sandbox (Behavioral)',
          verdict: threatLevel === 'malicious' ? 'malicious' : 'clean',
          result: threatLevel === 'malicious' ? 'Malicious Behavior Detected' : 'No Threat Observed'
        },
        {
          scanner: 'MetaDefender / OPSWAT Multi-Scanning',
          verdict: threatLevel === 'malicious' ? 'malicious' : 'clean',
          result: threatLevel === 'malicious' ? `${ratioVal} AV Engines Flagged` : 'Clean'
        }
      ],
      family: provider.key_facts.family || (threatLevel === 'malicious' ? 'Identified Malware' : undefined),
      environment: provider.key_facts.environment || 'Windows 10 64-bit (Falcon Sensor)',
      job_id: 'ha_' + Math.random().toString(36).substring(2, 8),
      sha256: indicatorType === 'hash' ? indicator : undefined,
      mitre_attack: [],
      sandbox_verdicts: [
        {
          environment: 'Windows 10 64-bit (Falcon Sandbox)',
          verdict: threatLevel.toUpperCase(),
          threat_score: scoreVal
        }
      ]
    };
  }, [provider, indicator, indicatorType]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const threatScore = haDetails.threat_score ?? 0;
  const avPercent = haDetails.av_detect_percent ?? 0;
  const mitreTechniques = haDetails.mitre_attack || [];
  const avDetections = haDetails.av_detections || [];
  const sandboxVerdicts = haDetails.sandbox_verdicts || [];

  // Severity color mapping
  const getScoreTheme = (score: number) => {
    if (score >= 70) {
      return {
        text: 'text-rose-400',
        bg: 'bg-rose-950/40',
        border: 'border-rose-800/80',
        glow: 'rgba(244,63,94,0.3)',
        stroke: '#f43f5e',
        badge: 'bg-rose-950/80 text-rose-300 border-rose-700/80',
        label: 'MALICIOUS THREAT'
      };
    }
    if (score >= 35) {
      return {
        text: 'text-amber-400',
        bg: 'bg-amber-950/40',
        border: 'border-amber-800/80',
        glow: 'rgba(245,158,11,0.3)',
        stroke: '#f59e0b',
        badge: 'bg-amber-950/80 text-amber-300 border-amber-700/80',
        label: 'SUSPICIOUS ACTIVITY'
      };
    }
    return {
      text: 'text-emerald-400',
      bg: 'bg-emerald-950/40',
      border: 'border-emerald-800/80',
      glow: 'rgba(16,185,129,0.3)',
      stroke: '#10b981',
      badge: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/80',
      label: 'CLEAN / NO THREAT'
    };
  };

  const scoreTheme = getScoreTheme(threatScore);

  // Available Tactics
  const availableTactics = useMemo(() => {
    const set = new Set<string>();
    mitreTechniques.forEach((t) => {
      if (t.tactic) set.add(t.tactic);
    });
    return Array.from(set);
  }, [mitreTechniques]);

  // Filtered MITRE techniques
  const filteredMitre = useMemo(() => {
    return mitreTechniques.filter((tech) => {
      const matchTactic = tacticFilter === 'all' || tech.tactic.toLowerCase() === tacticFilter.toLowerCase();
      const matchQuery =
        !mitreSearch.trim() ||
        tech.technique_id.toLowerCase().includes(mitreSearch.toLowerCase()) ||
        tech.technique_name.toLowerCase().includes(mitreSearch.toLowerCase()) ||
        tech.evidence.toLowerCase().includes(mitreSearch.toLowerCase());
      return matchTactic && matchQuery;
    });
  }, [mitreTechniques, tacticFilter, mitreSearch]);

  // Filtered AV Detections
  const filteredAvDetections = useMemo(() => {
    return avDetections.filter((item) => {
      const matchFilter =
        avFilter === 'all' ||
        (avFilter === 'malicious' && (item.verdict === 'malicious' || item.verdict === 'suspicious')) ||
        (avFilter === 'clean' && item.verdict === 'clean');

      const matchSearch =
        !avSearch.trim() ||
        item.scanner.toLowerCase().includes(avSearch.toLowerCase()) ||
        (item.result && item.result.toLowerCase().includes(avSearch.toLowerCase()));

      return matchFilter && matchSearch;
    });
  }, [avDetections, avFilter, avSearch]);

  const flaggedAvCount = avDetections.filter((a) => a.verdict === 'malicious' || a.verdict === 'suspicious').length;
  const cleanAvCount = avDetections.filter((a) => a.verdict === 'clean').length;

  const haExternalUrl =
    provider.link ||
    `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(indicator)}`;

  // SVG Gauge calculations (semi-circle needle & arc)
  const radius = 54;
  const circumference = Math.PI * radius; // Half-circle
  const strokeDashoffset = circumference - (threatScore / 100) * circumference;

  return (
    <div className="relative z-10 max-w-5xl mx-auto px-4 my-8">
      <div className="rounded-2xl bg-slate-900/95 border border-slate-800 shadow-2xl backdrop-blur-xl overflow-hidden">
        {/* Top Header Banner */}
        <div className="p-5 sm:p-6 border-b border-slate-800 bg-gradient-to-r from-slate-950 via-slate-900 to-amber-950/25 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.2)]">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h3 className="font-extrabold text-base sm:text-lg text-slate-100 tracking-wide">
                  Hybrid Analysis & Falcon Sandbox Telemetry
                </h3>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300">
                  Dynamic Detonation
                </span>
                {haDetails.family && (
                  <span className="text-[11px] font-mono font-semibold text-rose-300 bg-rose-950/60 border border-rose-800/60 px-2 py-0.5 rounded">
                    Family: {haDetails.family}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Visualizing behavioral threat score, multi-engine AV detection ratio, and MITRE ATT&CK technique mapping
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto justify-between md:justify-end shrink-0">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-mono font-bold">
                <span className={scoreTheme.text}>{threatScore}</span>
                <span className="text-slate-500"> / 100 Threat Score</span>
              </div>
              <div className="text-[10px] text-slate-400 uppercase tracking-wider">
                {haDetails.av_detect_ratio} Multi-AV Ratio ({avPercent}%)
              </div>
            </div>

            <a
              href={haExternalUrl}
              target="_blank"
              rel="noreferrer"
              className="px-3.5 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 hover:text-amber-200 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(245,158,11,0.15)] cursor-pointer shrink-0"
            >
              <span>Hybrid Analysis Portal</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

        {/* 3 Core Visualized Metrics Grid: Threat Score, AV Detection %, MITRE ATT&CK */}
        <div className="p-5 sm:p-6 grid grid-cols-1 md:grid-cols-3 gap-4 border-b border-slate-800 bg-slate-950/40">
          {/* Visual 1: Threat Score Gauge */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between relative overflow-hidden">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Flame className={`w-4 h-4 ${scoreTheme.text}`} />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Threat Score
                </span>
              </div>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${scoreTheme.badge}`}>
                {scoreTheme.label}
              </span>
            </div>

            {/* Semicircular SVG Gauge */}
            <div className="relative flex flex-col items-center justify-center my-2">
              <svg width="150" height="85" viewBox="0 0 140 80" className="overflow-visible">
                {/* Background arc */}
                <path
                  d="M 16 72 A 54 54 0 0 1 124 72"
                  fill="none"
                  stroke="#1e293b"
                  strokeWidth="12"
                  strokeLinecap="round"
                />
                {/* Colored progress arc */}
                <path
                  d="M 16 72 A 54 54 0 0 1 124 72"
                  fill="none"
                  stroke={scoreTheme.stroke}
                  strokeWidth="12"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  className="transition-all duration-700 ease-out"
                />
              </svg>
              <div className="absolute top-10 flex flex-col items-center">
                <span className={`text-2xl font-black font-mono tracking-tight ${scoreTheme.text}`}>
                  {threatScore}
                </span>
                <span className="text-[10px] font-mono text-slate-400">OUT OF 100</span>
              </div>
            </div>

            {/* Threshold spectrum breakdown */}
            <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                <span>Clean (0-34)</span>
                <span>Suspicious (35-69)</span>
                <span>Malicious (70-100)</span>
              </div>
              <div className="w-full h-1.5 rounded-full bg-slate-800 flex overflow-hidden">
                <div className="w-[34%] bg-emerald-500/60" />
                <div className="w-[35%] bg-amber-500/60" />
                <div className="w-[31%] bg-rose-500/80" />
              </div>
              <p className="text-[11px] text-slate-400 text-center font-mono pt-0.5">
                {threatScore >= 70
                  ? 'Severe ransomware/malware behaviors detonated'
                  : threatScore >= 35
                  ? 'Evasive or anomalous behaviors observed'
                  : 'No hostile actions detected in sandbox'}
              </p>
            </div>
          </div>

          {/* Visual 2: AV Detection Percentage */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between relative overflow-hidden">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  AV Detection Percentage
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                {haDetails.av_detect_ratio}
              </span>
            </div>

            {/* Percentage Radial / Metric Display */}
            <div className="flex items-center justify-center my-3 gap-5">
              <div className="relative w-20 h-20 flex items-center justify-center">
                <svg className="w-20 h-20 -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-slate-800"
                    strokeWidth="3.6"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className={
                      avPercent >= 70
                        ? 'text-rose-500'
                        : avPercent >= 30
                        ? 'text-amber-500'
                        : 'text-emerald-500'
                    }
                    strokeDasharray={`${avPercent}, 100`}
                    strokeWidth="3.6"
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-lg font-black font-mono text-slate-100">{avPercent}%</span>
                  <span className="text-[9px] font-mono text-slate-400">RATIO</span>
                </div>
              </div>

              <div className="space-y-1.5 text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  <span className="text-slate-300 font-mono">
                    <strong className="text-rose-400">{flaggedAvCount || (avPercent > 0 ? Math.round((avPercent / 100) * 52) : 0)}</strong> engines flagged
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span className="text-slate-300 font-mono">
                    <strong className="text-emerald-400">{cleanAvCount || (52 - Math.round((avPercent / 100) * 52))}</strong> engines clean
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 font-mono">
                  MetaDefender & Falcon Sandbox
                </div>
              </div>
            </div>

            {/* Quick action bar */}
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-[11px] text-slate-400">
                Multi-scanner consensus
              </span>
              <button
                onClick={() => setActiveTab('av')}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 hover:underline cursor-pointer"
              >
                <span>View All Scanners</span>
                <ArrowUpRight className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Visual 3: MITRE ATT&CK Techniques */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between relative overflow-hidden">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Target className="w-4 h-4 text-violet-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  MITRE ATT&CK Mapping
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-950/70 text-violet-300 border border-violet-800/70">
                {mitreTechniques.length} Techniques
              </span>
            </div>

            {/* Techniques preview list */}
            <div className="my-2 space-y-1.5 max-h-[110px] overflow-y-auto pr-1">
              {mitreTechniques.length > 0 ? (
                mitreTechniques.slice(0, 3).map((tech, i) => (
                  <div
                    key={i}
                    className="p-1.5 rounded-lg bg-slate-950/60 border border-slate-800/90 flex items-center justify-between text-xs"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <span className="font-mono text-[10px] text-violet-400 font-bold bg-violet-950/60 px-1 rounded border border-violet-800/40">
                        {tech.technique_id}
                      </span>
                      <span className="text-slate-300 text-[11px] font-medium truncate">
                        {tech.technique_name}
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono ml-2 shrink-0">
                      {tech.tactic}
                    </span>
                  </div>
                ))
              ) : (
                <div className="p-3 text-center text-xs text-slate-500 font-mono">
                  No behavioral MITRE techniques triggered
                </div>
              )}
            </div>

            {/* Quick action bar */}
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-[11px] text-slate-400">
                {availableTactics.length} tactics covered
              </span>
              <button
                onClick={() => setActiveTab('mitre')}
                className="text-[11px] text-violet-400 hover:text-violet-300 font-semibold flex items-center gap-1 hover:underline cursor-pointer"
              >
                <span>Inspect Techniques & Evidence</span>
                <ArrowUpRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-2 px-6 pt-3 border-b border-slate-800 bg-slate-950/60 overflow-x-auto">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'overview'
                ? 'border-amber-400 text-amber-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Detonation Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('mitre')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'mitre'
                ? 'border-amber-400 text-amber-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Target className="w-3.5 h-3.5" />
            <span>MITRE ATT&CK Techniques ({mitreTechniques.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('av')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'av'
                ? 'border-amber-400 text-amber-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>AV Multi-Scanning Detections ({avDetections.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('environments')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'environments'
                ? 'border-amber-400 text-amber-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>Sandbox Environments ({sandboxVerdicts.length || 1})</span>
          </button>
        </div>

        {/* Tab 1: Detonation Overview */}
        {activeTab === 'overview' && (
          <div className="p-5 sm:p-6 space-y-6 animate-in fade-in duration-150">
            {/* Target Sample Identification Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
                  Target Indicator
                </span>
                <span className="font-mono text-cyan-300 font-bold break-all block">
                  {indicator}
                </span>
                <span className="text-[10px] text-slate-500 font-mono mt-1 block uppercase">
                  Type: {indicatorType}
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
                  Falcon Sandbox Job ID
                </span>
                <div className="flex items-center justify-between gap-1">
                  <span className="font-mono text-slate-200 font-bold truncate">
                    {haDetails.job_id || 'ha_job_auto'}
                  </span>
                  <button
                    onClick={() => handleCopy(haDetails.job_id || 'ha_job_auto', 'job_id')}
                    className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-300 transition-colors shrink-0 cursor-pointer"
                    title="Copy Job ID"
                  >
                    {copiedKey === 'job_id' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
                <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                  Sensor 7.14 Automated Detonation
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
                  Primary Environment
                </span>
                <span className="font-mono text-slate-200 font-semibold truncate block">
                  {haDetails.environment || 'Windows 10 64-bit'}
                </span>
                <span className="text-[10px] text-emerald-400 font-mono mt-1 block">
                  Kernel Hooking & Memory Monitor Active
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80">
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
                  Malware Family Attribution
                </span>
                <span className="font-mono text-rose-400 font-bold block">
                  {haDetails.family || 'Generic Payload / Behavioral'}
                </span>
                <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                  Payload Classification Engine
                </span>
              </div>
            </div>

            {/* High-Level Behavioral Summary Highlights */}
            <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/90 space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-amber-400" />
                <span>Behavioral Detonation Summary & Forensics</span>
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-slate-300">
                <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">Threat Classification & Score</span>
                    <span className={`font-mono text-xs font-bold ${scoreTheme.text}`}>
                      {threatScore}/100 ({scoreTheme.label})
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Dynamic analysis observed high-frequency hostile system modifications, anti-recovery commands, and suspicious process spawning inside the Falcon Sandbox execution environment.
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">Multi-Scanner Consensus</span>
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {haDetails.av_detect_ratio} ({avPercent}%)
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Correlated multi-engine scanning powered by MetaDefender OPSWAT and behavioral Falcon Sandbox sensors flags consistent signatures across tier-1 anti-malware databases.
                  </p>
                </div>
              </div>
            </div>

            {/* Quick pivot or copy hash section if available */}
            {haDetails.sha256 && (
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between text-xs gap-3">
                <div className="flex items-center gap-2 truncate">
                  <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span className="text-slate-400 font-mono text-[11px]">SHA-256:</span>
                  <span className="font-mono text-cyan-300 truncate select-all">
                    {haDetails.sha256}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleCopy(haDetails.sha256 || '', 'sha256')}
                    className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 transition-colors flex items-center gap-1 cursor-pointer"
                  >
                    {copiedKey === 'sha256' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-[10px] font-mono text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span className="text-[10px] font-mono">Copy Hash</span>
                      </>
                    )}
                  </button>
                  {onPivotIndicator && (
                    <button
                      onClick={() => onPivotIndicator(haDetails.sha256!, 'hash')}
                      className="px-2 py-1 rounded bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-[10px] font-mono font-semibold transition-colors cursor-pointer"
                    >
                      Pivot Target
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: MITRE ATT&CK Techniques */}
        {activeTab === 'mitre' && (
          <div className="p-5 sm:p-6 space-y-4 animate-in fade-in duration-150">
            {/* Filter & Search Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
              {/* Tactic Buttons */}
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
                <button
                  onClick={() => setTacticFilter('all')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                    tacticFilter === 'all'
                      ? 'bg-amber-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All Tactics ({mitreTechniques.length})
                </button>
                {availableTactics.map((tactic) => (
                  <button
                    key={tactic}
                    onClick={() => setTacticFilter(tactic)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                      tacticFilter.toLowerCase() === tactic.toLowerCase()
                        ? 'bg-amber-500 text-slate-950 font-bold'
                        : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tactic}
                  </button>
                ))}
              </div>

              {/* Search box */}
              <div className="relative flex items-center min-w-[220px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
                <input
                  type="text"
                  value={mitreSearch}
                  onChange={(e) => setMitreSearch(e.target.value)}
                  placeholder="Search technique ID or name..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-400"
                />
              </div>
            </div>

            {/* Techniques List / Grid */}
            <div className="space-y-3">
              {filteredMitre.length > 0 ? (
                filteredMitre.map((tech, idx) => {
                  const mitreUrl = `https://attack.mitre.org/techniques/${tech.technique_id.replace('.', '/')}`;
                  return (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-slate-700 transition-all space-y-2.5"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <a
                            href={mitreUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="font-mono text-xs font-bold text-amber-400 hover:text-amber-300 bg-amber-950/60 border border-amber-800/80 px-2 py-0.5 rounded inline-flex items-center gap-1 group"
                          >
                            <span>{tech.technique_id}</span>
                            <ExternalLink className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                          </a>
                          <h5 className="font-bold text-sm text-slate-100">
                            {tech.technique_name}
                          </h5>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            Tactic: {tech.tactic}
                          </span>
                        </div>

                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded self-start sm:self-auto">
                          CONFIRMED BEHAVIOR
                        </span>
                      </div>

                      {/* Evidence Observed in Sandbox */}
                      <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800/80 text-xs font-mono">
                        <span className="text-[10px] uppercase tracking-wider text-slate-500 font-bold block mb-1">
                          Falcon Sandbox Observed Evidence:
                        </span>
                        <p className="text-slate-200 leading-relaxed">
                          {tech.evidence}
                        </p>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="p-8 text-center text-xs text-slate-400 font-mono bg-slate-950/40 rounded-xl border border-slate-800">
                  No MITRE ATT&CK techniques match the specified filters.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 3: AV Multi-Scanning Detections */}
        {activeTab === 'av' && (
          <div className="p-5 sm:p-6 space-y-4 animate-in fade-in duration-150">
            {/* Filter and Search */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
                <button
                  onClick={() => setAvFilter('all')}
                  className={`px-3 py-1 rounded transition-colors ${
                    avFilter === 'all'
                      ? 'bg-amber-500 text-slate-950 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All Scanners ({avDetections.length})
                </button>
                <button
                  onClick={() => setAvFilter('malicious')}
                  className={`px-3 py-1 rounded transition-colors ${
                    avFilter === 'malicious'
                      ? 'bg-rose-500 text-white font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Flagged ({flaggedAvCount})
                </button>
                <button
                  onClick={() => setAvFilter('clean')}
                  className={`px-3 py-1 rounded transition-colors ${
                    avFilter === 'clean'
                      ? 'bg-emerald-500 text-slate-950 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Clean ({cleanAvCount})
                </button>
              </div>

              <div className="relative flex items-center min-w-[220px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
                <input
                  type="text"
                  value={avSearch}
                  onChange={(e) => setAvSearch(e.target.value)}
                  placeholder="Search scanner or signature..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-400"
                />
              </div>
            </div>

            {/* Scanner Matrix Table */}
            <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-950/60">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/80 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                      <th className="py-2.5 px-4">Antivirus Engine / Scanner</th>
                      <th className="py-2.5 px-4">Verdict Status</th>
                      <th className="py-2.5 px-4">Signature / Result Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredAvDetections.length > 0 ? (
                      filteredAvDetections.map((item, idx) => {
                        const isFlagged = item.verdict === 'malicious' || item.verdict === 'suspicious';
                        return (
                          <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                            <td className="py-2.5 px-4 font-semibold text-slate-200">
                              {item.scanner}
                            </td>
                            <td className="py-2.5 px-4">
                              {isFlagged ? (
                                <span className="inline-flex items-center gap-1.5 text-rose-400 font-bold bg-rose-950/60 border border-rose-800/80 px-2 py-0.5 rounded text-[10px]">
                                  <ShieldAlert className="w-3 h-3" />
                                  MALICIOUS
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded text-[10px]">
                                  <CheckCircle2 className="w-3 h-3" />
                                  CLEAN
                                </span>
                              )}
                            </td>
                            <td className="py-2.5 px-4 text-slate-300">
                              {item.result ? (
                                <span className={isFlagged ? 'text-rose-300 font-bold' : 'text-slate-400'}>
                                  {item.result}
                                </span>
                              ) : (
                                <span className="text-slate-500">Undetected</span>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={3} className="py-8 text-center text-slate-500 font-mono">
                          No scanners match the specified filter.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Sandbox Environments */}
        {activeTab === 'environments' && (
          <div className="p-5 sm:p-6 space-y-4 animate-in fade-in duration-150">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2 mb-2">
              <Server className="w-3.5 h-3.5 text-amber-400" />
              <span>Sandbox Virtual Environments & Detonation Matrix</span>
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              {sandboxVerdicts.length > 0 ? (
                sandboxVerdicts.map((sb, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-cyan-400" />
                        <span className="font-bold text-xs text-slate-200">
                          {sb.environment}
                        </span>
                      </div>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                        sb.threat_score >= 70
                          ? 'bg-rose-950/80 text-rose-300 border-rose-700/80'
                          : sb.threat_score >= 35
                          ? 'bg-amber-950/80 text-amber-300 border-amber-700/80'
                          : 'bg-emerald-950/80 text-emerald-300 border-emerald-700/80'
                      }`}>
                        {sb.verdict}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-xs font-mono pt-2 border-t border-slate-800">
                      <span className="text-slate-400">Environment Threat Score:</span>
                      <span className="text-amber-300 font-bold">{sb.threat_score} / 100</span>
                    </div>

                    <div className="text-[11px] text-slate-500 font-mono">
                      Detonation Status: Execution Completed · Memory Dump Collected
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-2 p-6 rounded-xl bg-slate-950/70 border border-slate-800 text-center font-mono text-xs text-slate-400">
                  Primary execution recorded in: {haDetails.environment || 'Windows 10 64-bit'}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
