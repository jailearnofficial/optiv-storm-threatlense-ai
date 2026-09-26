/**
 * OPTIV S.T.O.R.M ThreatLense – AI Unified Threat Triage Portal
 * Core Application Dashboard
 */

import React, { useState, useEffect } from 'react';
import { HeroBackground } from './components/HeroBackground.js';
import { Header } from './components/Header.js';
import { SearchConsole } from './components/SearchConsole.js';
import { ProviderCard } from './components/ProviderCard.js';
import { ProviderDetailModal } from './components/ProviderDetailModal.js';
import { SummaryStrip } from './components/SummaryStrip.js';
import { VerdictBanner } from './components/VerdictBanner.js';
import { CategoryBreakdown } from './components/CategoryBreakdown.js';
import { ChartsPanel } from './components/ChartsPanel.js';
import { MitreAttackMatrix } from './components/MitreAttackMatrix.js';
import { IocTable } from './components/IocTable.js';
import { HistoryDrawer } from './components/HistoryDrawer.js';
import { ReportModal } from './components/ReportModal.js';
import { VirusTotalDeepDive } from './components/VirusTotalDeepDive.js';
import { HybridAnalysisDeepDive } from './components/HybridAnalysisDeepDive.js';
import { AlienVaultOTXDeepDive } from './components/AlienVaultOTXDeepDive.js';
import { ThreatGraphPanel } from './components/ThreatGraphPanel.js';
import { NetworkEnrichmentPanel } from './components/NetworkEnrichmentPanel.js';
import { DetectionRulesPanel } from './components/DetectionRulesPanel.js';
import { InvestigationHistoryFeed } from './components/InvestigationHistoryFeed.js';
import { TrendingThreatIntel } from './components/TrendingThreatIntel.js';
import { LoginGate } from './components/LoginGate.js';
import { AuthProvider, useAuth } from './context/AuthContext.js';
import {
  EvidenceObject,
  ProviderResult,
  AIAnalysisVerdict,
  IndicatorType,
  HistoryItemDTO
} from './types/index.js';
import { FileText, ShieldAlert, CheckCircle2, Download, AlertCircle, Network, Cpu, Radio, ChevronDown, ChevronUp, Lock, Database, RefreshCw, Globe, FileCode } from 'lucide-react';

function Dashboard() {
  const { user, loading: authLoading } = useAuth();
  const [indicator, setIndicator] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('auto');
  const [analystName, setAnalystName] = useState<string>('');
  const [lookupLoading, setLookupLoading] = useState<boolean>(false);
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [evidence, setEvidence] = useState<EvidenceObject | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysisVerdict | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showVTGraph, setShowVTGraph] = useState<boolean>(true);
  const [showHADeepDive, setShowHADeepDive] = useState<boolean>(true);
  const [showOTXDeepDive, setShowOTXDeepDive] = useState<boolean>(true);
  const [showThreatGraph, setShowThreatGraph] = useState<boolean>(true);
  const [showNetworkEnrichment, setShowNetworkEnrichment] = useState<boolean>(true);
  const [showDetectionRules, setShowDetectionRules] = useState<boolean>(true);

  // Modals & Drawers state
  const [inspectProvider, setInspectProvider] = useState<ProviderResult | null>(null);
  const [historyOpen, setHistoryOpen] = useState<boolean>(false);
  const [reportModalId, setReportModalId] = useState<string | null>(null);

  // Provider health from /api/health
  const [providerHealth, setProviderHealth] = useState<Record<string, { configured: boolean; status: string }>>({});
  // Recent investigation updates for Command Center stream (shared across all analysts)
  const [historyList, setHistoryList] = useState<HistoryItemDTO[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await fetch('/api/history?limit=50');
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : (data.history || []);
        setHistoryList(list);
      }
    } catch (err) {
      console.error('History load error:', err);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
    // Auto-sync history every 15s to keep all users in sync
    const interval = setInterval(() => {
      loadHistory();
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  // Restore last active investigation on page refresh from 24h history
  useEffect(() => {
    const savedLookupId = localStorage.getItem('threatlense_active_lookup_id');
    if (savedLookupId) {
      handleSelectLookupFromHistory(savedLookupId);
    }
  }, []);

  useEffect(() => {
    if (user) {
      const defaultName = user.displayName || user.email?.split('@')[0] || 'SOC Analyst';
      setAnalystName((prev) => (prev.trim() ? prev : defaultName));
    }
  }, [user]);

  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => {
        if (data.providers) setProviderHealth(data.providers);
      })
      .catch((err) => console.error('Health check failed:', err));
  }, []);

  // Handler for lookup execution
  const handleLookup = async (
    submitMode = false,
    file?: File,
    customAnalystName?: string,
    forceRefresh = false,
    directIndicator?: string,
    directType?: IndicatorType | 'auto'
  ) => {
    const activeAnalyst = (customAnalystName !== undefined ? customAnalystName : analystName).trim();
    const targetIndicator = (directIndicator !== undefined ? directIndicator : indicator).trim();
    const targetType = (directType !== undefined ? directType : selectedType);

    setLookupLoading(true);
    setErrorMessage(null);
    setAnalysis(null);

    try {
      if (file) {
        // Multipart file submit
        const formData = new FormData();
        formData.append('file', file);
        if (activeAnalyst) {
          formData.append('analyst_name', activeAnalyst);
        }
        if (forceRefresh) {
          formData.append('force_refresh', 'true');
        }
        const res = await fetch('/api/submit', {
          method: 'POST',
          body: formData
        });

        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.error?.message || 'File submission failed');
        }

        const data = await res.json();
        const fullEvidence: EvidenceObject = {
          ...data.evidence,
          cached: Boolean(data.cached),
          cache_age_ms: data.cache_age_ms,
          retention_window_hours: data.evidence?.retention_window_hours || 24
        };
        setEvidence(fullEvidence);
        setIndicator(data.file_info.sha256);
        setSelectedType('hash');
        localStorage.setItem('threatlense_active_lookup_id', fullEvidence.id);

        // Automatically synthesize AI analysis for the submitted file sample
        if (data.lookup_id) {
          synthesizeAIForLookup(data.lookup_id, activeAnalyst);
        }
      } else {
        // Regular JSON lookup
        const res = await fetch('/api/lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            indicator: targetIndicator,
            type: targetType === 'auto' ? undefined : targetType,
            submit: submitMode,
            analyst_name: activeAnalyst || undefined,
            force_refresh: forceRefresh,
            bypass_cache: forceRefresh
          })
        });

        if (!res.ok) {
          let errMsg = `Threat lookup failed (HTTP ${res.status})`;
          try {
            const errData = await res.json();
            errMsg = errData.error?.message || errData.message || errMsg;
          } catch {
            const rawText = await res.text();
            if (rawText) errMsg = `Server returned ${res.status}: ${rawText.substring(0, 100)}`;
          }
          throw new Error(errMsg);
        }

        const data = await res.json();
        const fullEvidence: EvidenceObject = {
          id: data.lookup_id,
          indicator: data.indicator,
          analyst_name: data.analyst_name || activeAnalyst,
          collected_at: data.collected_at,
          providers: data.providers,
          related: data.related || { domains: [], ips: [], urls: [], hashes: [] },
          mitre_hints: data.mitre_hints || [],
          rule_score: data.rule_score,
          cached: Boolean(data.cached),
          cached_at: data.cached_at,
          cache_age_ms: data.cache_age_ms,
          retention_window_hours: data.retention_window_hours || 24
        };
        setEvidence(fullEvidence);
        localStorage.setItem('threatlense_active_lookup_id', fullEvidence.id);

        // Automatically synthesize ThreatLense AI summary immediately upon feeds aggregation
        if (data.lookup_id) {
          synthesizeAIForLookup(data.lookup_id, activeAnalyst);
        }
      }
    } catch (err: any) {
      console.error('Lookup error:', err);
      setErrorMessage(err.message || 'Error communicating with backend threat engine.');
    } finally {
      setLookupLoading(false);
      loadHistory();
    }
  };

  // Helper for synthesizing Gemini AI triage
  const synthesizeAIForLookup = async (lookupId: string, customAnalyst?: string) => {
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      const activeAnalyst = (customAnalyst !== undefined ? customAnalyst : analystName).trim();
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          lookup_id: lookupId,
          refresh: true,
          analyst_name: activeAnalyst || undefined
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error?.message || 'AI analysis synthesis failed');
      }

      const verdictData: AIAnalysisVerdict = await res.json();
      setAnalysis(verdictData);
    } catch (err: any) {
      console.error('AI analysis error:', err);
      setErrorMessage(err.message || 'ThreatLense AI service encountered an error.');
    } finally {
      setAnalyzing(false);
    }
  };

  // Handler for manual Gemini AI triage synthesis button
  const handleAnalyzeAI = async () => {
    if (!evidence) return;
    await synthesizeAIForLookup(evidence.id, analystName.trim() || evidence.analyst_name);
  };

  // Pivot indicator investigation
  const handlePivotIndicator = (newIndicator: string, newType: IndicatorType | 'auto' = 'auto') => {
    setIndicator(newIndicator);
    setSelectedType(newType);
    setAnalysis(null);
    setErrorMessage(null);

    // Scroll smoothly to top search console
    window.scrollTo({ top: 0, behavior: 'smooth' });

    handleLookup(false, undefined, analystName, false, newIndicator, newType);
  };

  // Select from history drawer
  const handleSelectLookupFromHistory = async (lookupId: string) => {
    try {
      const res = await fetch(`/api/lookup/${lookupId}`);
      if (res.ok) {
        const ev: EvidenceObject = await res.json();
        setEvidence(ev);
        setIndicator(ev.indicator.normalized);
        setSelectedType(ev.indicator.type);
        localStorage.setItem('threatlense_active_lookup_id', lookupId);

        // Check if there is an existing analysis for this lookup
        const anlRes = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ lookup_id: lookupId, refresh: false })
        });
        if (anlRes.ok) {
          const anl = await anlRes.json();
          setAnalysis(anl);
        } else {
          setAnalysis(null);
        }
      } else if (res.status === 404) {
        localStorage.removeItem('threatlense_active_lookup_id');
      }
    } catch (err) {
      console.error(err);
    }
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#070A10] text-slate-100 flex flex-col items-center justify-center p-6 relative overflow-hidden font-sans">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b0f_1px,transparent_1px),linear-gradient(to_bottom,#1e293b0f_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none" />
        <div className="relative z-10 flex flex-col items-center gap-4 text-center">
          <div className="relative flex items-center justify-center w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_25px_rgba(34,211,238,0.2)]">
            <ShieldAlert className="w-7 h-7 text-cyan-400 animate-pulse" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100 uppercase tracking-wider">
              OPTIV S.T.O.R.M ThreatLense AI
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Verifying SOC Analyst Authorization & Session...
            </p>
          </div>
          <div className="w-48 h-1 bg-slate-800 rounded-full overflow-hidden mt-2">
            <div className="w-full h-full bg-gradient-to-r from-cyan-500 to-violet-500 animate-pulse" />
          </div>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginGate />;
  }

  return (
    <div className="relative min-h-screen bg-[#0A0E17] text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background canvas */}
      <HeroBackground />

      {/* Header bar with live provider health dots */}
      <Header
        onOpenHistory={() => setHistoryOpen(true)}
        providerHealth={providerHealth}
      />

      {/* Main Content Area (Classic SOC View) */}
      <main className="flex-1 max-w-7xl w-full mx-auto pb-16">
        {/* Search Console */}
        <SearchConsole
          indicator={indicator}
          setIndicator={setIndicator}
          selectedType={selectedType}
          setSelectedType={setSelectedType}
          onLookup={handleLookup}
          loading={lookupLoading}
          analystName={analystName}
          setAnalystName={setAnalystName}
        />

        {/* Error Notification Banner */}
        {errorMessage && (
          <div className="max-w-5xl mx-auto px-4 mb-4">
            <div className="p-3.5 rounded-xl bg-rose-950/70 border border-rose-700 text-rose-200 text-xs flex items-center justify-between gap-3 shadow-lg">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
              <button
                onClick={() => setErrorMessage(null)}
                className="text-rose-400 hover:text-rose-200 underline font-mono text-[11px]"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Quick Switch / Back to 24h Feed Bar if evidence is active */}
        {evidence && (
          <div className="max-w-5xl mx-auto px-4 mb-4 flex items-center justify-between">
            <button
              type="button"
              onClick={() => {
                setEvidence(null);
                setAnalysis(null);
                setIndicator('');
                localStorage.removeItem('threatlense_active_lookup_id');
              }}
              className="text-xs font-mono px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-700 flex items-center gap-2 transition-colors cursor-pointer shadow-sm"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>← New Investigation / View 24h Team Feed</span>
            </button>
            <span className="text-[11px] font-mono text-slate-400">
              Active Investigation: <span className="text-cyan-300 font-semibold">{evidence.id}</span>
            </span>
          </div>
        )}

        {/* Trending Threat Intelligence (Top 5 Emerging Threats Globally) */}
        {!evidence && !lookupLoading && (
          <TrendingThreatIntel
            onSelectIndicator={handlePivotIndicator}
            isLoading={lookupLoading}
          />
        )}

        {/* Live 24-Hour Investigation History & Audit Trail (Visible to all users on login) */}
        {!evidence && !lookupLoading && (
          <InvestigationHistoryFeed
            historyList={historyList}
            loading={historyLoading}
            onRefresh={loadHistory}
            onSelectLookup={handleSelectLookupFromHistory}
            onViewDossier={(lookupId) => {
              handleSelectLookupFromHistory(lookupId);
              setReportModalId(lookupId);
            }}
            currentLookupId={null}
            collapsedDefault={false}
          />
        )}

        {/* Threat Capabilities Guidance (when no active lookup) */}
        {!evidence && !lookupLoading && (
          <div className="relative z-10 max-w-5xl mx-auto px-4 mt-6">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-8 text-center backdrop-blur-md">
              <div className="inline-flex p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mb-4">
                <ShieldAlert className="w-8 h-8" />
              </div>
              <h2 className="text-lg font-bold text-slate-100 uppercase tracking-wide mb-2">
                Production Threat Intelligence Console Ready
              </h2>
              <p className="text-sm text-slate-400 max-w-xl mx-auto mb-6 leading-relaxed">
                Enter any live <strong>MD5 / SHA-1 / SHA-256 hash</strong>, <strong>domain</strong>, <strong>public IPv4/IPv6</strong>, or <strong>URL</strong> above to initiate real-time parallel triage across all 7 threat feeds.
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-3xl mx-auto text-left">
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1">Hash Support</span>
                  <span className="text-xs text-slate-300 font-mono">MD5, SHA1, SHA256</span>
                  <p className="text-[11px] text-slate-500 mt-1">VT, Hybrid Analysis, MalwareBazaar, OTX, urlscan</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1">Domain Support</span>
                  <span className="text-xs text-slate-300 font-mono">FQDN (e.g. google.com)</span>
                  <p className="text-[11px] text-slate-500 mt-1">VT, Hybrid Analysis, URLhaus, urlscan, OTX</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1">IP Support</span>
                  <span className="text-xs text-slate-300 font-mono">Public IPv4 & IPv6</span>
                  <p className="text-[11px] text-slate-500 mt-1">AbuseIPDB, VT, urlscan, OTX, URLhaus</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1">URL Support</span>
                  <span className="text-xs text-slate-300 font-mono">HTTP & HTTPS endpoints</span>
                  <p className="text-[11px] text-slate-500 mt-1">URLhaus, urlscan.io, VT, OTX</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 24-Hour Retention Cache Notice */}
        {evidence && evidence.cached && (
          <div className="relative z-10 max-w-5xl mx-auto px-4 mb-5">
            <div className="rounded-xl bg-gradient-to-r from-cyan-950/80 via-slate-900/90 to-cyan-950/80 border border-cyan-500/50 p-3.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400 shrink-0">
                  <Database className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                      24-Hour Retention Cache Hit
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300">
                      Local Cache · Zero Threat Feed Quota Used
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-0.5">
                    Identical indicator previously investigated within the 24-hour retention window. Retrieved instantly from local cache.
                    {evidence.cache_age_ms !== undefined && (
                      <span className="font-mono text-cyan-400 ml-1.5 font-medium">
                        · Analyzed {Math.max(1, Math.round(evidence.cache_age_ms / 60000))}m ago
                      </span>
                    )}
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => handleLookup(false, undefined, analystName, true)}
                disabled={lookupLoading}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 border border-cyan-500/40 text-cyan-300 hover:text-cyan-200 text-xs font-mono font-semibold flex items-center gap-1.5 shrink-0 transition-colors cursor-pointer shadow-sm disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${lookupLoading ? 'animate-spin' : ''}`} />
                <span>Force Live Re-Scan</span>
              </button>
            </div>
          </div>
        )}

        {/* Results Grid: 7 Threat Intel Providers */}
        {evidence && (
          <section className="relative z-10 max-w-5xl mx-auto px-4 mb-6">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Parallel Threat Intelligence Fan-Out ({evidence.providers.length} Feeds)
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                Collected at: {new Date(evidence.collected_at).toLocaleTimeString()}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3.5">
              {evidence.providers.map((provider) => (
                <ProviderCard
                  key={provider.name}
                  provider={provider}
                  onViewDetails={(p) => setInspectProvider(p)}
                  isLoading={lookupLoading}
                />
              ))}
            </div>
          </section>
        )}

        {/* VirusTotal Telemetry & Interactive VT Graph Deep Dive */}
        {evidence && evidence.providers.some((p) => p.name === 'virustotal') && (
          <div>
            <div className="max-w-5xl mx-auto px-4 mt-6 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  VirusTotal Telemetry & Graph Explorer
                </h3>
              </div>
              <button
                onClick={() => setShowVTGraph(!showVTGraph)}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
              >
                <span>{showVTGraph ? 'Hide Graph & Detections' : 'Show Graph & Detections'}</span>
                {showVTGraph ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {showVTGraph && (
              <VirusTotalDeepDive
                provider={evidence.providers.find((p) => p.name === 'virustotal')!}
                indicator={evidence.indicator.normalized}
                indicatorType={evidence.indicator.type}
                onPivotIndicator={(newInd, type) => handlePivotIndicator(newInd, type || 'auto')}
              />
            )}
          </div>
        )}

        {/* Hybrid Analysis Falcon Sandbox Deep Dive */}
        {evidence && evidence.providers.some((p) => p.name === 'hybrid_analysis') && (
          <div>
            <div className="max-w-5xl mx-auto px-4 mt-6 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-amber-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Hybrid Analysis & Falcon Sandbox Deep Dive
                </h3>
              </div>
              <button
                onClick={() => setShowHADeepDive(!showHADeepDive)}
                className="text-xs text-amber-400 hover:text-amber-300 font-semibold flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
              >
                <span>{showHADeepDive ? 'Hide Sandbox & ATT&CK' : 'Show Sandbox & ATT&CK'}</span>
                {showHADeepDive ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {showHADeepDive && (
              <HybridAnalysisDeepDive
                provider={evidence.providers.find((p) => p.name === 'hybrid_analysis')!}
                indicator={evidence.indicator.normalized}
                indicatorType={evidence.indicator.type}
                onPivotIndicator={(newInd, type) => handlePivotIndicator(newInd, type || 'auto')}
              />
            )}
          </div>
        )}

        {/* AlienVault OTX Community Threat Pulses Deep Dive */}
        {evidence && evidence.providers.some((p) => p.name === 'alienvault_otx') && (
          <div>
            <div className="max-w-5xl mx-auto px-4 mt-6 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-violet-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  AlienVault OTX & Community Threat Pulses
                </h3>
              </div>
              <button
                onClick={() => setShowOTXDeepDive(!showOTXDeepDive)}
                className="text-xs text-violet-400 hover:text-violet-300 font-semibold flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
              >
                <span>{showOTXDeepDive ? 'Hide OTX Pulses' : 'Show OTX Pulses'}</span>
                {showOTXDeepDive ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {showOTXDeepDive && (
              <AlienVaultOTXDeepDive
                provider={evidence.providers.find((p) => p.name === 'alienvault_otx')!}
                indicator={evidence.indicator.normalized}
                indicatorType={evidence.indicator.type}
                onPivotIndicator={(newInd, type) => handlePivotIndicator(newInd, type || 'auto')}
              />
            )}
          </div>
        )}

        {/* 1. Interactive Node-Link Threat & Infrastructure Graph */}
        {evidence && (
          <div>
            <div className="max-w-5xl mx-auto px-4 mt-6 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Interactive Node-Link Threat Graph
                </h3>
              </div>
              <button
                onClick={() => setShowThreatGraph(!showThreatGraph)}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
              >
                <span>{showThreatGraph ? 'Hide Threat Graph' : 'Show Threat Graph'}</span>
                {showThreatGraph ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {showThreatGraph && (
              <ThreatGraphPanel
                indicator={evidence.indicator.normalized}
                indicatorType={evidence.indicator.type}
                providers={evidence.providers}
                related={evidence.related}
                onPivotIndicator={(newInd, type) => handlePivotIndicator(newInd, type || 'auto')}
              />
            )}
          </div>
        )}

        {/* 2. Attack Surface, Passive DNS, WHOIS & Certificate Infrastructure Enrichment */}
        {evidence && (
          <div>
            <div className="max-w-5xl mx-auto px-4 mt-6 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Infrastructure & Attack Surface Enrichment (Passive DNS / WHOIS / SSL)
                </h3>
              </div>
              <button
                onClick={() => setShowNetworkEnrichment(!showNetworkEnrichment)}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
              >
                <span>{showNetworkEnrichment ? 'Hide Infrastructure Intel' : 'Show Infrastructure Intel'}</span>
                {showNetworkEnrichment ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {showNetworkEnrichment && (
              <NetworkEnrichmentPanel
                indicator={evidence.indicator.normalized}
                indicatorType={evidence.indicator.type}
                providers={evidence.providers}
                onPivotIndicator={(newInd, type) => handlePivotIndicator(newInd, type || 'auto')}
              />
            )}
          </div>
        )}

        {/* Summary Strip (Risk Gauge + ThreatLense AI Synthesis - Placed at the end of all detailed telemetry) */}
        {evidence && (
          <SummaryStrip
            ruleScore={evidence.rule_score}
            onAnalyzeAI={handleAnalyzeAI}
            isAnalyzing={analyzing}
            hasAnalysis={Boolean(analysis)}
          />
        )}

        {/* AI Analysis Dossier Section (Renders when Gemini AI completes) */}
        {analysis && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-300">
            {/* 1. Verdict Banner */}
            <VerdictBanner analysis={analysis} />

            {/* 2. Multi-Category Breakdown */}
            <CategoryBreakdown analysis={analysis} />

            {/* 3. Recharts Telemetry Visualizations */}
            <ChartsPanel analysis={analysis} />

            {/* 4. MITRE ATT&CK Matrix */}
            <MitreAttackMatrix records={analysis.mitre_attack} />

            {/* 5. Automated Sigma, YARA & SIEM Query Generator */}
            <div>
              <div className="max-w-5xl mx-auto px-4 mt-6 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    Sigma, YARA & SIEM Query Builder (Splunk / Sentinel / Elastic)
                  </h3>
                </div>
                <button
                  onClick={() => setShowDetectionRules(!showDetectionRules)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
                >
                  <span>{showDetectionRules ? 'Hide Detection Rules' : 'Show Detection Rules'}</span>
                  {showDetectionRules ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
              </div>

              {showDetectionRules && (
                <DetectionRulesPanel
                  indicator={evidence?.indicator.normalized || indicator}
                  indicatorType={(evidence?.indicator.type || 'domain') as IndicatorType}
                  verdict={analysis.verdict}
                  malwareFamily={analysis.malware_family}
                  mitreTechniques={analysis.mitre_attack}
                  iocs={analysis.iocs}
                  analystName={analystName || analysis.analyst_name}
                />
              )}
            </div>

            {/* 6. Verified IOCs Table (Malicious or Suspicious) */}
            <IocTable iocs={analysis.iocs} analysisId={analysis.id} />

            {/* Report & Export Action Bar */}
            <div className="max-w-5xl mx-auto px-4 my-8 flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/90 border border-slate-800 backdrop-blur-md">
              <div className="flex items-center gap-3 text-xs text-slate-400">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>
                  Investigation dossier compiled · ID:{' '}
                  <span className="font-mono text-slate-200">{analysis.id}</span>
                </span>
              </div>

              <div className="flex items-center gap-2.5 w-full sm:w-auto justify-end">
                <button
                  onClick={() => setReportModalId(analysis.id)}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(34,211,238,0.25)]"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Download / Print PDF Dossier</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Collapsible 24-Hour Investigation History Bar (Available while viewing any case) */}
        {evidence && (
          <InvestigationHistoryFeed
            historyList={historyList}
            loading={historyLoading}
            onRefresh={loadHistory}
            onSelectLookup={handleSelectLookupFromHistory}
            onViewDossier={(lookupId) => {
              handleSelectLookupFromHistory(lookupId);
              setReportModalId(analysis?.id || null);
            }}
            currentLookupId={evidence?.id}
            collapsedDefault={true}
          />
        )}
      </main>

      {/* Provider Details Modal Drawer */}
      <ProviderDetailModal
        provider={inspectProvider}
        onClose={() => setInspectProvider(null)}
      />

      {/* History Slide-Over Drawer */}
      <HistoryDrawer
        isOpen={historyOpen}
        onClose={() => setHistoryOpen(false)}
        onSelectLookup={handleSelectLookupFromHistory}
      />

      {/* Print / PDF Report Modal */}
      <ReportModal
        analysisId={reportModalId}
        analystName={analysis?.analyst_name || evidence?.analyst_name || analystName}
        onClose={() => setReportModalId(null)}
      />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Dashboard />
    </AuthProvider>
  );
}
