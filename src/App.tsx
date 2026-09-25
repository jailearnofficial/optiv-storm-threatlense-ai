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
import { LoginGate } from './components/LoginGate.js';
import { AuthProvider, useAuth } from './context/AuthContext.js';
import {
  EvidenceObject,
  ProviderResult,
  AIAnalysisVerdict,
  IndicatorType
} from './types/index.js';
import { FileText, ShieldAlert, CheckCircle2, Download, AlertCircle, Network, Cpu, Radio, ChevronDown, ChevronUp, Lock } from 'lucide-react';

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

  // Modals & Drawers state
  const [inspectProvider, setInspectProvider] = useState<ProviderResult | null>(null);
  const [historyOpen, setHistoryOpen] = useState<boolean>(false);
  const [reportModalId, setReportModalId] = useState<string | null>(null);

  // Provider health from /api/health
  const [providerHealth, setProviderHealth] = useState<Record<string, { configured: boolean; status: string }>>({});

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
  const handleLookup = async (submitMode = false, file?: File, customAnalystName?: string) => {
    const activeAnalyst = (customAnalystName !== undefined ? customAnalystName : analystName).trim();
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
        const res = await fetch('/api/submit', {
          method: 'POST',
          body: formData
        });

        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.error?.message || 'File submission failed');
        }

        const data = await res.json();
        setEvidence(data.evidence);
        setIndicator(data.file_info.sha256);
        setSelectedType('hash');

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
            indicator: indicator.trim(),
            type: selectedType === 'auto' ? undefined : selectedType,
            submit: submitMode,
            analyst_name: activeAnalyst || undefined
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
          rule_score: data.rule_score
        };
        setEvidence(fullEvidence);
      }
    } catch (err: any) {
      console.error('Lookup error:', err);
      setErrorMessage(err.message || 'Error communicating with backend threat engine.');
    } finally {
      setLookupLoading(false);
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
  const handlePivotIndicator = (newIndicator: string, newType: IndicatorType | 'auto') => {
    setIndicator(newIndicator);
    setSelectedType(newType);
    setAnalysis(null);
    setErrorMessage(null);

    handleLookup(false, undefined, analystName);
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

      {/* Main Content Area */}
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

        {/* Results Grid: 7 Threat Intel Providers */}
        {!evidence && !lookupLoading && (
          <div className="relative z-10 max-w-5xl mx-auto px-4 mt-8">
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

            {/* 5. Verified IOCs Table (Malicious or Suspicious) */}
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
