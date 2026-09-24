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
import {
  EvidenceObject,
  ProviderResult,
  AIAnalysisVerdict,
  IndicatorType
} from './types/index.js';
import { FileText, ShieldAlert, CheckCircle2, Download, AlertCircle, Network, Cpu, Radio, ChevronDown, ChevronUp } from 'lucide-react';

export default function App() {
  const [indicator, setIndicator] = useState<string>(
    'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8'
  );
  const [selectedType, setSelectedType] = useState<string>('auto');
  const [analystName, setAnalystName] = useState<string>(() => {
    try {
      return localStorage.getItem('soc_analyst_name') || '';
    } catch {
      return '';
    }
  });
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
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => {
        if (data.providers) setProviderHealth(data.providers);
      })
      .catch((err) => console.error('Health check failed:', err));

    // Automatically run initial lookup for the preset sample
    handleLookup(false);
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
          const errData = await res.json();
          throw new Error(errData.error?.message || 'Threat lookup failed');
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

  // Handler for Gemini AI triage synthesis
  const handleAnalyzeAI = async () => {
    if (!evidence) return;
    setAnalyzing(true);
    setErrorMessage(null);

    try {
      const activeAnalyst = analystName.trim() || evidence.analyst_name;
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          lookup_id: evidence.id,
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

  // Select sample from preset list or pivot
  const handleSelectSample = (sampleIndicator: string, sampleType: IndicatorType | 'auto') => {
    setIndicator(sampleIndicator);
    setSelectedType(sampleType);
    setAnalysis(null);
    setErrorMessage(null);

    // Run lookup on sample immediately
    setTimeout(() => {
      fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: sampleIndicator, type: sampleType })
      })
        .then((res) => res.json())
        .then((data) => {
          if (data.lookup_id) {
            setEvidence({
              id: data.lookup_id,
              indicator: data.indicator,
              collected_at: data.collected_at,
              providers: data.providers,
              related: data.related || { domains: [], ips: [], urls: [], hashes: [] },
              mitre_hints: data.mitre_hints || [],
              rule_score: data.rule_score
            });
          }
        })
        .catch((err) => console.error(err));
    }, 100);
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
        if (ev.analyst_name && !analystName) {
          setAnalystName(ev.analyst_name);
        }

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

  return (
    <div className="relative min-h-screen bg-[#0A0E17] text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background canvas */}
      <HeroBackground />

      {/* Header bar with live provider health dots */}
      <Header
        onOpenHistory={() => setHistoryOpen(true)}
        onSelectSample={handleSelectSample}
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
                onPivotIndicator={(newInd, type) => handleSelectSample(newInd, type || 'auto')}
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
                onPivotIndicator={(newInd, type) => handleSelectSample(newInd, type || 'auto')}
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
                onPivotIndicator={(newInd, type) => handleSelectSample(newInd, type || 'auto')}
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
