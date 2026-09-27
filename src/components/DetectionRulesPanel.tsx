import React, { useState, useMemo } from 'react';
import {
  Code2,
  Copy,
  Check,
  Download,
  Terminal,
  FileCode,
  Shield,
  Search,
  Cpu,
  Layers,
  Sparkles,
  Info
} from 'lucide-react';
import { IndicatorType, IOCItem, MitreAttackRecord } from '../types/index.js';
import { generateDetectionPack, GeneratedDetectionPack } from '../lib/detectionRules.js';

interface DetectionRulesPanelProps {
  indicator: string;
  indicatorType: IndicatorType;
  verdict?: string;
  malwareFamily?: string;
  mitreTechniques?: MitreAttackRecord[];
  iocs?: IOCItem[];
  analystName?: string;
}

type RuleTab = 'sigma' | 'yara' | 'splunk' | 'sentinel' | 'elastic' | 'suricata';

export const DetectionRulesPanel: React.FC<DetectionRulesPanelProps> = ({
  indicator,
  indicatorType,
  verdict,
  malwareFamily,
  mitreTechniques,
  iocs,
  analystName
}) => {
  const [activeTab, setActiveTab] = useState<RuleTab>('sigma');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const pack: GeneratedDetectionPack = useMemo(() => {
    return generateDetectionPack({
      indicator,
      indicatorType,
      verdict,
      malwareFamily,
      mitreTechniques,
      iocs,
      analystName
    });
  }, [indicator, indicatorType, verdict, malwareFamily, mitreTechniques, iocs, analystName]);

  const handleCopy = (content: string, key: string) => {
    navigator.clipboard.writeText(content);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleDownload = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const currentContent = useMemo(() => {
    switch (activeTab) {
      case 'sigma':
        return { text: pack.sigmaYaml, filename: `sigma_${indicatorType}_${Date.now()}.yml`, lang: 'yaml' };
      case 'yara':
        return { text: pack.yaraRule, filename: `rule_${indicatorType}_${Date.now()}.yar`, lang: 'yara' };
      case 'splunk':
        return { text: pack.splunkQuery, filename: `splunk_query_${Date.now()}.spl`, lang: 'spl' };
      case 'sentinel':
        return { text: pack.sentinelKql, filename: `sentinel_kql_${Date.now()}.kql`, lang: 'kql' };
      case 'elastic':
        return { text: pack.elasticEql, filename: `elastic_eql_${Date.now()}.eql`, lang: 'eql' };
      case 'suricata':
        return { text: pack.suricataRule, filename: `suricata_${Date.now()}.rules`, lang: 'snort' };
    }
  }, [activeTab, pack, indicatorType]);

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-5 md:p-6 backdrop-blur-md shadow-xl">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              Automated Detection Engineering & SIEM Query Generator
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Production-ready Sigma, YARA, Splunk SPL, and Sentinel KQL rules mapped directly to investigated IOCs
            </p>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-center">
            <button
              onClick={() => handleCopy(currentContent.text, activeTab)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono font-medium text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-all cursor-pointer shadow-sm hover:border-cyan-500/40"
            >
              {copiedKey === activeTab ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400 font-bold">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-400" />
                  <span>Copy Code</span>
                </>
              )}
            </button>

            <button
              onClick={() => handleDownload(currentContent.filename, currentContent.text)}
              className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-xs font-mono font-medium text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
              title="Download rule file"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Download</span>
            </button>
          </div>
        </div>

        {/* Tab Selection Switcher */}
        <div className="flex items-center gap-2 overflow-x-auto pb-2 mb-3 custom-scrollbar border-b border-slate-800">
          <button
            type="button"
            onClick={() => setActiveTab('sigma')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              activeTab === 'sigma'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
                : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Sigma Rule (YAML)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('yara')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              activeTab === 'yara'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
                : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>YARA Rule (.yar)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('splunk')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              activeTab === 'splunk'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
                : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-amber-400" />
            <span>Splunk SPL</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('sentinel')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              activeTab === 'sentinel'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
                : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <Search className="w-3.5 h-3.5 text-blue-400" />
            <span>Microsoft Sentinel (KQL)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('elastic')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              activeTab === 'elastic'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
                : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span>Elastic EQL</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('suricata')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              activeTab === 'suricata'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
                : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-purple-400" />
            <span>Suricata / Snort IDS</span>
          </button>
        </div>

        {/* Code Content Container */}
        <div className="relative rounded-lg bg-[#050811] border border-slate-800 p-4 font-mono text-xs overflow-x-auto text-slate-200 shadow-inner max-h-96">
          <div className="flex items-center justify-between text-[11px] text-slate-500 border-b border-slate-800/80 pb-2 mb-3">
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Target: <span className="text-cyan-300 font-bold">{indicator}</span></span>
              <span>· Format: <span className="uppercase text-slate-300 font-semibold">{activeTab}</span></span>
            </span>
            <span className="text-[10px] text-slate-400">
              Analyst: {analystName || 'SOC Team'}
            </span>
          </div>
          <pre className="text-slate-200 leading-relaxed font-mono whitespace-pre select-all selection:bg-cyan-900/60 selection:text-cyan-200">
            {currentContent.text}
          </pre>
        </div>

        {/* SIEM Deployment Tips */}
        <div className="mt-3.5 flex flex-wrap items-center justify-between gap-3 text-[11px] text-slate-400 bg-slate-950/60 px-3.5 py-2.5 rounded-lg border border-slate-800/80">
          <div className="flex items-center gap-2">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>
              {activeTab === 'sigma' && 'Sigma rules can be converted directly into Splunk, Sentinel, QRadar, or Elastic using sigma-cli or pySigma.'}
              {activeTab === 'yara' && 'YARA rule contains byte signatures and malware family strings for live endpoint memory triage & forensic disk sweeps.'}
              {activeTab === 'splunk' && 'Run in Splunk Search & Reporting app to identify historical compromised hosts and network pivots across indexes.'}
              {activeTab === 'sentinel' && 'Paste into Azure Log Analytics workspace to hunt across CommonSecurityLog and DeviceNetworkEvents.'}
              {activeTab === 'elastic' && 'Execute in Elastic Security Timeline or Kibana Query Bar to detect endpoint execution sequence.'}
              {activeTab === 'suricata' && 'Deploy to pfSense, OPNsense, Zeek, or Suricata IDS engine interface to alert or drop malicious traffic.'}
            </span>
          </div>
          <span className="text-[10px] font-mono text-cyan-400 font-semibold">
            Status: READY TO DEPLOY
          </span>
        </div>
      </div>
    </div>
  );
};
