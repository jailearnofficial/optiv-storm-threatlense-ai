import React, { useState } from 'react';
import { X, ExternalLink, Copy, Check, Terminal, FileJson, ListChecks, Network, ShieldAlert, Cpu } from 'lucide-react';
import { ProviderResult } from '../types/index.js';

interface ProviderDetailModalProps {
  provider: ProviderResult | null;
  onClose: () => void;
}

export const ProviderDetailModal: React.FC<ProviderDetailModalProps> = ({
  provider,
  onClose
}) => {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'facts' | 'raw' | 'vt_graph' | 'ha_sandbox'>('facts');

  if (!provider) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(provider.raw || {}, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const hasVTDetails = Boolean(provider.vt_details || provider.vt_graph);
  const hasHADetails = Boolean(provider.ha_details);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl max-h-[85vh] flex flex-col rounded-xl bg-slate-900 border border-slate-700 shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-extrabold text-base text-slate-100">
                {provider.displayName}
              </h3>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                {provider.status.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">{provider.headline}</p>
          </div>

          <div className="flex items-center gap-2">
            {provider.link && (
              <a
                href={provider.link}
                target="_blank"
                rel="noreferrer"
                className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition-colors"
                title="Open provider external URL"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center gap-2 px-6 pt-3 border-b border-slate-800 bg-slate-900 overflow-x-auto">
          <button
            onClick={() => setActiveTab('facts')}
            className={`pb-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
              activeTab === 'facts'
                ? 'border-cyan-400 text-cyan-300 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ListChecks className="w-3.5 h-3.5" />
            Key Facts & Attributes
          </button>

          {hasHADetails && (
            <button
              onClick={() => setActiveTab('ha_sandbox')}
              className={`pb-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
                activeTab === 'ha_sandbox'
                  ? 'border-amber-400 text-amber-300 font-bold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-3.5 h-3.5 text-amber-400" />
              Falcon Sandbox & AV ({provider.ha_details?.threat_score}/100)
            </button>
          )}

          {hasVTDetails && (
            <button
              onClick={() => setActiveTab('vt_graph')}
              className={`pb-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
                activeTab === 'vt_graph'
                  ? 'border-cyan-400 text-cyan-300 font-bold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Network className="w-3.5 h-3.5 text-cyan-400" />
              VT Graph & AV Matrix
            </button>
          )}

          <button
            onClick={() => setActiveTab('raw')}
            className={`pb-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
              activeTab === 'raw'
                ? 'border-cyan-400 text-cyan-300 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileJson className="w-3.5 h-3.5" />
            Raw Normalized Payload
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {activeTab === 'facts' ? (
            <div className="space-y-4">
              {/* Score breakdown */}
              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Detection Statistics & Score
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  {Object.entries(provider.score).map(([key, val]) => (
                    <div key={key} className="p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">{key.replace(/_/g, ' ')}</span>
                      <span className="text-slate-200 font-bold text-sm">{val}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Key Facts List */}
              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Extracted Telemetry Facts
                </h4>
                {Object.keys(provider.key_facts || {}).length > 0 ? (
                  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {Object.entries(provider.key_facts).map(([key, val]) => (
                      <div key={key} className="p-2 rounded bg-slate-900 border border-slate-800">
                        <dt className="text-slate-500 text-[10px] uppercase font-mono">{key.replace(/_/g, ' ')}</dt>
                        <dd className="text-slate-200 font-mono mt-0.5 truncate select-all">
                          {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                        </dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  <p className="text-xs text-slate-500 italic">No structured key facts found for this indicator.</p>
                )}
              </div>

              {/* Tags */}
              {provider.tags && provider.tags.length > 0 && (
                <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Threat Tags & Signatures
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {provider.tags.map((tag, i) => (
                      <span key={i} className="text-xs font-mono px-2 py-1 rounded bg-slate-900 text-cyan-300 border border-slate-700">
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : activeTab === 'ha_sandbox' && provider.ha_details ? (
            <div className="space-y-4">
              {/* HA Threat Score & Key Facts Banner */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-amber-500/30">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-slate-400 uppercase">Analyzed Indicator:</span>
                      <span className="text-xs font-mono font-bold text-slate-100 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 break-all">
                        {provider.ha_details.indicator}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      <span className="text-xs text-slate-400">Environment:</span>
                      <span className="text-xs text-slate-200 font-medium">{provider.ha_details.environment}</span>
                    </div>
                  </div>
                  <div className="text-right sm:border-l sm:border-slate-800 sm:pl-4">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block">Falcon Threat Score</span>
                    <div className="flex items-center gap-2 justify-end mt-0.5">
                      <span className={`text-2xl font-black font-mono ${
                        provider.ha_details.threat_score >= 70 ? 'text-rose-400' : provider.ha_details.threat_score >= 35 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {provider.ha_details.threat_score}
                      </span>
                      <span className="text-xs text-slate-500 font-mono">/ 100</span>
                    </div>
                  </div>
                </div>

                {/* Threat score progress bar */}
                <div className="mt-3 w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                  <div
                    className={`h-full transition-all duration-500 rounded-full ${
                      provider.ha_details.threat_score >= 70
                        ? 'bg-gradient-to-r from-amber-500 to-rose-600'
                        : provider.ha_details.threat_score >= 35
                        ? 'bg-amber-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.max(provider.ha_details.threat_score, 4)}%` }}
                  />
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-4 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">AV Detection Ratio</span>
                    <span className="text-slate-100 font-bold text-sm">{provider.ha_details.av_detect_ratio}</span>
                    <span className="text-slate-400 text-[11px] block mt-0.5">({provider.ha_details.av_detect_percent}% engines)</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Threat Level</span>
                    <span className={`font-bold text-sm uppercase ${
                      provider.ha_details.threat_level === 'malicious' ? 'text-rose-400' : provider.ha_details.threat_level === 'suspicious' ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {provider.ha_details.threat_level}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Payload Family</span>
                    <span className="text-slate-200 font-bold text-sm truncate block">{provider.ha_details.family || 'N/A'}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">MITRE Techniques</span>
                    <span className="text-purple-300 font-bold text-sm">{provider.ha_details.mitre_attack.length} Observed</span>
                  </div>
                </div>
              </div>

              {/* Multi-AV scanner detections breakdown */}
              {provider.ha_details.av_detections && provider.ha_details.av_detections.length > 0 && (
                <div className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800">
                  <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5 flex items-center justify-between">
                    <span>Multi-Scanner AV Telemetry</span>
                    <span className="text-slate-500 text-[11px] font-mono">{provider.ha_details.av_detect_ratio} Flagged</span>
                  </h5>
                  <div className="space-y-2">
                    {provider.ha_details.av_detections.map((av, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                      >
                        <div>
                          <span className="font-bold text-slate-200">{av.scanner}</span>
                          <span className="text-slate-400 block text-[11px] font-mono mt-0.5">{av.result}</span>
                        </div>
                        <span
                          className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded shrink-0 ${
                            av.verdict === 'malicious'
                              ? 'bg-rose-950 text-rose-400 border border-rose-800'
                              : av.verdict === 'suspicious'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          }`}
                        >
                          {av.verdict}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK techniques breakdown */}
              {provider.ha_details.mitre_attack && provider.ha_details.mitre_attack.length > 0 && (
                <div className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800">
                  <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
                    Falcon Sandbox MITRE ATT&CK Behavioral Techniques ({provider.ha_details.mitre_attack.length})
                  </h5>
                  <div className="space-y-2">
                    {provider.ha_details.mitre_attack.map((m, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs"
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-cyan-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                              {m.technique_id}
                            </span>
                            <span className="font-bold text-slate-200">{m.technique_name}</span>
                          </div>
                          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/80">
                            {m.tactic}
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px] leading-relaxed mt-1">
                          {m.evidence}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : activeTab === 'vt_graph' ? (
            <div className="space-y-4">
              {/* VT Graph Banner */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-cyan-500/30 flex items-center justify-between gap-4">
                <div>
                  <h4 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                    <Network className="w-4 h-4 text-cyan-400" />
                    <span>VirusTotal Knowledge Graph</span>
                  </h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {provider.vt_graph?.nodes?.length || 0} nodes mapped with relationships to infrastructure and payloads.
                  </p>
                </div>
                {provider.vt_graph?.vt_graph_url && (
                  <a
                    href={provider.vt_graph.vt_graph_url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 text-xs font-bold flex items-center gap-1.5 transition-colors shrink-0"
                  >
                    <span>Open in VT Graph</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>

              {/* Graph nodes list */}
              {provider.vt_graph?.nodes && provider.vt_graph.nodes.length > 0 && (
                <div className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800">
                  <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
                    Connected Graph Entities ({provider.vt_graph.nodes.length})
                  </h5>
                  <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                    {provider.vt_graph.nodes.map((node) => (
                      <div
                        key={node.id}
                        className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between gap-2 text-xs"
                      >
                        <div className="truncate">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                              {node.type}
                            </span>
                            <span className="font-bold text-slate-200 truncate">{node.label}</span>
                          </div>
                          {node.details && (
                            <span className="text-[11px] text-slate-400 block truncate mt-0.5">
                              {node.details}
                            </span>
                          )}
                        </div>
                        <span
                          className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                            node.status === 'malicious'
                              ? 'bg-rose-950 text-rose-400 border border-rose-800'
                              : node.status === 'suspicious'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          }`}
                        >
                          {node.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Top Engine Detections */}
              {provider.vt_details?.engines && provider.vt_details.engines.length > 0 && (
                <div className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800">
                  <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
                    Flagged Security Vendors ({provider.vt_details.engines.filter(e => e.category === 'malicious').length})
                  </h5>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-52 overflow-y-auto pr-1">
                    {provider.vt_details.engines.slice(0, 14).map((eng) => (
                      <div
                        key={eng.engine_name}
                        className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs flex items-center justify-between gap-2"
                      >
                        <span className="font-bold text-slate-200">{eng.engine_name}</span>
                        <span className="text-[11px] font-mono text-rose-400 truncate max-w-[140px]">
                          {eng.result || 'Flagged'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="relative">
              <button
                onClick={handleCopy}
                className="absolute top-2 right-2 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1 transition-colors z-10"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy JSON'}
              </button>
              <pre className="p-4 rounded-lg bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto border border-slate-800 max-h-[50vh]">
                {JSON.stringify(provider.raw || {}, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
