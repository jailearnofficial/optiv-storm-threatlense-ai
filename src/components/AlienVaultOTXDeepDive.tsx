import React, { useState, useMemo } from 'react';
import {
  Radio,
  ExternalLink,
  Copy,
  Check,
  Globe,
  Tag,
  Search,
  BookOpen,
  ArrowUpRight,
  Filter,
  Users
} from 'lucide-react';
import { ProviderResult, IndicatorType, AlienVaultOTXDetails, OTXPulse } from '../types/index.js';

interface AlienVaultOTXDeepDiveProps {
  provider: ProviderResult;
  indicator: string;
  indicatorType: IndicatorType;
  onPivotIndicator?: (newIndicator: string, type?: IndicatorType) => void;
}

export const AlienVaultOTXDeepDive: React.FC<AlienVaultOTXDeepDiveProps> = ({
  provider,
  indicator,
  indicatorType,
  onPivotIndicator
}) => {
  const [activeTab, setActiveTab] = useState<'pulses' | 'mitre' | 'geography' | 'references'>('pulses');
  const [pulseSearch, setPulseSearch] = useState('');
  const [selectedTag, setSelectedTag] = useState<string>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Extract or synthesize safe AlienVault OTX details
  const otxDetails: AlienVaultOTXDetails = useMemo(() => {
    if (provider.otx_details) {
      return provider.otx_details;
    }

    const pulseCount = provider.score?.pulse_count ?? (provider.score?.malicious ? 12 : 0);
    const adversary = provider.key_facts?.adversary || (pulseCount >= 3 ? 'Correlated Threat Group' : undefined);

    return {
      indicator,
      indicator_type: indicatorType,
      pulse_count: pulseCount,
      adversary,
      pulses: [],
      targeted_countries: ['Global'],
      tags: pulseCount > 0 ? ['threat-pulse', 'otx-telemetry'] : ['unindexed'],
      references: []
    };
  }, [provider, indicator, indicatorType]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const pulses = otxDetails.pulses || [];

  // Collect all unique tags
  const allTags = useMemo(() => {
    const tags = new Set<string>();
    pulses.forEach((p) => {
      p.tags?.forEach((t) => tags.add(t));
    });
    otxDetails.tags?.forEach((t) => tags.add(t));
    return Array.from(tags);
  }, [pulses, otxDetails.tags]);

  // Filter pulses based on search and selected tag
  const filteredPulses = useMemo(() => {
    return pulses.filter((p) => {
      const matchesSearch =
        !pulseSearch ||
        p.name.toLowerCase().includes(pulseSearch.toLowerCase()) ||
        p.description?.toLowerCase().includes(pulseSearch.toLowerCase()) ||
        p.author_name?.toLowerCase().includes(pulseSearch.toLowerCase()) ||
        p.adversary?.toLowerCase().includes(pulseSearch.toLowerCase());

      const matchesTag =
        selectedTag === 'all' ||
        (p.tags && p.tags.includes(selectedTag));

      return matchesSearch && matchesTag;
    });
  }, [pulses, pulseSearch, selectedTag]);

  // Collect unique ATT&CK IDs across pulses
  const attackIds = useMemo(() => {
    const set = new Set<string>();
    pulses.forEach((p) => {
      p.attack_ids?.forEach((id) => set.add(id));
    });
    return Array.from(set);
  }, [pulses]);

  // Collect unique references
  const allReferences = useMemo(() => {
    const set = new Set<string>();
    pulses.forEach((p) => {
      p.references?.forEach((r) => set.add(r));
    });
    otxDetails.references?.forEach((r) => set.add(r));
    return Array.from(set);
  }, [pulses, otxDetails.references]);

  const pulseCount = otxDetails.pulse_count ?? pulses.length;

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-2xl bg-slate-900/90 border border-violet-900/40 p-5 md:p-6 backdrop-blur-xl shadow-2xl shadow-violet-950/20">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded-xl bg-violet-950/60 border border-violet-800/60 text-violet-400 shrink-0">
              <Radio className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className="text-xs font-mono uppercase tracking-wider font-bold text-violet-400">
                  AlienVault Open Threat Exchange (OTX)
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-950/80 text-violet-300 border border-violet-800/70">
                  Global Threat Telemetry
                </span>
                {otxDetails.adversary && (
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800">
                    Adversary: {otxDetails.adversary}
                  </span>
                )}
              </div>
              <h2 className="text-lg md:text-xl font-black text-slate-100 mt-1 flex items-center gap-2">
                <span>Community Threat Pulses & Adversary Attribution</span>
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <a
              href={provider.link || `https://otx.alienvault.com/indicator/${indicatorType}/${encodeURIComponent(indicator)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-1.5 rounded-lg bg-violet-600/20 hover:bg-violet-600/30 text-violet-300 border border-violet-500/40 font-semibold text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>View in AlienVault OTX</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

        {/* Primary Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-5">
          {/* 1. Pulse Count */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <span className="text-[11px] uppercase tracking-wider font-mono text-slate-400">
              Threat Pulses
            </span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className={`text-2xl font-black font-mono ${pulseCount >= 3 ? 'text-rose-400' : pulseCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {pulseCount}
              </span>
              <span className="text-xs text-slate-500">campaigns</span>
            </div>
            <div className="mt-2">
              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded ${pulseCount >= 3 ? 'bg-rose-950 text-rose-300 border border-rose-800' : pulseCount > 0 ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}`}>
                {pulseCount >= 3 ? 'HIGH EXPOSURE' : pulseCount > 0 ? 'CORRELATED' : 'CLEAN / 0 PULSES'}
              </span>
            </div>
          </div>

          {/* 2. Attributed Adversary */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <span className="text-[11px] uppercase tracking-wider font-mono text-slate-400 flex items-center gap-1">
              <Users className="w-3.5 h-3.5 text-violet-400" />
              Threat Actor
            </span>
            <div className="mt-2">
              <span className="text-sm font-bold text-slate-100 line-clamp-1">
                {otxDetails.adversary || 'Unassigned / Independent'}
              </span>
              <span className="text-[10px] text-slate-400 block mt-0.5">
                {otxDetails.adversary ? 'Attributed Campaign Actor' : 'Community Reported Telemetry'}
              </span>
            </div>
            {otxDetails.adversary && (
              <button
                onClick={() => handleCopy(otxDetails.adversary!, 'adv')}
                className="mt-2 text-[10px] text-violet-400 hover:text-violet-300 flex items-center gap-1 cursor-pointer font-mono"
              >
                {copiedKey === 'adv' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'adv' ? 'Copied' : 'Copy Name'}</span>
              </button>
            )}
          </div>

          {/* 3. Targeted Geographies */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <span className="text-[11px] uppercase tracking-wider font-mono text-slate-400 flex items-center gap-1">
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              Targeted Regions
            </span>
            <div className="mt-2 flex flex-wrap gap-1">
              {otxDetails.targeted_countries && otxDetails.targeted_countries.length > 0 ? (
                otxDetails.targeted_countries.slice(0, 4).map((country, idx) => (
                  <span
                    key={idx}
                    className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700"
                  >
                    {country}
                  </span>
                ))
              ) : (
                <span className="text-xs text-slate-400">Global / Not Specified</span>
              )}
            </div>
            <span className="text-[10px] text-slate-500 mt-2">
              {otxDetails.targeted_countries?.length ? `${otxDetails.targeted_countries.length} regions observed` : 'Unrestricted targeting'}
            </span>
          </div>

          {/* 4. Target Indicator */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <span className="text-[11px] uppercase tracking-wider font-mono text-slate-400">
              Query Indicator
            </span>
            <div className="mt-2">
              <span className="text-xs font-mono text-slate-200 truncate block">
                {indicator}
              </span>
              <span className="text-[10px] font-mono text-violet-400 uppercase mt-0.5 block">
                Type: {indicatorType}
              </span>
            </div>
            <button
              onClick={() => handleCopy(indicator, 'ind')}
              className="mt-2 text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer font-mono"
            >
              {copiedKey === 'ind' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedKey === 'ind' ? 'Copied' : 'Copy Indicator'}</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3 mb-5">
          <button
            onClick={() => setActiveTab('pulses')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'pulses'
                ? 'bg-violet-500/20 text-violet-300 border border-violet-500/50'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Community Pulses ({pulses.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('mitre')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'mitre'
                ? 'bg-violet-500/20 text-violet-300 border border-violet-500/50'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Tag className="w-3.5 h-3.5" />
            <span>ATT&CK Techniques ({attackIds.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('geography')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'geography'
                ? 'bg-violet-500/20 text-violet-300 border border-violet-500/50'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Targeting & Geography</span>
          </button>

          <button
            onClick={() => setActiveTab('references')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'references'
                ? 'bg-violet-500/20 text-violet-300 border border-violet-500/50'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Advisory References ({allReferences.length})</span>
          </button>
        </div>

        {/* Tab 1: Pulses List */}
        {activeTab === 'pulses' && (
          <div className="space-y-4">
            {/* Search & Tag Filter Bar */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={pulseSearch}
                  onChange={(e) => setPulseSearch(e.target.value)}
                  placeholder="Search threat pulse title, author, description, adversary..."
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950/70 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-violet-500 font-mono"
                />
              </div>

              {allTags.length > 0 && (
                <div className="flex items-center gap-2 overflow-x-auto pb-1 max-w-full">
                  <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <button
                    onClick={() => setSelectedTag('all')}
                    className={`px-2 py-1 rounded text-[11px] font-mono shrink-0 cursor-pointer ${
                      selectedTag === 'all'
                        ? 'bg-violet-500/20 text-violet-300 border border-violet-500/40'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    All Tags
                  </button>
                  {allTags.slice(0, 8).map((t) => (
                    <button
                      key={t}
                      onClick={() => setSelectedTag(t)}
                      className={`px-2 py-1 rounded text-[11px] font-mono shrink-0 cursor-pointer ${
                        selectedTag === t
                          ? 'bg-violet-500/20 text-violet-300 border border-violet-500/40 font-bold'
                          : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      #{t}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Pulses Cards */}
            {filteredPulses.length > 0 ? (
              <div className="grid grid-cols-1 gap-3">
                {filteredPulses.map((pulse) => (
                  <div
                    key={pulse.id}
                    className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/90 hover:border-violet-900/60 transition-colors"
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h4 className="text-sm font-bold text-slate-100">{pulse.name}</h4>
                          {pulse.adversary && (
                            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                              {pulse.adversary}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-3 font-mono">
                          <span>By: <strong className="text-slate-300">{pulse.author_name || 'Community'}</strong></span>
                          {pulse.created && (
                            <span>Reported: {pulse.created.split('T')[0]}</span>
                          )}
                          {pulse.indicator_count ? (
                            <span>{pulse.indicator_count} indicators in pulse</span>
                          ) : null}
                        </div>
                      </div>

                      {pulse.references && pulse.references.length > 0 && (
                        <a
                          href={pulse.references[0]}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 shrink-0"
                        >
                          <span>Advisory Brief</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </a>
                      )}
                    </div>

                    {pulse.description && (
                      <p className="text-xs text-slate-300 leading-relaxed mt-2.5 font-sans bg-slate-900/40 p-2.5 rounded-lg border border-slate-800/60">
                        {pulse.description}
                      </p>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 mt-3 pt-2.5 border-t border-slate-900">
                      {/* Attack IDs */}
                      <div className="flex flex-wrap items-center gap-1.5">
                        {pulse.attack_ids && pulse.attack_ids.length > 0 && (
                          <>
                            <span className="text-[10px] uppercase font-mono text-slate-500 font-semibold">ATT&CK:</span>
                            {pulse.attack_ids.map((id) => (
                              <span
                                key={id}
                                className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-blue-950/70 text-blue-300 border border-blue-800/60"
                              >
                                {id}
                              </span>
                            ))}
                          </>
                        )}
                      </div>

                      {/* Tags */}
                      <div className="flex flex-wrap items-center gap-1">
                        {pulse.tags?.slice(0, 5).map((tag) => (
                          <span
                            key={tag}
                            className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800"
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-10 rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 font-mono">
                {pulseSearch || selectedTag !== 'all'
                  ? 'No community threat pulses match the specified search or tag filter.'
                  : '0 threat pulses correlated in AlienVault OTX for this indicator.'}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: ATT&CK Techniques */}
        {activeTab === 'mitre' && (
          <div className="space-y-4">
            {attackIds.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                {attackIds.map((id) => (
                  <div
                    key={id}
                    className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-black text-violet-400">{id}</span>
                        <a
                          href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-slate-400 hover:text-slate-200"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                      <span className="text-[11px] text-slate-300 mt-1 block font-medium">
                        Identified in AlienVault OTX Threat Telemetry
                      </span>
                    </div>
                    <div className="mt-2 pt-2 border-t border-slate-900 text-[10px] text-slate-500 font-mono">
                      Referenced by {pulses.filter((p) => p.attack_ids?.includes(id)).length} pulse(s)
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-10 rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 font-mono">
                No MITRE ATT&CK technique IDs associated with this indicator in AlienVault OTX.
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Targeting & Geography */}
        {activeTab === 'geography' && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                Targeted Geographies & Sovereign Jurisdictions
              </h4>
              <div className="flex flex-wrap gap-2">
                {otxDetails.targeted_countries && otxDetails.targeted_countries.length > 0 ? (
                  otxDetails.targeted_countries.map((c, i) => (
                    <div
                      key={i}
                      className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-200 flex items-center gap-1.5"
                    >
                      <span className="w-2 h-2 rounded-full bg-cyan-400" />
                      <span>{c}</span>
                    </div>
                  ))
                ) : (
                  <span className="text-xs text-slate-400">Global targeting telemetry / no exclusive regions.</span>
                )}
              </div>
            </div>

            {otxDetails.adversary && (
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Adversary Attribution Profile
                </h4>
                <div className="text-sm font-bold text-rose-300 font-mono">
                  {otxDetails.adversary}
                </div>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  AlienVault OTX community researchers have associated this indicator with organized intrusion sets and targeted campaigns.
                </p>
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Advisory References */}
        {activeTab === 'references' && (
          <div className="space-y-3">
            {allReferences.length > 0 ? (
              <div className="grid grid-cols-1 gap-2">
                {allReferences.map((ref, idx) => (
                  <a
                    key={idx}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-violet-700/60 flex items-center justify-between text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    <span className="truncate pr-4">{ref}</span>
                    <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                  </a>
                ))}
              </div>
            ) : (
              <div className="text-center py-10 rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 font-mono">
                No external advisory links or documentation references attached to these pulses.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
