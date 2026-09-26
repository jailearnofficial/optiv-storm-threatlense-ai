import React, { useState, useEffect } from 'react';
import {
  Flame,
  Radio,
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  RefreshCw,
  Search,
  Copy,
  Check,
  ChevronRight,
  Crosshair,
  Globe,
  Tag,
  Clock,
  Layers,
  Sparkles,
  Server
} from 'lucide-react';
import { TrendingThreat, IndicatorType } from '../types/index.js';

interface ThreatCondition {
  level: string;
  defcon: string;
  advisory: string;
  last_updated: string;
  active_global_campaigns: number;
  feed_sources: string[];
}

interface TrendingThreatIntelProps {
  onSelectIndicator: (indicator: string, type: IndicatorType | 'auto') => void;
  isLoading?: boolean;
}

export const TrendingThreatIntel: React.FC<TrendingThreatIntelProps> = ({
  onSelectIndicator,
  isLoading: parentLoading
}) => {
  const [threats, setThreats] = useState<TrendingThreat[]>([]);
  const [threatCondition, setThreatCondition] = useState<ThreatCondition | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const fetchTrendingThreats = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/trending-threats');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch emerging threats`);
      const data = await res.json();
      setThreats(data.threats || []);
      setThreatCondition(data.threat_condition || null);
      setLastRefreshed(new Date());
    } catch (err: any) {
      console.error('Error fetching trending threat intel:', err);
      setError(err.message || 'Unable to load emerging threat feed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrendingThreats();
    // Auto-refresh feed every 60 seconds
    const timer = setInterval(fetchTrendingThreats, 60000);
    return () => clearInterval(timer);
  }, []);

  const handleCopyIoc = (e: React.MouseEvent, ioc: string, id: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(ioc);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <section className="relative z-10 max-w-5xl mx-auto px-4 mt-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-2xl">
        {/* Header Ribbon: Global Threat Condition */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
              <Flame className="w-4 h-4 animate-pulse text-rose-400" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500" />
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 flex items-center gap-2">
                  <span>Trending Threat Intelligence</span>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-700/60 uppercase">
                    Top 5 Global Threats
                  </span>
                </h2>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time active adversary campaigns, edge appliance zero-days & emerging weaponized IOCs
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 self-start sm:self-center">
            {threatCondition && (
              <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-md bg-amber-950/40 border border-amber-800/40 text-[11px] font-mono text-amber-300">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                <span className="font-semibold">{threatCondition.defcon}</span>
                <span className="text-amber-400/60">·</span>
                <span className="text-slate-300">{threatCondition.level}</span>
              </div>
            )}

            <button
              onClick={fetchTrendingThreats}
              disabled={loading || parentLoading}
              title="Refresh Global Threat Feed"
              className="px-2.5 py-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-750 border border-slate-700 hover:border-slate-600 text-slate-300 hover:text-white text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
              <span className="text-[11px]">Sync Feed</span>
            </button>
          </div>
        </div>

        {/* Global Advisory Banner */}
        {threatCondition && (
          <div className="mt-3.5 mb-4 p-2.5 rounded-xl bg-gradient-to-r from-rose-950/30 via-slate-900/50 to-amber-950/20 border border-rose-900/40 flex items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 min-w-0">
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
              <div className="truncate">
                <span className="font-mono font-bold text-rose-400 uppercase text-[11px] mr-2">
                  CTI Global Advisory:
                </span>
                <span className="text-slate-200 font-medium">{threatCondition.advisory}</span>
              </div>
            </div>
            <div className="shrink-0 text-[10px] font-mono text-slate-400 hidden sm:block">
              Updated: {lastRefreshed.toLocaleTimeString()}
            </div>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Loading Skeletons */}
        {loading && threats.length === 0 && (
          <div className="grid grid-cols-1 gap-3 mt-3">
            {[1, 2, 3].map((n) => (
              <div
                key={n}
                className="h-28 rounded-xl bg-slate-950/50 border border-slate-800/60 animate-pulse p-4 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <div className="h-4 bg-slate-800 rounded w-1/3" />
                  <div className="h-4 bg-slate-800 rounded w-16" />
                </div>
                <div className="h-3 bg-slate-800/60 rounded w-3/4" />
                <div className="h-3 bg-slate-800/40 rounded w-1/2" />
              </div>
            ))}
          </div>
        )}

        {/* Top 5 Emerging Threats List */}
        <div className="grid grid-cols-1 gap-3.5 mt-3">
          {threats.map((threat, index) => {
            const isSelected = selectedThreatId === threat.id;
            const isCritical = threat.severity === 'CRITICAL';

            return (
              <div
                key={threat.id}
                className={`group rounded-xl border transition-all duration-200 ${
                  isCritical
                    ? 'border-rose-900/40 hover:border-rose-700/70 bg-gradient-to-br from-slate-950/90 via-slate-900/60 to-rose-950/15'
                    : 'border-slate-800 hover:border-slate-700 bg-gradient-to-br from-slate-950/90 via-slate-900/60 to-amber-950/10'
                } p-4 shadow-sm hover:shadow-lg`}
              >
                {/* Top Row: Threat Index, Title, Severity Badge, Timestamp */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2.5 mb-2">
                  <div className="flex items-start gap-2.5 min-w-0">
                    <span className="font-mono text-xs font-bold px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 shrink-0">
                      0{index + 1}
                    </span>
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition-colors">
                          {threat.title}
                        </h3>
                        <span
                          className={`text-[9.5px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                            isCritical
                              ? 'bg-rose-950/80 text-rose-300 border-rose-700/60 shadow-[0_0_8px_rgba(244,63,94,0.2)]'
                              : 'bg-amber-950/80 text-amber-300 border-amber-700/60'
                          }`}
                        >
                          {threat.severity}
                        </span>
                      </div>

                      {/* Threat Actor & Trend */}
                      <div className="flex flex-wrap items-center gap-2 mt-1 text-xs">
                        <span className="inline-flex items-center gap-1 font-mono text-[11px] text-cyan-400 font-semibold bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
                          <Crosshair className="w-3 h-3 text-cyan-400" />
                          <span>{threat.threat_actor}</span>
                        </span>
                        <span className="text-slate-500">•</span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          {threat.trend}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-start sm:self-center shrink-0">
                    <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      <Clock className="w-3 h-3 text-slate-400" />
                      <span>{threat.timestamp}</span>
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 hidden md:inline-block">
                      {threat.source}
                    </span>
                  </div>
                </div>

                {/* Summary Description */}
                <p className="text-xs text-slate-300 leading-relaxed mt-2 mb-3">
                  {threat.summary}
                </p>

                {/* Metadata Tags: CVEs, Sectors, Region */}
                <div className="flex flex-wrap items-center gap-1.5 mb-3">
                  {threat.cves.map((cve) => (
                    <span
                      key={cve}
                      className="px-2 py-0.5 rounded bg-rose-950/40 border border-rose-800/50 text-[10.5px] font-mono text-rose-300 font-semibold"
                    >
                      {cve}
                    </span>
                  ))}
                  {threat.sectors.slice(0, 3).map((sector) => (
                    <span
                      key={sector}
                      className="px-2 py-0.5 rounded bg-slate-800/70 border border-slate-700/60 text-[10.5px] font-sans text-slate-300"
                    >
                      {sector}
                    </span>
                  ))}
                  <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10.5px] font-mono text-slate-400 flex items-center gap-1">
                    <Globe className="w-3 h-3 text-slate-400" />
                    <span>{threat.region}</span>
                  </span>
                </div>

                {/* MITRE ATT&CK Techniques Chips */}
                <div className="flex flex-wrap items-center gap-1.5 mb-3.5">
                  <span className="text-[10px] font-mono uppercase text-slate-400 mr-1 flex items-center gap-1">
                    <Layers className="w-3 h-3 text-cyan-400" />
                    <span>MITRE:</span>
                  </span>
                  {threat.mitre_techniques.map((tech) => (
                    <span
                      key={tech.id}
                      title={tech.name}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900/80 border border-cyan-900/40 text-cyan-300 hover:border-cyan-600 transition-colors"
                    >
                      <strong className="text-cyan-400">{tech.id}</strong> {tech.name}
                    </span>
                  ))}
                </div>

                {/* Actionable IOC Bar with Pivot Triage Button */}
                <div className="pt-3 border-t border-slate-800/70 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 bg-slate-950/60 -mx-4 -mb-4 p-3 rounded-b-xl">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800/60 text-cyan-300 shrink-0">
                      {threat.sample_indicator.type}
                    </span>
                    <div className="min-w-0 flex items-center gap-2">
                      <code className="text-xs font-mono font-bold text-slate-200 truncate select-all">
                        {threat.sample_indicator.value}
                      </code>
                      <button
                        type="button"
                        onClick={(e) => handleCopyIoc(e, threat.sample_indicator.value, threat.id)}
                        className="text-slate-400 hover:text-slate-200 transition-colors p-1 rounded hover:bg-slate-800 cursor-pointer shrink-0"
                        title="Copy Indicator"
                      >
                        {copiedId === threat.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Immediate Pivot / Investigation CTA */}
                  <button
                    type="button"
                    onClick={() =>
                      onSelectIndicator(threat.sample_indicator.value, threat.sample_indicator.type)
                    }
                    className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-bold text-xs font-mono flex items-center justify-center gap-1.5 transition-all shadow-[0_0_12px_rgba(34,211,238,0.25)] hover:shadow-[0_0_16px_rgba(34,211,238,0.4)] cursor-pointer shrink-0"
                  >
                    <Search className="w-3.5 h-3.5 text-slate-950" />
                    <span>Pivot & Triage IOC</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Footer Guidance Note */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
          <div className="flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Feeds Synced: CISA KEV · Microsoft Threat Intel · Europol EC3 · AlienVault OTX · URLhaus</span>
          </div>
          <span className="hidden sm:inline-block">24-Hour Active Threat Horizon</span>
        </div>
      </div>
    </section>
  );
};
