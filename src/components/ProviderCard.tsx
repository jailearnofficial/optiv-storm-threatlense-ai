import React from 'react';
import { ExternalLink, CheckCircle, AlertTriangle, XCircle, Clock, ShieldX, ShieldAlert } from 'lucide-react';
import { ProviderResult } from '../types/index.js';

interface ProviderCardProps {
  provider: ProviderResult;
  onViewDetails: (provider: ProviderResult) => void;
  isLoading?: boolean;
}

export const ProviderCard: React.FC<ProviderCardProps> = ({
  provider,
  onViewDetails,
  isLoading
}) => {
  const isMalicious = (provider.score.malicious && provider.score.malicious > 0) ||
    (provider.score.abuse_confidence && provider.score.abuse_confidence >= 50) ||
    (provider.score.threat_score && provider.score.threat_score >= 50);

  const isSuspicious = !isMalicious && (
    (provider.score.suspicious && provider.score.suspicious > 0) ||
    (provider.score.pulse_count && provider.score.pulse_count > 0) ||
    (provider.score.threat_score && provider.score.threat_score > 0)
  );

  const getStatusBadge = () => {
    switch (provider.status) {
      case 'ok':
        if (isMalicious) {
          return (
            <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-rose-950/80 text-rose-400 border border-rose-800/80">
              <ShieldAlert className="w-3 h-3" />
              FLAGGED
            </span>
          );
        }
        if (isSuspicious) {
          return (
            <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800/80">
              <AlertTriangle className="w-3 h-3" />
              SUSPICIOUS
            </span>
          );
        }
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/80">
            <CheckCircle className="w-3 h-3" />
            CLEAN
          </span>
        );
      case 'not_found':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            NOT INDEXED
          </span>
        );
      case 'rate_limited':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800">
            RATE LIMITED
          </span>
        );
      case 'error':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-900">
            ERROR
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono text-slate-500">
            {provider.status}
          </span>
        );
    }
  };

  const borderClass = isMalicious
    ? 'border-rose-900/60 hover:border-rose-500/80 shadow-[0_0_15px_rgba(239,68,68,0.08)]'
    : isSuspicious
    ? 'border-amber-900/60 hover:border-amber-500/80 shadow-[0_0_15px_rgba(245,158,11,0.08)]'
    : 'border-slate-800 hover:border-slate-700 shadow-sm';

  return (
    <div
      onClick={() => onViewDetails(provider)}
      className={`group relative rounded-xl bg-slate-900/80 p-4 border transition-all cursor-pointer flex flex-col justify-between backdrop-blur-sm ${borderClass} ${
        isLoading ? 'animate-pulse' : ''
      }`}
    >
      {/* Top row */}
      <div>
        <div className="flex items-center justify-between gap-2 mb-2.5">
          <div className="flex items-center gap-2">
            <span className="font-bold text-sm text-slate-100 group-hover:text-cyan-300 transition-colors">
              {provider.displayName}
            </span>
          </div>
          <div className="flex items-center gap-2">
            {getStatusBadge()}
          </div>
        </div>

        {/* Headline */}
        <p className="text-xs text-slate-300 font-medium line-clamp-2 min-h-[34px]">
          {provider.headline || 'No telemetry signals recorded'}
        </p>

        {provider.name === 'virustotal' && (
          <div className="mt-2 flex items-center gap-1.5">
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/80">
              ⚡ VT Graph & AV Matrix
            </span>
          </div>
        )}

        {provider.name === 'hybrid_analysis' && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {provider.ha_details ? (
              <>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                  provider.ha_details.threat_score >= 70
                    ? 'bg-rose-950/80 text-rose-300 border-rose-800/80'
                    : provider.ha_details.threat_score >= 35
                    ? 'bg-amber-950/80 text-amber-300 border-amber-800/80'
                    : 'bg-emerald-950/80 text-emerald-300 border-emerald-800/80'
                }`}>
                  🎯 Threat Score: {provider.ha_details.threat_score}/100
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                  🛡️ AV: {provider.ha_details.av_detect_ratio}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/80">
                  ⚔️ {provider.ha_details.mitre_attack.length} MITRE
                </span>
              </>
            ) : (
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/80">
                Falcon Sandbox
              </span>
            )}
          </div>
        )}
      </div>

      {/* Bottom tags & metrics */}
      <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-col gap-2">
        {/* Tags */}
        <div className="flex flex-wrap items-center gap-1 min-h-[22px]">
          {(provider.tags || []).slice(0, 3).map((tag, i) => (
            <span
              key={i}
              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950/80 text-slate-400 border border-slate-800/80"
            >
              #{tag}
            </span>
          ))}
          {(!provider.tags || provider.tags.length === 0) && (
            <span className="text-[10px] text-slate-600 font-mono italic">
              no tags
            </span>
          )}
        </div>

        {/* Latency and External Link */}
        <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3 text-slate-500" />
            {provider.latency_ms}ms
          </span>

          <div className="flex items-center gap-2">
            {provider.link && (
              <a
                href={provider.link}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="text-slate-400 hover:text-cyan-400 p-0.5 transition-colors"
                title="Open directly in provider portal"
              >
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            )}
            <span className="text-[10px] text-cyan-400/80 font-sans group-hover:underline">
              Inspect →
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
