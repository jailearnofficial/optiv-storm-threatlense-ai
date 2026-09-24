import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Cpu,
  Target,
  FileText
} from 'lucide-react';
import { AIAnalysisVerdict } from '../types/index.js';

interface VerdictBannerProps {
  analysis: AIAnalysisVerdict;
}

export const VerdictBanner: React.FC<VerdictBannerProps> = ({ analysis }) => {
  const [showTechDetails, setShowTechDetails] = useState(false);

  const getVerdictTheme = () => {
    switch (analysis.verdict) {
      case 'Malicious':
        return {
          badgeBg: 'bg-rose-950/80 text-rose-300 border-rose-600',
          bannerBg: 'from-rose-950/40 to-slate-900/90 border-rose-800/80',
          glow: 'shadow-[0_0_30px_rgba(239,68,68,0.2)]',
          icon: ShieldAlert,
          iconColor: 'text-rose-400'
        };
      case 'Suspicious':
        return {
          badgeBg: 'bg-amber-950/80 text-amber-300 border-amber-600',
          bannerBg: 'from-amber-950/40 to-slate-900/90 border-amber-800/80',
          glow: 'shadow-[0_0_30px_rgba(245,158,11,0.2)]',
          icon: AlertTriangle,
          iconColor: 'text-amber-400'
        };
      case 'Benign':
        return {
          badgeBg: 'bg-emerald-950/80 text-emerald-300 border-emerald-600',
          bannerBg: 'from-emerald-950/40 to-slate-900/90 border-emerald-800/80',
          glow: 'shadow-[0_0_30px_rgba(16,185,129,0.2)]',
          icon: ShieldCheck,
          iconColor: 'text-emerald-400'
        };
      case 'False Positive':
        return {
          badgeBg: 'bg-blue-950/80 text-blue-300 border-blue-600',
          bannerBg: 'from-blue-950/40 to-slate-900/90 border-blue-800/80',
          glow: 'shadow-[0_0_30px_rgba(59,130,246,0.2)]',
          icon: ShieldCheck,
          iconColor: 'text-blue-400'
        };
      default:
        return {
          badgeBg: 'bg-slate-800 text-slate-300 border-slate-600',
          bannerBg: 'from-slate-900 to-slate-900/90 border-slate-700',
          glow: 'shadow-none',
          icon: HelpCircle,
          iconColor: 'text-slate-400'
        };
    }
  };

  const theme = getVerdictTheme();
  const Icon = theme.icon;

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div
        className={`rounded-2xl bg-gradient-to-br ${theme.bannerBg} border p-6 md:p-8 backdrop-blur-xl transition-all ${theme.glow}`}
      >
        {/* Top Header */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 shadow-inner">
              <Icon className={`w-8 h-8 ${theme.iconColor}`} />
            </div>

            <div>
              <div className="flex items-center gap-3">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  AI Triage Verdict
                </span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-violet-950/60 text-violet-300 border border-violet-800/60 flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-violet-400" />
                  {analysis.model}
                </span>

                {analysis.analyst_name && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/70 text-cyan-300 border border-cyan-700/60">
                    SOC analyst name: {analysis.analyst_name}
                  </span>
                )}
              </div>

              <div className="flex items-center gap-3 mt-1">
                <h2 className="text-2xl md:text-3xl font-black text-slate-100 uppercase tracking-tight">
                  {analysis.verdict}
                </h2>

                {analysis.malware_family && (
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-800">
                    {analysis.malware_family}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Confidence and Risk Badges */}
          <div className="flex items-center gap-4">
            <div className="text-right">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">
                Analyst Confidence
              </span>
              <span className="text-xl font-mono font-extrabold text-cyan-400">
                {Math.round(analysis.confidence * 100)}%
              </span>
            </div>

            <div className="h-8 w-px bg-slate-800" />

            <div className="text-right">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">
                Aggregated Risk
              </span>
              <span className="text-xl font-mono font-extrabold text-slate-100">
                {analysis.risk_score}
                <span className="text-xs text-slate-500 font-normal">/100</span>
              </span>
            </div>
          </div>
        </div>

        {/* Threat Categories Pills */}
        {analysis.threat_categories.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 pt-4">
            <span className="text-xs text-slate-400 font-medium">Categories:</span>
            {analysis.threat_categories.map((cat, i) => (
              <span
                key={i}
                className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900/90 text-slate-300 border border-slate-700"
              >
                {cat}
              </span>
            ))}
          </div>
        )}

        {/* Executive Summary */}
        <div className="mt-5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            Executive Summary for SOC Lead
          </h3>
          <p className="text-sm md:text-base text-slate-200 leading-relaxed bg-slate-950/40 p-4 rounded-xl border border-slate-800/80 font-normal">
            {analysis.executive_summary}
          </p>
        </div>

        {/* Recommended Actions */}
        {analysis.recommended_actions.length > 0 && (
          <div className="mt-5">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 flex items-center gap-1.5">
              <Target className="w-3.5 h-3.5 text-rose-400" />
              Immediate Incident Response Actions
            </h3>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-200">
              {analysis.recommended_actions.map((action, i) => (
                <li
                  key={i}
                  className="flex items-start gap-2 p-2.5 rounded-lg bg-slate-950/50 border border-slate-800"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0 mt-1.5" />
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Technical Summary Accordion */}
        <div className="mt-5 pt-4 border-t border-slate-800/80">
          <button
            onClick={() => setShowTechDetails(!showTechDetails)}
            className="flex items-center justify-between w-full text-xs text-slate-400 hover:text-slate-200 font-medium py-1 transition-colors cursor-pointer"
          >
            <span className="flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5 text-violet-400" />
              Detailed Analyst Technical Breakdown & Engine Agreement
            </span>
            {showTechDetails ? (
              <ChevronUp className="w-4 h-4 text-slate-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-400" />
            )}
          </button>

          {showTechDetails && (
            <div className="mt-3 p-4 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-300 leading-relaxed font-mono space-y-3 animate-in fade-in duration-150">
              <p>{analysis.technical_summary}</p>

              {/* Provider Agreement Table */}
              {analysis.provider_agreement && analysis.provider_agreement.length > 0 && (
                <div className="pt-2 border-t border-slate-800">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-2 font-sans">
                    Provider Stance Breakdown:
                  </span>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {analysis.provider_agreement.map((item, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between"
                      >
                        <span className="text-slate-300 truncate font-sans">{item.provider}</span>
                        <span
                          className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                            item.stance === 'malicious'
                              ? 'bg-rose-950 text-rose-400'
                              : item.stance === 'suspicious'
                              ? 'bg-amber-950 text-amber-400'
                              : item.stance === 'clean'
                              ? 'bg-emerald-950 text-emerald-400'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {item.stance}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
