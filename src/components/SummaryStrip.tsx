import React from 'react';
import { Sparkles, Shield, Cpu, ArrowRight, RefreshCw, BarChart2 } from 'lucide-react';
import { RuleScoreResult } from '../types/index.js';

interface SummaryStripProps {
  ruleScore: RuleScoreResult;
  onAnalyzeAI: () => void;
  isAnalyzing: boolean;
  hasAnalysis: boolean;
}

export const SummaryStrip: React.FC<SummaryStripProps> = ({
  ruleScore,
  onAnalyzeAI,
  isAnalyzing,
  hasAnalysis
}) => {
  const getBandStyles = () => {
    switch (ruleScore.band) {
      case 'high':
        return {
          bg: 'bg-rose-950/60 border-rose-800 text-rose-400',
          label: 'HIGH RISK',
          accent: 'text-rose-400'
        };
      case 'medium':
        return {
          bg: 'bg-amber-950/60 border-amber-800 text-amber-400',
          label: 'MEDIUM RISK',
          accent: 'text-amber-400'
        };
      case 'low':
        return {
          bg: 'bg-blue-950/60 border-blue-800 text-blue-400',
          label: 'LOW RISK',
          accent: 'text-blue-400'
        };
      default:
        return {
          bg: 'bg-emerald-950/60 border-emerald-800 text-emerald-400',
          label: 'CLEAN',
          accent: 'text-emerald-400'
        };
    }
  };

  const band = getBandStyles();

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-xl bg-slate-900/90 border border-slate-700/80 p-4 md:p-5 backdrop-blur-md shadow-xl flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Left: Deterministic Rule-Based Risk Score */}
        <div className="flex items-center gap-4 w-full md:w-auto">
          {/* Circular Score Gauge */}
          <div className="relative flex items-center justify-center w-16 h-16 rounded-full bg-slate-950 border border-slate-800 shrink-0">
            <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-slate-800"
                strokeWidth="3.5"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className={
                  ruleScore.band === 'high'
                    ? 'text-rose-500'
                    : ruleScore.band === 'medium'
                    ? 'text-amber-500'
                    : ruleScore.band === 'low'
                    ? 'text-blue-500'
                    : 'text-emerald-500'
                }
                strokeDasharray={`${ruleScore.value}, 100`}
                strokeWidth="3.5"
                strokeLinecap="round"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <span className="absolute font-mono font-extrabold text-lg text-slate-100">
              {ruleScore.value}
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Rule-Based Risk Score
              </span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${band.bg}`}>
                {band.label}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Coverage: <span className="font-mono text-cyan-400 font-semibold">{ruleScore.coverage}</span> active feeds evaluated
            </p>
          </div>
        </div>

        {/* Right: Analyze AI Button */}
        <div className="flex items-center gap-3 w-full md:w-auto justify-end">
          <button
            onClick={onAnalyzeAI}
            disabled={isAnalyzing || ruleScore.activeProviders === 0}
            className="w-full md:w-auto px-6 py-3 rounded-lg bg-gradient-to-r from-violet-600 via-purple-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500 text-white font-bold text-sm tracking-wide transition-all shadow-[0_0_20px_rgba(139,92,246,0.35)] disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2.5 cursor-pointer border border-violet-400/30"
          >
            {isAnalyzing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-violet-200" />
                <span>Synthesizing with ThreatLense AI...</span>
              </>
            ) : hasAnalysis ? (
              <>
                <Sparkles className="w-4 h-4 text-violet-300 animate-pulse" />
                <span>Re-Analyze with ThreatLense AI</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-violet-300 animate-pulse" />
                <span>Synthesize with ThreatLense AI</span>
                <ArrowRight className="w-4 h-4 text-violet-300" />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
