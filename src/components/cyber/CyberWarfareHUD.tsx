import React, { useState } from 'react';
import {
  Globe,
  Radio,
  Zap,
  ShieldAlert,
  ShieldCheck,
  Maximize2,
  Minimize2,
  Crosshair,
  Volume2,
  VolumeX,
  Layers,
  ChevronDown,
  ChevronUp,
  Cpu,
  Activity,
  Terminal,
  AlertTriangle
} from 'lucide-react';
import { CyberAttackGlobe } from './CyberAttackGlobe.js';
import { CyberRadarSweep } from './CyberRadarSweep.js';
import { CyberKillChain } from './CyberKillChain.js';
import { EvidenceObject, AIAnalysisVerdict, ProviderResult } from '../../types/index.js';

interface CyberWarfareHUDProps {
  evidence?: EvidenceObject | null;
  analysis?: AIAnalysisVerdict | null;
  onSelectProvider?: (provider: ProviderResult) => void;
  defaultExpanded?: boolean;
}

export const CyberWarfareHUD: React.FC<CyberWarfareHUDProps> = ({
  evidence,
  analysis,
  onSelectProvider,
  defaultExpanded = true
}) => {
  const [activeTab, setActiveTab] = useState<'all' | 'globe' | 'radar' | 'killchain'>('all');
  const [isExpanded, setIsExpanded] = useState<boolean>(defaultExpanded);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);

  const numericScore =
    typeof evidence?.rule_score === 'number'
      ? evidence.rule_score
      : (evidence?.rule_score?.value ?? analysis?.risk_score ?? analysis?.confidence ?? 78);

  // Compute DEFCON scale based on ruleScore and verdict
  let defconLevel = 5;
  let defconName = 'DEFCON 5 · PEACETIME NORMAL';
  let defconColor = 'text-emerald-400 bg-emerald-950 border-emerald-800';
  let defconBadge = 'bg-emerald-500';

  if (numericScore >= 85) {
    defconLevel = 1;
    defconName = 'DEFCON 1 · CRITICAL ACTIVE WARFARE';
    defconColor = 'text-rose-400 bg-rose-950 border-rose-700 animate-pulse';
    defconBadge = 'bg-rose-500 animate-ping';
  } else if (numericScore >= 70) {
    defconLevel = 2;
    defconName = 'DEFCON 2 · HIGH SEVERITY ADVERSARY BREACH';
    defconColor = 'text-rose-300 bg-rose-950/80 border-rose-800';
    defconBadge = 'bg-rose-500';
  } else if (numericScore >= 45) {
    defconLevel = 3;
    defconName = 'DEFCON 3 · SUSPICIOUS INTRUSION FLAGGED';
    defconColor = 'text-amber-300 bg-amber-950/80 border-amber-800';
    defconBadge = 'bg-amber-400';
  } else if (numericScore >= 20) {
    defconLevel = 4;
    defconName = 'DEFCON 4 · ELEVATED SURVEILLANCE';
    defconColor = 'text-cyan-300 bg-cyan-950/80 border-cyan-800';
    defconBadge = 'bg-cyan-400';
  }

  return (
    <div
      className={`relative rounded-2xl border transition-all ${
        isFullscreen
          ? 'fixed inset-3 z-50 overflow-y-auto bg-[#060A13] border-cyan-500 shadow-[0_0_80px_rgba(34,211,238,0.25)] p-6'
          : 'border-cyan-500/40 bg-gradient-to-b from-[#090E1A] via-[#060912] to-[#090E1A] p-4 sm:p-5 shadow-[0_0_50px_rgba(34,211,238,0.15)]'
      }`}
    >
      {/* Sci-Fi Corner Reticle Brackets [ + ] */}
      <div className="absolute top-2 left-2 w-3 h-3 border-t-2 border-l-2 border-cyan-400 pointer-events-none" />
      <div className="absolute top-2 right-2 w-3 h-3 border-t-2 border-r-2 border-cyan-400 pointer-events-none" />
      <div className="absolute bottom-2 left-2 w-3 h-3 border-b-2 border-l-2 border-cyan-400 pointer-events-none" />
      <div className="absolute bottom-2 right-2 w-3 h-3 border-b-2 border-r-2 border-cyan-400 pointer-events-none" />

      {/* Main HUD Banner Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/90 pb-4 mb-4">
        {/* Brand & DEFCON Status */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-cyan-950 to-slate-900 border border-cyan-400/50 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(34,211,238,0.3)]">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold tracking-wider uppercase text-slate-100 flex items-center gap-2">
                <span>Cyber Threat Intelligence Warfare Center</span>
              </h2>
              <span
                className={`font-mono text-[10px] px-2.5 py-0.5 rounded border font-bold flex items-center gap-1.5 ${defconColor}`}
              >
                <span className={`w-2 h-2 rounded-full ${defconBadge}`} />
                {defconName}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Interactive 3D attack trajectory globe, 360° radar sweep HUD, and Lockheed Martin 7-stage kill-chain.
            </p>
          </div>
        </div>

        {/* Tactical View Controls & Tabs */}
        <div className="flex items-center gap-2">
          {/* View Tab Selector */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
            <button
              onClick={() => setActiveTab('all')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'all'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Full Warfare HUD</span>
            </button>

            <button
              onClick={() => setActiveTab('globe')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'globe'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Attack Globe</span>
            </button>

            <button
              onClick={() => setActiveTab('radar')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'radar'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>360° Radar</span>
            </button>

            <button
              onClick={() => setActiveTab('killchain')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'killchain'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Kill-Chain</span>
            </button>
          </div>

          {/* Fullscreen Toggle */}
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors cursor-pointer"
            title={isFullscreen ? 'Exit Fullscreen' : 'Enter Fullscreen Warfare Briefing'}
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4 text-cyan-400" /> : <Maximize2 className="w-4 h-4 text-cyan-400" />}
          </button>

          {/* Collapse/Expand Toggle */}
          {!isFullscreen && (
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors cursor-pointer"
              title={isExpanded ? 'Collapse Tactical HUD' : 'Expand Tactical HUD'}
            >
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      {isExpanded && (
        <div className="space-y-5 animate-in fade-in duration-200">
          {/* TAB: ALL (Stacked Visuals) */}
          {activeTab === 'all' && (
            <div className="space-y-5">
              {/* 1. Global Holographic Attack Globe */}
              <CyberAttackGlobe evidence={evidence} analysis={analysis} />

              {/* 2. Side-by-side or Stacked: 360° Radar & Kill Chain */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
                <div className="lg:col-span-6">
                  <CyberRadarSweep
                    providers={evidence?.providers}
                    ruleScore={numericScore}
                    indicator={evidence?.indicator.normalized}
                    indicatorType={evidence?.indicator.type}
                    onSelectProvider={onSelectProvider}
                  />
                </div>

                <div className="lg:col-span-6">
                  <CyberKillChain analysis={analysis} evidence={evidence} />
                </div>
              </div>
            </div>
          )}

          {/* TAB: GLOBE ONLY */}
          {activeTab === 'globe' && (
            <CyberAttackGlobe evidence={evidence} analysis={analysis} height={520} />
          )}

          {/* TAB: RADAR ONLY */}
          {activeTab === 'radar' && (
            <CyberRadarSweep
              providers={evidence?.providers}
              ruleScore={numericScore}
              indicator={evidence?.indicator.normalized}
              indicatorType={evidence?.indicator.type}
              onSelectProvider={onSelectProvider}
            />
          )}

          {/* TAB: KILL-CHAIN ONLY */}
          {activeTab === 'killchain' && (
            <CyberKillChain analysis={analysis} evidence={evidence} />
          )}
        </div>
      )}
    </div>
  );
};
