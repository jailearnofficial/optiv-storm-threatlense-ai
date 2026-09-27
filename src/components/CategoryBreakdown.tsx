import React, { useState } from 'react';
import { Hash, Globe, Server, Link, Gauge, Layers, Cpu, Radio } from 'lucide-react';
import { AIAnalysisVerdict } from '../types/index.js';

interface CategoryBreakdownProps {
  analysis: AIAnalysisVerdict;
}

export const CategoryBreakdown: React.FC<CategoryBreakdownProps> = ({ analysis }) => {
  const breakdown = analysis.category_breakdown || {};
  const tabs = [
    { id: 'scoring', label: 'Scoring Engine', icon: Gauge, content: breakdown.scoring },
    { id: 'hybrid_analysis', label: 'Hybrid Analysis (Falcon)', icon: Cpu, content: breakdown.hybrid_analysis },
    { id: 'alienvault_otx', label: 'AlienVault OTX Pulses', icon: Radio, content: breakdown.alienvault_otx },
    { id: 'domain', label: 'Domain Intel', icon: Globe, content: breakdown.domain },
    { id: 'ip', label: 'IP Infrastructure', icon: Server, content: breakdown.ip },
    { id: 'url', label: 'URL / Web', icon: Link, content: breakdown.url },
    { id: 'file_hash', label: 'File Hash', icon: Hash, content: breakdown.file_hash },
    { id: 'other', label: 'Context / Host', icon: Layers, content: breakdown.other },
  ].filter((t) => Boolean(t.content) || t.id === 'scoring');

  const [activeTab, setActiveTab] = useState(tabs[0]?.id || 'scoring');
  const currentTab = tabs.find((t) => t.id === activeTab) || tabs[0];

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 backdrop-blur-md">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          Multi-Category Threat Breakdown
        </h3>

        {/* Tab Strip */}
        <div className="flex flex-wrap gap-1.5 border-b border-slate-800 pb-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = tab.id === activeTab;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Content */}
        <div className="mt-4 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-200 leading-relaxed font-mono min-h-[70px]">
          {currentTab?.content || 'No specific category intelligence reported for this indicator.'}
        </div>
      </div>
    </div>
  );
};
