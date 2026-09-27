import React, { useState } from 'react';
import {
  ExternalLink,
  Shield,
  Layers,
  ChevronRight,
  Info,
  X,
  Target,
  FileSearch,
  CheckCircle2
} from 'lucide-react';
import { MitreAttackRecord } from '../types/index.js';

interface MitreAttackMatrixProps {
  records: MitreAttackRecord[];
}

export const MitreAttackMatrix: React.FC<MitreAttackMatrixProps> = ({ records }) => {
  const [selectedRecord, setSelectedRecord] = useState<MitreAttackRecord | null>(null);

  if (!records || records.length === 0) {
    return null;
  }

  // Group records by tactic
  const groupedByTactic: Record<string, MitreAttackRecord[]> = {};
  for (const r of records) {
    const key = r.tactic || 'General Attack';
    if (!groupedByTactic[key]) {
      groupedByTactic[key] = [];
    }
    groupedByTactic[key].push(r);
  }

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 md:p-6 backdrop-blur-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Target className="w-3.5 h-3.5 text-cyan-400" />
              MITRE ATT&CK Enterprise Matrix Mapping ({records.length} Techniques Identified)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Mapped in kill-chain sequence · Click any technique to inspect detection hunt logic and mitigations
            </p>
          </div>
          <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-1 rounded border border-cyan-800/60 self-start">
            Enterprise ATT&CK v15
          </span>
        </div>

        {/* Matrix Horizontal Scroll Container */}
        <div className="overflow-x-auto pb-3">
          <div className="flex items-start gap-3 min-w-max">
            {Object.entries(groupedByTactic).map(([tacticName, items]) => (
              <div
                key={tacticName}
                className="w-56 rounded-xl bg-slate-950/70 border border-slate-800/90 overflow-hidden flex flex-col shrink-0"
              >
                {/* Tactic Column Header */}
                <div className="px-3 py-2.5 bg-slate-900 border-b border-slate-800">
                  <span className="text-[10px] font-mono text-cyan-400 font-semibold uppercase block truncate">
                    {items[0]?.tactic_id || 'TACTIC'}
                  </span>
                  <h4 className="text-xs font-bold text-slate-200 truncate">
                    {tacticName}
                  </h4>
                </div>

                {/* Technique Cards in this Tactic */}
                <div className="p-2 space-y-2">
                  {items.map((record, idx) => {
                    const isHigh = record.confidence === 'high';
                    const isProvider = record.source === 'provider';

                    return (
                      <div
                        key={`${record.tactic_id || tacticName}-${record.technique_id}-${idx}`}
                        onClick={() => setSelectedRecord(record)}
                        className={`p-2.5 rounded-lg border text-left cursor-pointer transition-all hover:scale-[1.02] flex flex-col justify-between gap-1.5 ${
                          isHigh
                            ? 'bg-violet-950/40 border-violet-700/60 hover:border-violet-400 shadow-[0_0_10px_rgba(139,92,246,0.1)]'
                            : 'bg-slate-900/60 border-slate-800 hover:border-slate-600'
                        }`}
                      >
                        <div>
                          <div className="flex items-center justify-between gap-1 mb-1">
                            <span className="text-[10px] font-mono font-bold text-violet-300">
                              {record.technique_id}
                            </span>
                            <span
                              className={`text-[9px] font-mono uppercase px-1.5 py-0.2 rounded ${
                                isProvider
                                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                                  : 'bg-slate-800 text-slate-400'
                              }`}
                            >
                              {record.source}
                            </span>
                          </div>

                          <p className="text-xs font-semibold text-slate-200 line-clamp-2">
                            {record.technique}
                          </p>
                        </div>

                        <p className="text-[10px] text-slate-400 line-clamp-2 font-mono">
                          {record.evidence}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Technique Detail Modal Drawer */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="relative w-full max-w-2xl rounded-xl bg-slate-900 border border-slate-700 shadow-2xl p-6 overflow-hidden max-h-[85vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-violet-950 text-violet-300 border border-violet-800 font-bold">
                    {selectedRecord.technique_id}
                  </span>
                  <span className="text-xs font-mono text-cyan-400 uppercase">
                    {selectedRecord.tactic} ({selectedRecord.tactic_id})
                  </span>
                </div>
                <h3 className="text-lg font-bold text-slate-100">
                  {selectedRecord.technique}
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <a
                  href={selectedRecord.reference}
                  target="_blank"
                  rel="noreferrer"
                  className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition-colors"
                  title="Open in official MITRE ATT&CK Matrix"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
                <button
                  onClick={() => setSelectedRecord(null)}
                  className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Content Details */}
            <div className="space-y-4 mt-4 text-xs">
              {/* Telemetry Evidence Quote */}
              <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                  Telemetry Evidence Correlation
                </span>
                <p className="text-slate-200 font-mono text-xs leading-relaxed">
                  {selectedRecord.evidence}
                </p>
                <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                  <span>Source: <strong className="text-cyan-400 uppercase">{selectedRecord.source}</strong></span>
                  <span>Confidence: <strong className="text-violet-400 uppercase">{selectedRecord.confidence}</strong></span>
                </div>
              </div>

              {/* SOC Detection & Hunting Guidance */}
              <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1 flex items-center gap-1.5">
                  <FileSearch className="w-3 h-3 text-cyan-400" />
                  SOC Detection & Threat Hunting Strategy
                </span>
                <p className="text-slate-300 leading-relaxed">
                  {selectedRecord.detection}
                </p>
              </div>

              {/* Recommended Mitigations */}
              {selectedRecord.mitigation && selectedRecord.mitigation.length > 0 && (
                <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    Recommended MITRE Mitigations
                  </span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {selectedRecord.mitigation.map((m, idx) => (
                      <span
                        key={idx}
                        className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
