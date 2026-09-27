import React, { useState } from 'react';
import { Download, Copy, Check, ShieldAlert, FileSpreadsheet, Code2 } from 'lucide-react';
import { IOCItem } from '../types/index.js';

interface IocTableProps {
  iocs: IOCItem[];
  analysisId: string;
}

export const IocTable: React.FC<IocTableProps> = ({ iocs, analysisId }) => {
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);

  if (!iocs || iocs.length === 0) {
    return null;
  }

  const handleCopySingle = (val: string, idx: number) => {
    navigator.clipboard.writeText(val);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1500);
  };

  const handleCopyAll = () => {
    const text = iocs.map((ioc) => `${ioc.type}: ${ioc.value}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 1500);
  };

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 md:p-6 backdrop-blur-md">
        {/* Header and export buttons */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              Verified Indicators of Compromise (IOCs) · {iocs.length} Extracted
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified against provider evidence (anti-hallucination filter applied) · Defanged for safe export
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyAll}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              {copiedAll ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedAll ? 'Copied All' : 'Copy All'}</span>
            </button>

            <a
              href={`/api/iocs/${analysisId}?format=csv`}
              download
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 font-medium flex items-center gap-1.5 transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" />
              <span>CSV</span>
            </a>

            <a
              href={`/api/iocs/${analysisId}?format=json`}
              download
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 font-medium flex items-center gap-1.5 transition-colors"
            >
              <Code2 className="w-3.5 h-3.5 text-violet-400" />
              <span>STIX 2.1</span>
            </a>
          </div>
        </div>

        {/* IOC Table */}
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Defanged Value</th>
                <th className="px-4 py-3">Role / Context</th>
                <th className="px-4 py-3">Telemetry Source</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-900/40 font-mono">
              {iocs.map((ioc, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-2.5 uppercase font-bold text-cyan-400">
                    {ioc.type}
                  </td>
                  <td className="px-4 py-2.5 text-rose-300 font-semibold select-all">
                    {ioc.value}
                  </td>
                  <td className="px-4 py-2.5 text-slate-300 font-sans">
                    {ioc.context}
                  </td>
                  <td className="px-4 py-2.5 text-slate-400 text-[11px] font-sans">
                    {ioc.source}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <button
                      onClick={() => handleCopySingle(ioc.value, idx)}
                      className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                      title="Copy defanged value"
                    >
                      {copiedIdx === idx ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
