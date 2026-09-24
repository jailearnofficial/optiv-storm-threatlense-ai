import React, { useEffect, useState } from 'react';
import { X, History, Clock, ArrowRight, ShieldAlert, ShieldCheck, RefreshCw } from 'lucide-react';

interface HistoryItem {
  id: string;
  indicator: string;
  defanged: string;
  type: string;
  createdAt: string;
  ruleScore: number;
  verdict?: string;
}

interface HistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectLookup: (lookupId: string) => void;
}

export const HistoryDrawer: React.FC<HistoryDrawerProps> = ({
  isOpen,
  onClose,
  onSelectLookup
}) => {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/history?limit=25');
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      }
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="absolute inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-md bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col">
          {/* Header */}
          <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-cyan-400" />
              <h3 className="font-extrabold text-sm text-slate-100 uppercase tracking-wider">
                Investigated Dossiers
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={fetchHistory}
                className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
                title="Refresh history"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              </button>
              <button
                onClick={onClose}
                className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* List */}
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {history.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center text-xs text-slate-500 gap-2">
                <Clock className="w-6 h-6 text-slate-600" />
                <span>No investigation history recorded yet</span>
              </div>
            ) : (
              history.map((item) => (
                <div
                  key={item.id}
                  onClick={() => {
                    onSelectLookup(item.id);
                    onClose();
                  }}
                  className="p-3 rounded-lg bg-slate-950/50 hover:bg-slate-800/60 border border-slate-800/80 hover:border-slate-700 transition-all cursor-pointer group flex flex-col gap-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-cyan-400 uppercase font-semibold">
                      {item.type}
                    </span>
                    {item.verdict && (
                      <span
                        className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${
                          item.verdict === 'Malicious'
                            ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                            : item.verdict === 'Suspicious'
                            ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                            : item.verdict === 'Benign'
                            ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {item.verdict}
                      </span>
                    )}
                  </div>

                  <p className="font-mono text-xs text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                    {item.defanged}
                  </p>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono mt-1">
                    <span>{new Date(item.createdAt).toLocaleTimeString()}</span>
                    <span>Risk: {item.ruleScore}/100</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
