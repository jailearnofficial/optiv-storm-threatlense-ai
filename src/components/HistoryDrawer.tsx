import React, { useEffect, useState } from 'react';
import {
  X,
  History,
  Clock,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  UserCheck,
  FileText,
  UploadCloud,
  Search,
  Hash,
  Filter,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';

interface HistoryItem {
  id: string;
  indicator: string;
  defanged: string;
  type: string;
  createdAt: string;
  ruleScore: number;
  verdict?: string;
  analystName?: string;
  actionType?: 'file_submission' | 'indicator_search';
  fileName?: string;
  fileSize?: number;
  hashes?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

interface HistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectLookup: (lookupId: string) => void;
}

function formatRelativeTime(dateString: string): string {
  const diffMs = Date.now() - new Date(dateString).getTime();
  if (isNaN(diffMs) || diffMs < 0) return 'Just now';
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'Just now';
  if (mins === 1) return '1m ago';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours === 1) return '1h ago';
  return `${hours}h ago`;
}

function formatExactTime(dateString: string): string {
  try {
    const d = new Date(dateString);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  } catch {
    return dateString;
  }
}

export const HistoryDrawer: React.FC<HistoryDrawerProps> = ({
  isOpen,
  onClose,
  onSelectLookup
}) => {
  const [history, setHistory] = useState<HistoryItem[]>(() => {
    try {
      const cached = localStorage.getItem('threatlense_history_cache');
      if (cached) {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {}
    return [];
  });
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [retentionNotice, setRetentionNotice] = useState<string>('24-Hour Active Retention Window');

  const fetchHistory = async (retries = 2) => {
    setLoading(true);
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6000);
        const res = await fetch('/api/history?limit=50', { signal: controller.signal });
        clearTimeout(timeoutId);

        if (res.ok) {
          const data = await res.json();
          const items = data.history || [];
          setHistory(items);
          try {
            localStorage.setItem('threatlense_history_cache', JSON.stringify(items));
          } catch {}
          if (data.retention_window_hours) {
            setRetentionNotice(`${data.retention_window_hours}-Hour Active Retention Window`);
          }
          setLoading(false);
          return;
        }
      } catch (err: any) {
        if (attempt < retries) {
          await new Promise((resolve) => setTimeout(resolve, 500 * (attempt + 1)));
          continue;
        }
        console.warn('History drawer using cached local investigations:', err?.message || err);
      }
    }
    setLoading(false);
  };

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const filteredHistory = history.filter((item) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    const matchAnalyst = (item.analystName || '').toLowerCase().includes(term);
    const matchIndicator = (item.indicator || '').toLowerCase().includes(term);
    const matchFile = (item.fileName || '').toLowerCase().includes(term);
    const matchSha = (item.hashes?.sha256 || '').toLowerCase().includes(term);
    const matchMd5 = (item.hashes?.md5 || '').toLowerCase().includes(term);
    const matchVerdict = (item.verdict || '').toLowerCase().includes(term);
    return matchAnalyst || matchIndicator || matchFile || matchSha || matchMd5 || matchVerdict;
  });

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="absolute inset-y-0 right-0 max-w-full flex pl-6 sm:pl-10">
        <div className="w-screen max-w-lg bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col h-full">
          {/* Header */}
          <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-950/80">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <History className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-extrabold text-sm text-slate-100 uppercase tracking-wider flex items-center gap-2">
                    Investigation History
                    <span className="text-[10px] font-mono font-normal px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/80">
                      {history.length}
                    </span>
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    SOC analyst run telemetry & verified file hashes
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => fetchHistory()}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                  title="Refresh history"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={onClose}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                  title="Close history drawer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* 24-Hour Strict Retention Policy Banner */}
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] flex items-center justify-between gap-2 text-slate-400">
              <div className="flex items-center gap-2">
                <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="font-medium text-slate-300">{retentionNotice}</span>
              </div>
              <span className="text-[10px] font-mono text-cyan-400/80 uppercase">
                Auto-Purge &gt;24h Active
              </span>
            </div>

            {/* Search / Filter Input */}
            <div className="relative mt-3">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Filter by analyst name, filename, hash, or verdict..."
                className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500/80 rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 outline-none transition-colors"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs font-mono"
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* List of Historic Runs */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {history.length === 0 ? (
              <div className="h-64 flex flex-col items-center justify-center text-xs text-slate-500 gap-2.5 p-6 text-center">
                <div className="p-3 rounded-full bg-slate-950 border border-slate-800 text-slate-600">
                  <Clock className="w-6 h-6" />
                </div>
                <p className="font-semibold text-slate-300">No recent investigations</p>
                <p className="text-[11px] text-slate-500 max-w-xs">
                  Runs are recorded with the assigned SOC Analyst name, submitted sample file or file hash, and exact run time. Records older than 24 hours are automatically purged.
                </p>
              </div>
            ) : filteredHistory.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center text-xs text-slate-500 gap-1.5 text-center">
                <Filter className="w-5 h-5 text-slate-600 mb-1" />
                <p className="text-slate-300 font-medium">No matches found</p>
                <p className="text-[11px] text-slate-500">
                  No investigations match &quot;{searchTerm}&quot;
                </p>
              </div>
            ) : (
              filteredHistory.map((item) => {
                const isFileSubmit = item.actionType === 'file_submission' || Boolean(item.fileName);
                const sha256 = item.hashes?.sha256 || (item.type === 'hash' && item.indicator.length === 64 ? item.indicator : undefined);
                const md5 = item.hashes?.md5;

                return (
                  <div
                    key={item.id}
                    onClick={() => {
                      onSelectLookup(item.id);
                      onClose();
                    }}
                    className="p-3.5 rounded-xl bg-slate-950/60 hover:bg-slate-800/60 border border-slate-800/90 hover:border-cyan-500/50 transition-all cursor-pointer group flex flex-col gap-2 shadow-sm"
                  >
                    {/* Top Row: Action Type & Verdict */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        {isFileSubmit ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/70 border border-amber-800/80 text-amber-300 text-[10px] font-mono font-bold uppercase">
                            <UploadCloud className="w-3 h-3 text-amber-400" />
                            File Submission
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 text-[10px] font-mono font-bold uppercase">
                            <Search className="w-3 h-3 text-cyan-400" />
                            Indicator Query
                          </span>
                        )}
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          {item.type}
                        </span>
                      </div>

                      {item.verdict ? (
                        <span
                          className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded border tracking-wide ${
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
                      ) : (
                        <span className="text-[9px] font-mono uppercase px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                          Analyzed
                        </span>
                      )}
                    </div>

                    {/* SOC Analyst Attribution */}
                    <div className="flex items-center gap-1.5 text-xs">
                      <UserCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="text-[11px] text-slate-400">SOC Analyst:</span>
                      <span className="text-xs font-semibold text-slate-100 font-mono truncate">
                        {item.analystName || 'SOC Analyst'}
                      </span>
                    </div>

                    {/* File / File Hash Details Block */}
                    <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
                      {item.fileName && (
                        <div className="flex items-center gap-1.5 font-mono text-xs text-slate-200">
                          <FileText className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <span className="font-semibold truncate">{item.fileName}</span>
                          {item.fileSize && (
                            <span className="text-[10px] text-slate-500 shrink-0">
                              ({(item.fileSize / 1024).toFixed(1)} KB)
                            </span>
                          )}
                        </div>
                      )}

                      {/* File Hash Information */}
                      {sha256 ? (
                        <div className="flex flex-col gap-0.5 font-mono text-[11px]">
                          <div className="flex items-center gap-1 text-slate-400">
                            <Hash className="w-3 h-3 text-cyan-400 shrink-0" />
                            <span className="text-[10px] uppercase font-semibold text-slate-400">SHA-256:</span>
                          </div>
                          <span className="text-[10px] text-cyan-300/90 break-all select-all pl-4 bg-slate-950/60 p-1 rounded border border-slate-800/80">
                            {sha256}
                          </span>
                          {md5 && (
                            <div className="flex items-center gap-1 text-[10px] text-slate-500 pl-4 mt-0.5">
                              <span>MD5:</span>
                              <span className="font-mono text-slate-400 select-all">{md5}</span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="font-mono text-xs text-slate-300 truncate">
                          {item.defanged || item.indicator}
                        </div>
                      )}
                    </div>

                    {/* Footer: Exact Run Time & Risk Score */}
                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono pt-0.5">
                      <div className="flex items-center gap-1 text-slate-400" title={item.createdAt}>
                        <Clock className="w-3 h-3 text-slate-500 shrink-0" />
                        <span>{formatExactTime(item.createdAt)}</span>
                        <span className="text-slate-500 text-[10px]">({formatRelativeTime(item.createdAt)})</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-300 font-semibold">
                          Risk: {item.ruleScore}/100
                        </span>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
