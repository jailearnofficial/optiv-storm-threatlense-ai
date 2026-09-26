import React, { useState } from 'react';
import {
  History,
  Clock,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  Hash,
  Globe,
  FileText,
  User,
  Copy,
  Check,
  Filter,
  ExternalLink,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { HistoryItemDTO } from '../types/index.js';

interface InvestigationHistoryFeedProps {
  historyList: HistoryItemDTO[];
  loading: boolean;
  onRefresh: () => void;
  onSelectLookup: (lookupId: string) => void;
  onViewDossier?: (lookupId: string) => void;
  currentLookupId?: string | null;
  collapsedDefault?: boolean;
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
      minute: '2-digit'
    });
  } catch {
    return dateString;
  }
}

export const InvestigationHistoryFeed: React.FC<InvestigationHistoryFeedProps> = ({
  historyList,
  loading,
  onRefresh,
  onSelectLookup,
  onViewDossier,
  currentLookupId,
  collapsedDefault = false
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'malicious' | 'suspicious' | 'clean' | 'hash'>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isCollapsed, setIsCollapsed] = useState<boolean>(collapsedDefault);

  const handleCopy = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filtered = historyList.filter((item) => {
    // Type filter
    if (filterType === 'malicious' && item.verdict?.toLowerCase() !== 'malicious') return false;
    if (filterType === 'suspicious' && item.verdict?.toLowerCase() !== 'suspicious') return false;
    if (filterType === 'clean' && !['clean', 'benign', 'clean / benign'].includes(item.verdict?.toLowerCase() || '')) return false;
    if (filterType === 'hash' && item.type !== 'hash') return false;

    // Search filter
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      (item.indicator || '').toLowerCase().includes(term) ||
      (item.analystName || '').toLowerCase().includes(term) ||
      (item.verdict || '').toLowerCase().includes(term) ||
      (item.type || '').toLowerCase().includes(term) ||
      (item.hashes?.sha256 || '').toLowerCase().includes(term) ||
      (item.fileName || '').toLowerCase().includes(term)
    );
  });

  return (
    <section className="relative z-10 max-w-5xl mx-auto px-4 mt-6 mb-8">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-md overflow-hidden shadow-2xl">
        {/* Header Bar */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-950/70 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-violet-500/20 border border-cyan-500/30 text-cyan-400">
              <History className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="font-extrabold text-sm sm:text-base text-slate-100 uppercase tracking-wider flex items-center gap-2">
                  24-Hour Investigation History & Audit Trail
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/90 text-cyan-300 border border-cyan-700/60 font-semibold">
                  {historyList.length} Active Records
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Retaining all SOC analyst queries for 24 hours · Visible to all logged-in analysts
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end sm:self-center">
            <span className="hidden md:inline-flex items-center gap-1.5 text-[10px] font-mono px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700 text-slate-300">
              <Clock className="w-3 h-3 text-cyan-400" />
              <span>Strict 24h Window</span>
            </span>

            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              title="Refresh 24-hour investigation feed"
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 text-xs font-mono border border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
              <span className="hidden sm:inline">Refresh</span>
            </button>

            <button
              type="button"
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 transition-colors cursor-pointer"
              title={isCollapsed ? 'Expand history feed' : 'Collapse history feed'}
            >
              {isCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Collapsible Content */}
        {!isCollapsed && (
          <div>
            {/* Filter & Search Toolbar */}
            <div className="p-3 sm:p-4 bg-slate-950/40 border-b border-slate-800/70 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
              {/* Search Bar */}
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter by hash, domain, IP, or analyst name..."
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Filter Pills */}
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0 text-xs">
                <button
                  type="button"
                  onClick={() => setFilterType('all')}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium font-mono transition-colors cursor-pointer whitespace-nowrap ${
                    filterType === 'all'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All ({historyList.length})
                </button>
                <button
                  type="button"
                  onClick={() => setFilterType('malicious')}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium font-mono transition-colors cursor-pointer whitespace-nowrap ${
                    filterType === 'malicious'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      : 'bg-slate-800 text-slate-400 hover:text-rose-300'
                  }`}
                >
                  Malicious
                </button>
                <button
                  type="button"
                  onClick={() => setFilterType('suspicious')}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium font-mono transition-colors cursor-pointer whitespace-nowrap ${
                    filterType === 'suspicious'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      : 'bg-slate-800 text-slate-400 hover:text-amber-300'
                  }`}
                >
                  Suspicious
                </button>
                <button
                  type="button"
                  onClick={() => setFilterType('clean')}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium font-mono transition-colors cursor-pointer whitespace-nowrap ${
                    filterType === 'clean'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-400 hover:text-emerald-300'
                  }`}
                >
                  Clean
                </button>
                <button
                  type="button"
                  onClick={() => setFilterType('hash')}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-medium font-mono transition-colors cursor-pointer whitespace-nowrap ${
                    filterType === 'hash'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-slate-800 text-slate-400 hover:text-cyan-300'
                  }`}
                >
                  Hashes
                </button>
              </div>
            </div>

            {/* List Table */}
            <div className="divide-y divide-slate-800/80 max-h-[460px] overflow-y-auto">
              {filtered.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-xs">
                  <p className="font-semibold text-slate-300">No matching 24-hour investigation records</p>
                  <p className="mt-1 text-slate-500">
                    {searchTerm ? 'Try adjusting your search filter' : 'Submit or paste any hash/URL above to run triage'}
                  </p>
                </div>
              ) : (
                filtered.map((item) => {
                  const isCurrent = currentLookupId === item.id;
                  const isMalicious = item.verdict?.toLowerCase() === 'malicious';
                  const isSuspicious = item.verdict?.toLowerCase() === 'suspicious';
                  const isClean = ['clean', 'benign', 'clean / benign'].includes(item.verdict?.toLowerCase() || '');

                  return (
                    <div
                      key={item.id}
                      onClick={() => onSelectLookup(item.id)}
                      className={`p-3.5 sm:p-4 hover:bg-slate-800/40 transition-colors cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3 group ${
                        isCurrent ? 'bg-cyan-950/20 border-l-4 border-cyan-400' : ''
                      }`}
                    >
                      {/* Left: Indicator & Verdict */}
                      <div className="flex items-start gap-3 min-w-0 flex-1">
                        {/* Verdict Icon Pill */}
                        <div
                          className={`p-2 rounded-lg shrink-0 mt-0.5 ${
                            isMalicious
                              ? 'bg-rose-500/15 border border-rose-500/30 text-rose-400'
                              : isSuspicious
                              ? 'bg-amber-500/15 border border-amber-500/30 text-amber-400'
                              : 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400'
                          }`}
                        >
                          {isMalicious ? (
                            <ShieldAlert className="w-4 h-4" />
                          ) : isSuspicious ? (
                            <AlertTriangle className="w-4 h-4" />
                          ) : (
                            <ShieldCheck className="w-4 h-4" />
                          )}
                        </div>

                        {/* Details */}
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            {/* Verdict Badge */}
                            <span
                              className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded-full border ${
                                isMalicious
                                  ? 'bg-rose-950/80 text-rose-300 border-rose-700/60'
                                  : isSuspicious
                                  ? 'bg-amber-950/80 text-amber-300 border-amber-700/60'
                                  : 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
                              }`}
                            >
                              {item.verdict || (item.ruleScore >= 70 ? 'Malicious' : 'Suspicious')}
                            </span>

                            {/* Type Pill */}
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                              {item.type}
                            </span>

                            {/* Rule Score Pill */}
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950 text-cyan-400 border border-cyan-800/40">
                              Score: {item.ruleScore}/100
                            </span>

                            {isCurrent && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold animate-pulse">
                                Active on Console
                              </span>
                            )}
                          </div>

                          {/* Indicator string */}
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs sm:text-sm text-slate-100 truncate select-all group-hover:text-cyan-300 transition-colors">
                              {item.defanged || item.indicator}
                            </span>

                            <button
                              type="button"
                              onClick={(e) => handleCopy(item.indicator, item.id, e)}
                              title="Copy raw indicator"
                              className="text-slate-500 hover:text-slate-300 p-1 rounded transition-colors shrink-0"
                            >
                              {copiedId === item.id ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>

                          {/* File info if any */}
                          {item.fileName && (
                            <p className="text-[11px] font-mono text-slate-400 mt-0.5 flex items-center gap-1.5">
                              <FileText className="w-3 h-3 text-cyan-400" />
                              <span>{item.fileName}</span>
                              {item.fileSize && (
                                <span className="text-slate-500">({(item.fileSize / 1024).toFixed(1)} KB)</span>
                              )}
                            </p>
                          )}
                        </div>
                      </div>

                      {/* Right: Analyst Attribution, Timestamp & Action */}
                      <div className="flex items-center justify-between md:justify-end gap-4 shrink-0 pl-11 md:pl-0 border-t md:border-t-0 border-slate-800/60 pt-2 md:pt-0">
                        <div className="text-left md:text-right">
                          {/* Analyst Badge */}
                          <div className="flex items-center md:justify-end gap-1.5 text-xs text-slate-300 font-medium">
                            <User className="w-3 h-3 text-cyan-400" />
                            <span className="truncate max-w-[150px]">{item.analystName || 'SOC Analyst'}</span>
                          </div>

                          {/* Timestamp */}
                          <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                            {formatRelativeTime(item.createdAt)} · {formatExactTime(item.createdAt)}
                          </p>
                        </div>

                        {/* Load Button */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectLookup(item.id);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 group-hover:bg-cyan-500 group-hover:text-slate-950 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm border border-slate-700 group-hover:border-cyan-400"
                        >
                          <span>Load</span>
                          <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" />
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Footer Summary Strip */}
            <div className="p-3 bg-slate-950/90 border-t border-slate-800 text-xs text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-2">
              <span className="text-[11px]">
                Showing {filtered.length} of {historyList.length} investigation records within the 24-hour retention window.
              </span>
              <span className="text-[11px] font-mono text-cyan-400/90">
                Auto-synced across all authorized SOC analysts
              </span>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
