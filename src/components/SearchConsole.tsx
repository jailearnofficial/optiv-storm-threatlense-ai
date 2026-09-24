import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  UploadCloud,
  FileCode,
  ShieldCheck,
  AlertOctagon,
  ArrowRight,
  RefreshCw,
  Eye,
  Check,
  FileText,
  User,
  UserCheck,
  ShieldAlert,
  X
} from 'lucide-react';
import { IndicatorType } from '../types/index.js';

interface SearchConsoleProps {
  indicator: string;
  setIndicator: (val: string) => void;
  selectedType: string;
  setSelectedType: (type: string) => void;
  onLookup: (submitMode: boolean, file?: File) => void;
  loading: boolean;
  analystName: string;
  setAnalystName: (name: string) => void;
}

export const SearchConsole: React.FC<SearchConsoleProps> = ({
  indicator,
  setIndicator,
  selectedType,
  setSelectedType,
  onLookup,
  loading,
  analystName,
  setAnalystName
}) => {
  const [submitToggle, setSubmitToggle] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [detectedType, setDetectedType] = useState<IndicatorType>('domain');
  const [defangedPreview, setDefangedPreview] = useState<string>('');
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Modal prompt state for collecting SOC analyst name before search/submission
  const [showAnalystModal, setShowAnalystModal] = useState(false);
  const [modalInputName, setModalInputName] = useState('');
  const [modalError, setModalError] = useState('');
  const [pendingAction, setPendingAction] = useState<{ submitMode: boolean; file?: File } | null>(null);
  const modalInputRef = useRef<HTMLInputElement>(null);

  // Auto detect type & defang locally for real-time chip
  useEffect(() => {
    const raw = indicator.trim();
    if (!raw) {
      setDefangedPreview('');
      return;
    }

    const clean = raw.replace(/^hxxp(s?):\/\//i, 'http$1://').replace(/\[\.\]/g, '.');

    // Hash check
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(clean)) {
      setDetectedType('hash');
      setDefangedPreview(clean.toLowerCase());
      return;
    }

    // IP check
    if (/^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/.test(clean) || clean.includes(':')) {
      setDetectedType('ip');
      setDefangedPreview(clean.replace(/\./g, '[.]'));
      return;
    }

    // URL check
    if (/^https?:\/\/|^ftp:\/\//i.test(clean) || (clean.includes('/') && clean.indexOf('/') < clean.length - 1)) {
      setDetectedType('url');
      setDefangedPreview(
        clean
          .replace(/^https:\/\//i, 'hxxps://')
          .replace(/^http:\/\//i, 'hxxp://')
          .replace(/\./g, '[.]')
      );
      return;
    }

    // Domain
    setDetectedType('domain');
    setDefangedPreview(clean.replace(/\./g, '[.]'));
  }, [indicator]);

  // Focus modal input when prompt opens
  useEffect(() => {
    if (showAnalystModal) {
      setModalInputName(analystName || '');
      setModalError('');
      setTimeout(() => modalInputRef.current?.focus(), 50);
    }
  }, [showAnalystModal, analystName]);

  const initiateSearchOrSubmission = (submitMode: boolean, file?: File) => {
    // If analyst name is missing, prompt to collect it first
    if (!analystName.trim()) {
      setPendingAction({ submitMode, file });
      setShowAnalystModal(true);
      return;
    }

    // Otherwise continue what is set so far
    if (submitMode && file) {
      onLookup(true, file);
    } else if (indicator.trim()) {
      onLookup(submitMode);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (submitToggle && selectedFile) {
      initiateSearchOrSubmission(true, selectedFile);
    } else if (indicator.trim()) {
      initiateSearchOrSubmission(submitToggle);
    }
  };

  const handleModalSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = modalInputName.trim();
    if (!clean) {
      setModalError('Please enter the SOC analyst name to proceed.');
      return;
    }

    setAnalystName(clean);
    try {
      localStorage.setItem('soc_analyst_name', clean);
    } catch {
      // ignore quota / private mode storage error
    }
    setShowAnalystModal(false);

    // Continue what was set so far
    const action = pendingAction || { submitMode: submitToggle, file: selectedFile || undefined };
    setPendingAction(null);

    if (action.submitMode && action.file) {
      onLookup(true, action.file);
    } else if (indicator.trim()) {
      onLookup(action.submitMode);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.size > 32 * 1024 * 1024) {
        alert('File size exceeds 32 MB limit.');
        return;
      }
      setSelectedFile(file);

      // Check analyst name
      if (!analystName.trim()) {
        setPendingAction({ submitMode: true, file });
        setShowAnalystModal(true);
      }
    }
  };

  const currentType = selectedType === 'auto' ? detectedType : (selectedType as IndicatorType);

  return (
    <section className="relative z-10 max-w-5xl mx-auto mt-6 mb-8 px-4">
      {/* Top Analyst Identity Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-2.5 px-1 text-xs">
        <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-700/80 rounded-lg px-3 py-1.5 shadow-sm">
          <User className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider shrink-0">
            SOC Analyst:
          </span>
          <input
            type="text"
            value={analystName}
            onChange={(e) => {
              setAnalystName(e.target.value);
              try {
                localStorage.setItem('soc_analyst_name', e.target.value);
              } catch {}
            }}
            placeholder="Enter SOC analyst name (e.g., Jane Doe)..."
            className="bg-transparent text-cyan-300 font-mono text-xs placeholder-slate-500 focus:outline-none w-52 sm:w-64"
          />
          {analystName.trim() ? (
            <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-1.5 py-0.5 rounded">
              <UserCheck className="w-3 h-3" />
              Verified
            </span>
          ) : (
            <span className="text-[10px] font-mono text-amber-300 bg-amber-950/60 border border-amber-700/60 px-1.5 py-0.5 rounded">
              Required for reports
            </span>
          )}
        </div>

        <div className="text-[11px] text-slate-400 hidden sm:flex items-center gap-1 font-mono">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          <span>Analyst attribution will be stamped on dossier & PDF report</span>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-3.5">
        {/* Main Search Panel */}
        <div className="relative rounded-xl bg-slate-900/90 border border-slate-700/80 shadow-[0_4px_25px_rgba(0,0,0,0.5)] p-2 md:p-3 backdrop-blur-md focus-within:border-cyan-500/80 focus-within:shadow-[0_0_20px_rgba(34,211,238,0.15)] transition-all">
          <div className="flex flex-col md:flex-row items-stretch md:items-center gap-2.5">
            {/* Type Selector Dropdown / Segment */}
            <div className="flex items-center gap-1 bg-slate-950/70 p-1 rounded-lg border border-slate-800 text-xs font-mono self-start md:self-auto">
              {['auto', 'hash', 'domain', 'ip', 'url'].map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setSelectedType(t)}
                  className={`px-2.5 py-1 rounded transition-colors uppercase text-[11px] font-medium ${
                    selectedType === t
                      ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            {/* Indicator Input Box */}
            <div className="relative flex-1 flex items-center">
              <input
                type="text"
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                placeholder="Enter target file hash, domain, IP, or URL..."
                className="w-full bg-transparent text-slate-100 placeholder-slate-500 font-mono text-sm md:text-base px-3 py-2 outline-none border-none focus:ring-0"
                disabled={loading}
              />

              {indicator && (
                <span className="hidden sm:inline-flex items-center gap-1.5 mr-2 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 select-none">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  {currentType.toUpperCase()}
                </span>
              )}
            </div>

            {/* Lookup / Investigate Button */}
            <button
              type="submit"
              disabled={loading || (!indicator.trim() && !selectedFile)}
              className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-bold text-sm tracking-wide transition-all shadow-[0_0_15px_rgba(34,211,238,0.3)] disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Querying 7 Feeds...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-slate-950" />
                  <span>Triage Indicator</span>
                </>
              )}
            </button>
          </div>

          {/* Defanged Preview Strip */}
          {defangedPreview && (
            <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs px-2 text-slate-400">
              <div className="flex items-center gap-2 truncate">
                <span className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">
                  Defanged Form:
                </span>
                <span className="font-mono text-cyan-300/90 truncate select-all bg-slate-950/60 px-2 py-0.5 rounded border border-slate-800">
                  {defangedPreview}
                </span>
              </div>
              <span className="text-[11px] text-slate-500 hidden sm:inline">
                Safe for SOC logs & dev tools
              </span>
            </div>
          )}
        </div>

        {/* Submission Mode Toggle & Warning */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 px-1 text-xs text-slate-400">
          <label className="flex items-center gap-2.5 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={submitToggle}
              onChange={(e) => setSubmitToggle(e.target.checked)}
              className="sr-only"
            />
            <div
              className={`w-9 h-5 rounded-full p-0.5 transition-colors ${
                submitToggle ? 'bg-amber-500' : 'bg-slate-700'
              }`}
            >
              <div
                className={`w-4 h-4 rounded-full bg-white transition-transform ${
                  submitToggle ? 'translate-x-4' : 'translate-x-0'
                }`}
              />
            </div>
            <span className={submitToggle ? 'text-amber-300 font-medium' : 'text-slate-400'}>
              Submit for Active Analysis / File Sandbox (Upload up to 32MB)
            </span>
          </label>

          <span className="text-[11px] text-slate-500 font-mono">
            Default: Passive Query (No data leaked to public feeds)
          </span>
        </div>

        {/* Active File Dropzone if Submit Toggle Enabled */}
        {submitToggle && (
          <div className="animate-in fade-in slide-in-from-top-2 duration-200">
            {/* Warning Banner */}
            <div className="p-3 mb-2.5 rounded-lg bg-amber-950/40 border border-amber-600/40 text-amber-200 text-xs flex items-start gap-2.5">
              <AlertOctagon className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-amber-300">Public Intelligence Disclosure Warning</p>
                <p className="text-[11px] text-amber-200/80 leading-relaxed">
                  Submitting active files or URLs forwards them to third-party sandbox engines (VirusTotal, Hybrid Analysis, urlscan.io). Indicators and files may become visible to other security researchers on those platforms. urlscan.io is forced to <code className="text-amber-100 font-mono">unlisted</code>.
                </p>
              </div>
            </div>

            {/* Dropzone */}
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition-colors ${
                dragOver
                  ? 'border-cyan-400 bg-cyan-950/20'
                  : 'border-slate-700 hover:border-slate-600 bg-slate-900/40'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    const f = e.target.files[0];
                    if (f.size > 32 * 1024 * 1024) {
                      alert('File exceeds 32 MB limit.');
                      return;
                    }
                    setSelectedFile(f);
                    if (!analystName.trim()) {
                      setPendingAction({ submitMode: true, file: f });
                      setShowAnalystModal(true);
                    }
                  }
                }}
              />

              {selectedFile ? (
                <div className="flex items-center justify-center gap-3">
                  <FileText className="w-8 h-8 text-cyan-400" />
                  <div className="text-left">
                    <p className="font-mono text-sm font-semibold text-slate-200">
                      {selectedFile.name}
                    </p>
                    <p className="text-xs text-slate-400 font-mono">
                      {(selectedFile.size / 1024).toFixed(1)} KB · Ready to compute MD5, SHA-1, SHA-256
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                    }}
                    className="ml-4 text-xs text-rose-400 hover:text-rose-300 underline"
                  >
                    Remove
                  </button>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center gap-1.5">
                  <UploadCloud className="w-7 h-7 text-slate-400 mb-1" />
                  <p className="text-xs text-slate-300 font-medium">
                    Drag and drop a suspicious file here, or click to browse
                  </p>
                  <p className="text-[11px] text-slate-500">
                    Max file size 32 MB · File never executed locally · Hashes computed securely
                  </p>
                </div>
              )}
            </div>
          </div>
        )}
      </form>

      {/* Mandatory SOC Analyst Name Collection Modal */}
      {showAnalystModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-150">
          <div className="relative w-full max-w-md rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl p-6 overflow-hidden">
            <button
              onClick={() => {
                setShowAnalystModal(false);
                setPendingAction(null);
              }}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <UserCheck className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100 uppercase tracking-wide">
                  SOC Analyst Verification
                </h3>
                <p className="text-xs text-slate-400">
                  Attribution required before search or submission
                </p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Please enter your name or investigator handle. This will be recorded with the query and printed on generated dossier summaries and PDF reports as:
              <br />
              <code className="block mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-[11px]">
                SOC analyst name: [entered name]
              </code>
            </p>

            <form onSubmit={handleModalSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  SOC Analyst Name
                </label>
                <input
                  ref={modalInputRef}
                  type="text"
                  value={modalInputName}
                  onChange={(e) => {
                    setModalInputName(e.target.value);
                    if (modalError) setModalError('');
                  }}
                  placeholder="e.g., Alex Rivera, Tier-2 Analyst"
                  className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg px-3.5 py-2.5 text-sm font-mono text-slate-100 placeholder-slate-500 outline-none transition-colors"
                />
                {modalError && (
                  <p className="text-xs text-rose-400 mt-1.5 flex items-center gap-1">
                    <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                    {modalError}
                  </p>
                )}
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowAnalystModal(false);
                    setPendingAction(null);
                  }}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-all shadow-[0_0_15px_rgba(34,211,238,0.3)] flex items-center gap-1.5 cursor-pointer"
                >
                  <span>Continue Investigation</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
};
