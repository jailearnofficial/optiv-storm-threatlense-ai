import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
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
  X,
  Globe,
  Server,
  Terminal,
  Cpu
} from 'lucide-react';
import { IndicatorType, DetonationTarget, SandboxGuestOS } from '../types/index.js';
import { useAuth } from '../context/AuthContext.js';

interface SearchConsoleProps {
  indicator: string;
  setIndicator: (val: string) => void;
  selectedType: string;
  setSelectedType: (type: string) => void;
  onLookup: (
    submitMode: boolean,
    file?: File,
    customAnalystName?: string,
    forceRefresh?: boolean,
    detonationOptions?: {
      detonationTarget: 'threat_intel' | 'in_house_sandbox' | 'dual_track';
      guestOS: 'win10_x64' | 'win11_x64' | 'ubuntu_x64';
    }
  ) => void;
  loading: boolean;
  analystName: string;
  setAnalystName: (name: string) => void;
  onFileModalOpenChange?: (open: boolean) => void;
}

export const SearchConsole: React.FC<SearchConsoleProps> = ({
  indicator,
  setIndicator,
  selectedType,
  setSelectedType,
  onLookup,
  loading,
  analystName,
  setAnalystName,
  onFileModalOpenChange
}) => {
  const { user } = useAuth();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [detectedType, setDetectedType] = useState<IndicatorType>('domain');
  const [defangedPreview, setDefangedPreview] = useState<string>('');
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Modal prompt state for collecting SOC analyst name before search/submission
  const [showAnalystModal, setShowAnalystModal] = useState(false);
  const [modalInputName, setModalInputName] = useState('');
  const [modalError, setModalError] = useState('');
  const [pendingAction, setPendingAction] = useState<{
    submitMode: boolean;
    file?: File;
    detonationOptions?: {
      detonationTarget: DetonationTarget;
      guestOS: SandboxGuestOS;
    };
  } | null>(null);
  const modalInputRef = useRef<HTMLInputElement>(null);

  // In-House Sandbox Detonation Target Selection Modal
  const [showDetonationModal, setShowDetonationModal] = useState(false);
  const [detonationTarget, setDetonationTarget] = useState<DetonationTarget>('threat_intel');
  const [guestOS, setGuestOS] = useState<SandboxGuestOS>('win10_x64');
  const [fileToDetonate, setFileToDetonate] = useState<File | null>(null);
  const modalFileInputRef = useRef<HTMLInputElement>(null);

  // Notify parent App when file modal opens/closes so background feeds and 24h history can be hidden
  useEffect(() => {
    onFileModalOpenChange?.(showDetonationModal);
  }, [showDetonationModal, onFileModalOpenChange]);

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

  const handleFileSelected = (file: File) => {
    if (file.size > 32 * 1024 * 1024) {
      alert('File size exceeds 32 MB limit.');
      return;
    }
    setSelectedFile(file);
    setIndicator(`[File] ${file.name}`);
    setSelectedType('hash');
    setFileToDetonate(file);
    setShowDetonationModal(true);
  };

  const handleOpenBrowseModal = () => {
    setShowDetonationModal(true);
  };

  const handleDetonationConfirm = () => {
    const file = fileToDetonate || selectedFile;
    if (!file) {
      modalFileInputRef.current?.click();
      return;
    }

    const targetAnalyst = (analystName.trim() || modalInputName.trim() || 'SOC Analyst (Active)');
    if (!analystName.trim()) {
      setAnalystName(targetAnalyst);
    }

    setShowDetonationModal(false);

    const detonationOptions = {
      detonationTarget,
      guestOS
    };

    onLookup(true, file, targetAnalyst, false, detonationOptions);
  };

  const initiateSearchOrSubmission = (submitMode: boolean, file?: File) => {
    const targetFile = file || selectedFile;
    if (targetFile) {
      setFileToDetonate(targetFile);
      setShowDetonationModal(true);
      return;
    }

    if (indicator.trim()) {
      onLookup(submitMode);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedFile) {
      initiateSearchOrSubmission(true, selectedFile);
    } else if (indicator.trim()) {
      initiateSearchOrSubmission(false);
    }
  };

  const handleModalSubmit = (e: React.FormEvent, skipName = false) => {
    e.preventDefault();
    const clean = skipName ? 'SOC Analyst (Active)' : modalInputName.trim();
    if (!clean && !skipName) {
      setModalError('Please enter the SOC analyst name to proceed, or click "Continue as Analyst".');
      return;
    }

    if (clean) {
      setAnalystName(clean);
    }
    setShowAnalystModal(false);

    // Continue what was set so far
    const action = pendingAction || { submitMode: true, file: selectedFile || undefined };
    setPendingAction(null);

    if (action.file) {
      onLookup(true, action.file, clean || undefined, false, action.detonationOptions);
    } else if (indicator.trim()) {
      onLookup(action.submitMode, undefined, clean || undefined);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      handleFileSelected(file);
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
            onChange={(e) => setAnalystName(e.target.value)}
            placeholder="Enter SOC analyst name (e.g., Jane Doe)..."
            className="bg-transparent text-cyan-300 font-mono text-xs placeholder-slate-500 focus:outline-none w-52 sm:w-64"
          />
          {analystName && (
            <button
              type="button"
              onClick={() => setAnalystName('')}
              title="Clear analyst name"
              className="text-slate-500 hover:text-slate-300 p-0.5 rounded transition-colors"
            >
              <X className="w-3 h-3" />
            </button>
          )}
          {analystName.trim() ? (
            <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-1.5 py-0.5 rounded">
              <UserCheck className="w-3 h-3" />
              <span>{user ? 'Authenticated' : 'Verified'}</span>
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
        {/* Hidden File Input for Sample File Analysis */}
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileSelected(e.target.files[0]);
            }
          }}
        />

        {/* Main Search Panel */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`relative rounded-xl bg-slate-900/90 border shadow-[0_4px_25px_rgba(0,0,0,0.5)] p-2 md:p-3 backdrop-blur-md focus-within:border-cyan-500/80 focus-within:shadow-[0_0_20px_rgba(34,211,238,0.15)] transition-all ${
            dragOver ? 'border-cyan-400 bg-cyan-950/30' : 'border-slate-700/80'
          }`}
        >
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
                onChange={(e) => {
                  if (selectedFile) setSelectedFile(null);
                  let val = e.target.value.trim();
                  // Clean any accidental adjacent concatenated duplicate hashes
                  if (val.length >= 64 && val.length % 2 === 0) {
                    const half = val.length / 2;
                    if (val.slice(0, half) === val.slice(half) && /^[a-fA-F0-9]+$/.test(val)) {
                      val = val.slice(0, half);
                    }
                  } else if (val.length >= 80 && val.length % 2 === 0) {
                    const half = val.length / 2;
                    if (val.slice(0, half) === val.slice(half) && /^[a-fA-F0-9]+$/.test(val)) {
                      val = val.slice(0, half);
                    }
                  } else if (val.length >= 128 && val.length % 2 === 0) {
                    const half = val.length / 2;
                    if (val.slice(0, half) === val.slice(half) && /^[a-fA-F0-9]+$/.test(val)) {
                      val = val.slice(0, half);
                    }
                  }
                  setIndicator(val);
                }}
                onPaste={(e) => {
                  e.preventDefault();
                  const pasted = e.clipboardData.getData('text');
                  if (pasted) {
                    let cleanPasted = pasted.trim();
                    // Strip wrapping quotes, brackets, or code fences
                    cleanPasted = cleanPasted.replace(/^["'`]|["'`]$/g, '').trim();

                    // Check if clipboard itself contained adjacent duplicate hashes
                    if (cleanPasted.length >= 64 && cleanPasted.length % 2 === 0) {
                      const half = cleanPasted.length / 2;
                      if (cleanPasted.slice(0, half) === cleanPasted.slice(half) && /^[a-fA-F0-9]+$/.test(cleanPasted)) {
                        cleanPasted = cleanPasted.slice(0, half);
                      }
                    } else if (cleanPasted.length >= 80 && cleanPasted.length % 2 === 0) {
                      const half = cleanPasted.length / 2;
                      if (cleanPasted.slice(0, half) === cleanPasted.slice(half) && /^[a-fA-F0-9]+$/.test(cleanPasted)) {
                        cleanPasted = cleanPasted.slice(0, half);
                      }
                    } else if (cleanPasted.length >= 128 && cleanPasted.length % 2 === 0) {
                      const half = cleanPasted.length / 2;
                      if (cleanPasted.slice(0, half) === cleanPasted.slice(half) && /^[a-fA-F0-9]+$/.test(cleanPasted)) {
                        cleanPasted = cleanPasted.slice(0, half);
                      }
                    }

                    if (cleanPasted) {
                      if (selectedFile) setSelectedFile(null);
                      setIndicator(cleanPasted);
                    }
                  }
                }}
                placeholder="Enter or paste target file hash, domain, IP, or URL..."
                className="w-full bg-transparent text-slate-100 placeholder-slate-500 font-mono text-sm md:text-base px-3 py-2 outline-none border-none focus:ring-0 pr-24"
                disabled={loading}
              />

              <div className="absolute right-2 flex items-center gap-1.5">
                {indicator && !loading && (
                  <button
                    type="button"
                    onClick={() => {
                      setIndicator('');
                      setSelectedFile(null);
                    }}
                    title="Clear indicator to paste another hash"
                    className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-rose-400 text-[11px] font-mono border border-slate-700 flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <X className="w-3 h-3" />
                    <span className="hidden sm:inline">Clear</span>
                  </button>
                )}

                {indicator && (
                  <span className="hidden sm:inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 select-none">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                    {currentType.toUpperCase()}
                  </span>
                )}
              </div>
            </div>

            {/* Browse File Button */}
            <button
              type="button"
              onClick={handleOpenBrowseModal}
              className="px-4 py-2.5 rounded-lg bg-slate-800/90 hover:bg-slate-700/90 text-cyan-300 hover:text-cyan-200 border border-slate-700 hover:border-cyan-500/50 font-bold text-xs flex items-center justify-center gap-1.5 transition-all shadow-sm cursor-pointer shrink-0"
              title="Browse and detonate binary, script, or document sample"
            >
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              <span>Browse File</span>
            </button>

            {/* Lookup / Investigate Button */}
            <button
              type="submit"
              disabled={loading || (!indicator.trim() && !selectedFile)}
              className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-bold text-sm tracking-wide transition-all shadow-[0_0_15px_rgba(34,211,238,0.3)] disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer shrink-0"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Querying 7 Feeds...</span>
                </>
              ) : selectedFile ? (
                <>
                  <UploadCloud className="w-4 h-4 text-slate-950" />
                  <span>Fetch Feeds for Sample</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-slate-950" />
                  <span>Search Feeds</span>
                </>
              )}
            </button>
          </div>

          {/* Selected File Details Banner */}
          {selectedFile && (
            <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs px-2 text-cyan-300">
              <div className="flex items-center gap-2 font-mono truncate">
                <FileText className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="font-semibold truncate">{selectedFile.name}</span>
                <span className="text-slate-500 text-[11px] shrink-0">
                  ({(selectedFile.size / 1024).toFixed(1)} KB)
                </span>
                <span className="hidden sm:inline text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 shrink-0">
                  VirusTotal · Hybrid Analysis · AlienVault OTX
                </span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setSelectedFile(null);
                  setIndicator('');
                }}
                className="text-rose-400 hover:text-rose-300 text-[11px] font-mono underline ml-3 shrink-0"
              >
                Clear
              </button>
            </div>
          )}

          {/* Defanged Preview Strip */}
          {defangedPreview && !selectedFile && (
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
      </form>

      {/* Detonation Target & In-House Sandbox Selection Modal (Rendered at Root Portal to ensure clean view without interference) */}
      {showDetonationModal && createPortal(
        <div className="fixed inset-0 z-[99999] flex items-center justify-center p-4 bg-[#070B14]/95 backdrop-blur-2xl overflow-y-auto animate-in fade-in duration-150">
          <div className="relative w-full max-w-xl rounded-2xl bg-slate-900 border border-cyan-500/50 shadow-[0_0_80px_rgba(0,0,0,0.9)] p-6 overflow-hidden my-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                    <span>Sample Detonation Routing Target</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Isolated Air-Gapped Sandbox & Threat Intelligence Pipeline
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowDetonationModal(false);
                  setFileToDetonate(null);
                }}
                className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Public Intelligence Disclosure Warning Disclaimer */}
            <div className="my-3.5 p-3.5 rounded-xl bg-amber-950/40 border border-amber-600/50 text-amber-200 text-xs flex items-start gap-3 shadow-[0_0_15px_rgba(245,158,11,0.1)]">
              <AlertOctagon className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold text-amber-300 text-xs tracking-wide uppercase">
                  Public Intelligence Disclosure Warning
                </p>
                <p className="text-[11.5px] text-amber-200/90 leading-relaxed mt-1">
                  Submitting active files or URLs forwards them to third-party sandbox engines (VirusTotal, Hybrid Analysis, urlscan.io). Indicators and files may become visible to other security researchers on those platforms. urlscan.io is forced to <code className="text-amber-100 font-mono bg-amber-950/80 px-1 py-0.5 rounded border border-amber-700/60">unlisted</code>.
                </p>
              </div>
            </div>

            {/* Hidden Input for Selecting / Changing File */}
            <input
              ref={modalFileInputRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  const file = e.target.files[0];
                  if (file.size > 32 * 1024 * 1024) {
                    alert('File size exceeds 32 MB limit.');
                    return;
                  }
                  setFileToDetonate(file);
                  setSelectedFile(file);
                  setIndicator(`[File] ${file.name}`);
                  setSelectedType('hash');
                }
              }}
            />

            {/* Embedded File Selection / Status Box */}
            <div className="my-4">
              {fileToDetonate || selectedFile ? (
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-950 border border-cyan-500/40">
                  <div className="flex items-center gap-3 truncate">
                    <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shrink-0">
                      <FileText className="w-5 h-5" />
                    </div>
                    <div className="truncate">
                      <div className="text-xs font-mono font-bold text-cyan-300 truncate">
                        {(fileToDetonate || selectedFile)?.name}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        {((fileToDetonate || selectedFile)!.size / 1024).toFixed(1)} KB · Ready to Detonate
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => modalFileInputRef.current?.click()}
                    className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors cursor-pointer border border-slate-700 shrink-0 ml-3"
                  >
                    Change File
                  </button>
                </div>
              ) : (
                <div
                  onClick={() => modalFileInputRef.current?.click()}
                  className="border-2 border-dashed border-cyan-500/50 hover:border-cyan-400 bg-cyan-950/20 hover:bg-cyan-950/40 rounded-xl p-5 text-center cursor-pointer transition-all group"
                >
                  <UploadCloud className="w-8 h-8 text-cyan-400 mx-auto mb-1.5 group-hover:scale-110 transition-transform" />
                  <p className="text-xs font-bold text-slate-100">
                    Click to Select Sample File or Drag & Drop Here
                  </p>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Supports PE, ELF, scripts (.ps1, .sh, .py), Office documents up to 32 MB
                  </p>
                </div>
              )}
            </div>

            {/* SOC Analyst Attribution Field */}
            <div className="mb-4 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
              <label className="block text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-cyan-400" />
                <span>SOC Analyst Attribution:</span>
              </label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                placeholder="Enter SOC analyst name (e.g., SOC Analyst)..."
                className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500 w-full"
              />
            </div>

            <p className="text-xs text-slate-300 mb-3 leading-relaxed">
              Select where and how this binary sample should be evaluated:
            </p>

            {/* Target Options */}
            <div className="space-y-2.5">
              {/* Option 1: External Threat Intel */}
              <div
                onClick={() => setDetonationTarget('threat_intel')}
                className={`p-3 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                  detonationTarget === 'threat_intel'
                    ? 'border-cyan-400 bg-cyan-950/40 shadow-[0_0_15px_rgba(34,211,238,0.15)] ring-1 ring-cyan-500/50'
                    : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                }`}
              >
                <div className={`mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center shrink-0 ${
                  detonationTarget === 'threat_intel' ? 'border-cyan-400 bg-cyan-500 text-slate-950' : 'border-slate-600'
                }`}>
                  {detonationTarget === 'threat_intel' && <div className="w-1.5 h-1.5 rounded-full bg-slate-950" />}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-cyan-400" />
                      <span>7-Way Threat Intelligence Feeds</span>
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                      Standard
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                    Calculates SHA256/MD5 hashes locally and queries VirusTotal, Falcon Sandbox, MalwareBazaar, and OTX without exposing confidential binary contents.
                  </p>
                </div>
              </div>

              {/* Option 2: In-House Air-Gapped Sandbox */}
              <div
                onClick={() => setDetonationTarget('in_house_sandbox')}
                className={`p-3 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                  detonationTarget === 'in_house_sandbox'
                    ? 'border-emerald-400 bg-emerald-950/40 shadow-[0_0_15px_rgba(16,185,129,0.15)] ring-1 ring-emerald-500/50'
                    : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                }`}
              >
                <div className={`mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center shrink-0 ${
                  detonationTarget === 'in_house_sandbox' ? 'border-emerald-400 bg-emerald-500 text-slate-950' : 'border-slate-600'
                }`}>
                  {detonationTarget === 'in_house_sandbox' && <div className="w-1.5 h-1.5 rounded-full bg-slate-950" />}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-emerald-400" />
                      <span>In-House Air-Gapped Sandbox (CAPE / Cuckoo VM)</span>
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/60">
                      OPSEC Safe
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                    Executes binary in private isolated microVM. Captures process hollowing, API hooks, registry tampering, and network beacons while bypassing all third-party public clouds.
                  </p>
                </div>
              </div>

              {/* Option 3: Dual-Track */}
              <div
                onClick={() => setDetonationTarget('dual_track')}
                className={`p-3 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                  detonationTarget === 'dual_track'
                    ? 'border-purple-400 bg-purple-950/40 shadow-[0_0_15px_rgba(168,85,247,0.15)] ring-1 ring-purple-500/50'
                    : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                }`}
              >
                <div className={`mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center shrink-0 ${
                  detonationTarget === 'dual_track' ? 'border-purple-400 bg-purple-500 text-slate-950' : 'border-slate-600'
                }`}>
                  {detonationTarget === 'dual_track' && <div className="w-1.5 h-1.5 rounded-full bg-slate-950" />}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-purple-400" />
                      <span>Dual-Track Comprehensive Execution</span>
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/60">
                      Deep Triage
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                    Forks execution simultaneously into both the external Threat Intelligence network and private in-house sandbox for complete cross-validation.
                  </p>
                </div>
              </div>
            </div>

            {/* Guest VM Environment Selection when sandbox is selected */}
            {(detonationTarget === 'in_house_sandbox' || detonationTarget === 'dual_track') && (
              <div className="mt-3.5 p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <label className="block text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                  Guest VM Detonation Profile:
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {[
                    { id: 'win10_x64', label: 'Win 10 Pro 22H2', desc: 'Enterprise EDR Active' },
                    { id: 'win11_x64', label: 'Win 11 x64 Enterprise', desc: 'Office 365 + PS7' },
                    { id: 'ubuntu_x64', label: 'Ubuntu 22.04 LTS', desc: 'Linux ELF / Sh Trace' }
                  ].map((env) => (
                    <button
                      type="button"
                      key={env.id}
                      onClick={() => setGuestOS(env.id as SandboxGuestOS)}
                      className={`p-2 rounded-lg border text-left transition-all cursor-pointer ${
                        guestOS === env.id
                          ? 'border-cyan-400 bg-cyan-950/60 text-white ring-1 ring-cyan-500/50'
                          : 'border-slate-800 bg-slate-900/50 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="text-xs font-bold">{env.label}</div>
                      <div className="text-[10px] text-slate-400">{env.desc}</div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Modal Actions */}
            <div className="flex items-center justify-end gap-3 mt-5 pt-4 border-t border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setShowDetonationModal(false);
                  setFileToDetonate(null);
                }}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDetonationConfirm}
                className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 text-xs font-bold transition-all shadow-[0_0_20px_rgba(34,211,238,0.3)] flex items-center gap-1.5 cursor-pointer"
              >
                <span>Execute Analysis</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>,
        document.body
      )}

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

              <div className="flex items-center justify-between gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={(e) => handleModalSubmit(e, true)}
                  className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs font-mono transition-colors cursor-pointer"
                >
                  Skip Name
                </button>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowAnalystModal(false);
                      setPendingAction(null);
                    }}
                    className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-all shadow-[0_0_15px_rgba(34,211,238,0.3)] flex items-center gap-1.5 cursor-pointer"
                  >
                    <span>Analyze</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
};
