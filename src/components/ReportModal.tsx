import React from 'react';
import { X, Printer, Download, ExternalLink, ShieldCheck } from 'lucide-react';

interface ReportModalProps {
  analysisId: string | null;
  analystName?: string;
  onClose: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({ analysisId, analystName, onClose }) => {
  if (!analysisId) return null;

  const reportUrl = analystName
    ? `/api/report/${analysisId}.pdf?analyst_name=${encodeURIComponent(analystName)}`
    : `/api/report/${analysisId}.pdf`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-150">
      <div className="relative w-full max-w-5xl h-[90vh] flex flex-col rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl overflow-hidden">
        {/* Top Control Bar */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-extrabold text-sm text-slate-100 uppercase tracking-wider">
                  OPTIV S.T.O.R.M · ThreatLense AI Dossier
                </h3>
                {analystName && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-700/60 hidden sm:inline-block">
                    SOC analyst name: {analystName}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 font-mono">Dossier ID: {analysisId}</p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => {
                const iframe = document.getElementById('report-frame') as HTMLIFrameElement;
                if (iframe?.contentWindow) {
                  iframe.contentWindow.focus();
                  iframe.contentWindow.print();
                }
              }}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </button>

            <a
              href={reportUrl}
              target="_blank"
              rel="noreferrer"
              className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition-colors"
              title="Open full report in new tab"
            >
              <ExternalLink className="w-4 h-4" />
            </a>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Embedded Iframe */}
        <div className="flex-1 bg-white p-2">
          <iframe
            id="report-frame"
            src={reportUrl}
            className="w-full h-full border-0 rounded"
            title="Threat Dossier PDF Report"
          />
        </div>
      </div>
    </div>
  );
};
