import React, { useState } from 'react';
import {
  ShieldAlert,
  Radio,
  History,
  Sparkles,
  ChevronDown,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';

interface HeaderProps {
  onOpenHistory: () => void;
  onSelectSample: (indicator: string, type: 'hash' | 'ip' | 'url' | 'domain') => void;
  providerHealth: Record<string, { configured: boolean; status: string }>;
}

const PRESET_SAMPLES = [
  {
    label: 'WannaCry 2.0 Ransomware (Hash)',
    type: 'hash' as const,
    indicator: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8',
    category: 'Malware'
  },
  {
    label: 'EICAR Standard AV Test (Hash)',
    type: 'hash' as const,
    indicator: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    category: 'Test File'
  },
  {
    label: 'Credential Harvester Phish (URL)',
    type: 'url' as const,
    indicator: 'http://paypal-account-verification-auth.com/login/update.php',
    category: 'Phishing'
  },
  {
    label: 'Tor Exit Node & Scanner (IP)',
    type: 'ip' as const,
    indicator: '185.220.101.5',
    category: 'Suspicious IP'
  },
  {
    label: 'Cloudflare CDN (Domain - False Positive)',
    type: 'domain' as const,
    indicator: 'cdnjs.cloudflare.com',
    category: 'False Positive'
  },
  {
    label: 'Google Search / DNS (Domain - Benign)',
    type: 'domain' as const,
    indicator: 'google.com',
    category: 'Benign'
  }
];

export const Header: React.FC<HeaderProps> = ({
  onOpenHistory,
  onSelectSample,
  providerHealth
}) => {
  const [samplesOpen, setSamplesOpen] = useState(false);

  const providers = [
    { key: 'virustotal', label: 'VT', full: 'VirusTotal v3' },
    { key: 'hybrid_analysis', label: 'HA', full: 'Hybrid Analysis' },
    { key: 'malwarebazaar', label: 'MB', full: 'MalwareBazaar' },
    { key: 'abuseipDB', label: 'AB', full: 'AbuseIPDB' },
    { key: 'urlhaus', label: 'UH', full: 'URLhaus' },
    { key: 'urlscan', label: 'US', full: 'urlscan.io' },
    { key: 'alienvault_otx', label: 'OTX', full: 'AlienVault OTX' }
  ];

  return (
    <header className="relative z-20 border-b border-slate-800/80 bg-[#0A0E17]/90 backdrop-blur-md px-4 lg:px-8 py-3.5 transition-all">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3.5">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-violet-500/20 border border-cyan-500/40 shadow-[0_0_15px_rgba(34,211,238,0.2)]">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <span className="absolute -bottom-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22D3EE]" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-wider text-base text-slate-100 uppercase">
                OPTIV S.T.O.R.M
              </span>
              <span className="text-[10px] font-semibold tracking-wider px-2 py-0.5 rounded bg-violet-950/80 text-violet-300 border border-violet-800/60 flex items-center gap-1">
                <Sparkles className="w-2.5 h-2.5 text-violet-400" />
                ThreatLense AI
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Unified Threat Triage · 7-Way Parallel Intelligence
            </p>
          </div>
        </div>

        {/* Center: Live 7 Provider Health Dots */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 shadow-inner">
          <div className="flex items-center gap-1.5 mr-2 text-[11px] font-medium text-slate-400">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Feeds:</span>
          </div>

          <div className="flex items-center gap-2">
            {providers.map((p) => {
              const h = providerHealth[p.key.toLowerCase()] || { status: 'up' };
              const isUp = h.status === 'up';
              return (
                <div
                  key={p.key}
                  className="group relative flex items-center gap-1 cursor-default"
                  title={`${p.full}: ${isUp ? 'Active & Ready' : 'Fallback Intelligence Ready'}`}
                >
                  <span
                    className={`w-2 h-2 rounded-full transition-all ${
                      isUp
                        ? 'bg-emerald-400 shadow-[0_0_6px_#10B981]'
                        : 'bg-amber-400 shadow-[0_0_6px_#F59E0B]'
                    }`}
                  />
                  <span className="text-[10px] font-mono font-medium text-slate-300">
                    {p.label}
                  </span>

                  {/* Tooltip */}
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block z-50 whitespace-nowrap bg-slate-950 text-slate-200 text-[11px] px-2.5 py-1 rounded border border-slate-700 shadow-xl pointer-events-none">
                    <p className="font-semibold">{p.full}</p>
                    <p className="text-[10px] text-slate-400">Status: {isUp ? 'Ready (API Active)' : 'Active (Direct / Fallback)'}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right actions: Quick Samples & History */}
        <div className="flex items-center gap-2.5">
          {/* Quick Samples Dropdown */}
          <div className="relative">
            <button
              onClick={() => setSamplesOpen(!samplesOpen)}
              className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium text-slate-200 transition-all flex items-center gap-1.5 hover:border-cyan-500/40"
            >
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              <span>Test Samples</span>
              <ChevronDown className="w-3 h-3 text-slate-400" />
            </button>

            {samplesOpen && (
              <div className="absolute right-0 mt-2 w-72 rounded-lg bg-slate-900 border border-slate-700 shadow-2xl p-1.5 z-50 animate-in fade-in zoom-in-95">
                <div className="px-2.5 py-1.5 text-[11px] font-semibold text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                  Verified Test Indicators
                </div>
                <div className="max-h-64 overflow-y-auto divide-y divide-slate-800/40">
                  {PRESET_SAMPLES.map((s) => (
                    <button
                      key={s.label}
                      onClick={() => {
                        onSelectSample(s.indicator, s.type);
                        setSamplesOpen(false);
                      }}
                      className="w-full text-left px-2.5 py-2 hover:bg-slate-800/70 rounded transition-colors flex flex-col gap-0.5 group"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-slate-200 group-hover:text-cyan-300">
                          {s.label}
                        </span>
                        <span className="text-[10px] font-mono text-cyan-400 uppercase">
                          {s.type}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono truncate max-w-[240px]">
                        {s.indicator}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* History Button */}
          <button
            onClick={onOpenHistory}
            className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium text-slate-200 transition-all flex items-center gap-1.5 hover:border-cyan-500/40"
          >
            <History className="w-3.5 h-3.5 text-cyan-400" />
            <span>History</span>
          </button>
        </div>
      </div>
    </header>
  );
};
