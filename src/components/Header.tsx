import React from 'react';
import {
  ShieldAlert,
  Radio,
  History,
  Sparkles,
  LogOut,
  UserCheck
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.js';

interface HeaderProps {
  onOpenHistory: () => void;
  providerHealth: Record<string, { configured: boolean; status: string }>;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenHistory,
  providerHealth
}) => {
  const { user, signOut } = useAuth();
  const providers = [
    { key: 'virustotal', label: 'VT', full: 'VirusTotal v3' },
    { key: 'hybrid_analysis', label: 'HA', full: 'Hybrid Analysis' },
    { key: 'malwarebazaar', label: 'MB', full: 'MalwareBazaar' },
    { key: 'abuseipdb', label: 'AB', full: 'AbuseIPDB' },
    { key: 'urlhaus', label: 'UH', full: 'URLhaus' },
    { key: 'urlscan', label: 'US', full: 'urlscan.io' },
    { key: 'alienvault_otx', label: 'OTX', full: 'AlienVault OTX' }
  ];

  const analystDisplayName = user?.displayName || user?.email?.split('@')[0] || 'SOC Analyst';

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
              Live Threat Triage & Intelligence Aggregation
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
                  title={`${p.full}: ${isUp ? 'Active & Ready' : 'Feed Ready'}`}
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
                    <p className="text-[10px] text-slate-400">Status: {isUp ? 'Active & Ready' : 'Fallback Intelligence Ready'}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right actions: History & User Info / Sign Out */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={onOpenHistory}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium text-slate-200 transition-all flex items-center gap-1.5 hover:border-cyan-500/40 cursor-pointer shadow-sm"
          >
            <History className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Investigation History</span>
            <span className="sm:hidden">History</span>
          </button>

          {/* Authenticated Analyst Badge & Sign Out */}
          {user && (
            <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
              <div className="flex items-center gap-2 py-1 px-2.5 rounded-lg bg-slate-900 border border-slate-800">
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={analystDisplayName}
                    className="w-5 h-5 rounded-full border border-cyan-400/40 object-cover"
                  />
                ) : (
                  <UserCheck className="w-4 h-4 text-cyan-400" />
                )}
                <div className="flex flex-col text-left">
                  <span className="text-xs font-semibold text-slate-200 truncate max-w-[120px] font-mono leading-none">
                    {analystDisplayName}
                  </span>
                  <span className="text-[9px] text-cyan-400 font-mono mt-0.5 leading-none">
                    SOC Analyst
                  </span>
                </div>
              </div>

              <button
                onClick={() => signOut()}
                title="Sign out of SOC console"
                className="p-2 rounded-lg bg-slate-800/80 hover:bg-rose-950/80 border border-slate-700 hover:border-rose-800 text-slate-400 hover:text-rose-300 transition-colors cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
