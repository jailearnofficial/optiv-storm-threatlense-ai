import React, { useState, useRef, useEffect } from 'react';
import {
  ShieldAlert,
  Radio,
  History,
  Sparkles,
  LogOut,
  UserCheck,
  Cable,
  ChevronDown,
  Key,
  ShieldCheck,
  Sliders
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.js';

interface HeaderProps {
  onOpenHistory: () => void;
  onOpenSiemSoar?: () => void;
  providerHealth: Record<string, { configured: boolean; status: string }>;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenHistory,
  onOpenSiemSoar,
  providerHealth
}) => {
  const { user, signOut } = useAuth();
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const profileMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target as Node)) {
        setProfileDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

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
    <header className="relative z-30 border-b border-slate-800/80 bg-[#0A0E17]/90 backdrop-blur-md px-4 lg:px-8 py-3.5 transition-all">
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

        {/* Right actions: History, SIEM/SOAR Button & Interactive Profile Menu */}
        <div className="flex items-center gap-2.5">
          {/* SIEM & SOAR Integration Quick Button */}
          {onOpenSiemSoar && (
            <button
              onClick={onOpenSiemSoar}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-950/80 to-slate-900 hover:from-cyan-900/90 hover:to-slate-800 border border-cyan-500/40 hover:border-cyan-400 text-xs font-medium text-cyan-200 transition-all flex items-center gap-1.5 cursor-pointer shadow-[0_0_12px_rgba(34,211,238,0.15)] group"
              title="Configure Enterprise SIEM & SOAR Connectors"
            >
              <Cable className="w-3.5 h-3.5 text-cyan-400 group-hover:rotate-12 transition-transform" />
              <span className="font-semibold">SIEM / SOAR</span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse ml-0.5" />
            </button>
          )}

          {/* Investigation History Button */}
          <button
            onClick={onOpenHistory}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium text-slate-200 transition-all flex items-center gap-1.5 hover:border-cyan-500/40 cursor-pointer shadow-sm"
          >
            <History className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Investigation History</span>
            <span className="sm:hidden">History</span>
          </button>

          {/* Authenticated Analyst Profile Menu */}
          {user && (
            <div className="relative pl-2 border-l border-slate-800" ref={profileMenuRef}>
              <button
                onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
                className="flex items-center gap-2 py-1 px-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer group"
                title="Analyst Profile & System Integrations"
              >
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
                  <span className="text-xs font-semibold text-slate-200 truncate max-w-[120px] font-mono leading-none group-hover:text-cyan-300">
                    {analystDisplayName}
                  </span>
                  <span className="text-[9px] text-cyan-400 font-mono mt-0.5 leading-none">
                    SOC Analyst
                  </span>
                </div>
                <ChevronDown
                  className={`w-3 h-3 text-slate-400 transition-transform ${
                    profileDropdownOpen ? 'rotate-180 text-cyan-400' : ''
                  }`}
                />
              </button>

              {/* Profile Dropdown Menu */}
              {profileDropdownOpen && (
                <div className="absolute right-0 mt-2 w-72 rounded-xl bg-[#0D131F] border border-slate-700/90 shadow-[0_10px_30px_rgba(0,0,0,0.7)] text-slate-200 py-2 z-50 animate-in fade-in duration-100">
                  {/* Analyst Details Ribbon */}
                  <div className="px-4 py-2.5 border-b border-slate-800 bg-slate-950/40">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#10B981]" />
                      <span className="text-xs font-bold text-slate-100 truncate">
                        {user.displayName || analystDisplayName}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                      {user.email}
                    </p>
                    <div className="mt-1.5 flex items-center gap-1.5">
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                        Tier-2 SOC Lead
                      </span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        Firebase Verified
                      </span>
                    </div>
                  </div>

                  {/* Integration Menu Items */}
                  <div className="p-1 space-y-0.5 text-xs font-medium">
                    {onOpenSiemSoar && (
                      <button
                        onClick={() => {
                          setProfileDropdownOpen(false);
                          onOpenSiemSoar();
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-cyan-950/60 hover:text-cyan-300 flex items-center justify-between transition-colors cursor-pointer group"
                      >
                        <div className="flex items-center gap-2.5">
                          <Cable className="w-4 h-4 text-cyan-400" />
                          <div>
                            <span className="block font-semibold">SIEM & SOAR Connectors</span>
                            <span className="text-[10px] text-slate-400 font-normal">
                              Sentinel, Splunk, XSOAR, Chronicle
                            </span>
                          </div>
                        </div>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                          Active
                        </span>
                      </button>
                    )}

                    {onOpenSiemSoar && (
                      <button
                        onClick={() => {
                          setProfileDropdownOpen(false);
                          onOpenSiemSoar();
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-800/80 hover:text-slate-100 flex items-center gap-2.5 transition-colors cursor-pointer"
                      >
                        <Key className="w-4 h-4 text-violet-400" />
                        <div>
                          <span className="block font-semibold">SOAR Webhook & API Keys</span>
                          <span className="text-[10px] text-slate-400 font-normal">
                            Headless Ingestion Endpoint
                          </span>
                        </div>
                      </button>
                    )}

                    <button
                      onClick={() => {
                        setProfileDropdownOpen(false);
                        onOpenHistory();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-800/80 hover:text-slate-100 flex items-center gap-2.5 transition-colors cursor-pointer"
                    >
                      <History className="w-4 h-4 text-cyan-400" />
                      <div>
                        <span className="block font-semibold">24-Hour Investigation Feed</span>
                        <span className="text-[10px] text-slate-400 font-normal">
                          Audit Trail & Case Cache
                        </span>
                      </div>
                    </button>
                  </div>

                  {/* Sign Out Action */}
                  <div className="p-1 pt-1.5 border-t border-slate-800/80 mt-1">
                    <button
                      onClick={() => {
                        setProfileDropdownOpen(false);
                        signOut();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-rose-950/60 hover:text-rose-300 text-slate-300 flex items-center gap-2.5 transition-colors cursor-pointer text-xs"
                    >
                      <LogOut className="w-4 h-4 text-rose-400" />
                      <span>Sign Out of Console</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
