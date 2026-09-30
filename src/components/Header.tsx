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
  Sliders,
  Globe,
  Crosshair,
  Sun,
  Moon,
  Bot
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.js';
import { useTheme } from '../context/ThemeContext.js';

interface HeaderProps {
  onOpenHistory: () => void;
  onOpenSiemSoar?: () => void;
  onOpenApiKeyModal?: () => void;
  onResetToFreshWorkspace?: () => void;
  activeSiemCount?: number;
  providerHealth: Record<string, { configured: boolean; status: string }>;
  onToggleCyberWarfare?: () => void;
  isCyberWarfareActive?: boolean;
  isAgenticMode?: boolean;
  onToggleAgenticMode?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenHistory,
  onOpenSiemSoar,
  onOpenApiKeyModal,
  onResetToFreshWorkspace,
  activeSiemCount = 0,
  providerHealth,
  onToggleCyberWarfare,
  isCyberWarfareActive = false,
  isAgenticMode = false,
  onToggleAgenticMode
}) => {
  const { user, isAdmin, userRole, signOut } = useAuth();
  const { theme, toggleTheme } = useTheme();
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
        <div
          onClick={onResetToFreshWorkspace}
          className={`flex items-center gap-3.5 ${
            onResetToFreshWorkspace ? 'cursor-pointer hover:opacity-90 transition-opacity' : ''
          }`}
          title={onResetToFreshWorkspace ? 'Reset to Fresh Investigation Workspace' : undefined}
        >
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
        <div className="flex items-center gap-2">
          {/* Autonomous Agentic AI Mode Switcher Toggle Button */}
          {onToggleAgenticMode && (
            <button
              onClick={onToggleAgenticMode}
              className={`px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer shadow-sm group ${
                isAgenticMode
                  ? 'bg-gradient-to-r from-violet-950 via-slate-900 to-cyan-950 border-violet-400 text-violet-200 shadow-[0_0_15px_rgba(167,139,250,0.3)]'
                  : 'bg-slate-900/90 hover:bg-slate-850 border-slate-700/80 text-slate-300 hover:text-violet-300 hover:border-violet-500/50'
              }`}
              title="Toggle Autonomous Agentic AI Investigation Mode"
            >
              <Bot className={`w-3.5 h-3.5 ${isAgenticMode ? 'text-violet-400 animate-pulse' : 'text-slate-400 group-hover:text-violet-400'}`} />
              <span className="hidden sm:inline">Agentic AI</span>
              <span
                className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-bold ${
                  isAgenticMode
                    ? 'bg-violet-500/20 text-violet-300 border-violet-500/40'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                {isAgenticMode ? 'ON' : 'OFF'}
              </span>
            </button>
          )}

          {/* Cyber Warfare Visuals HUD Button */}
          {onToggleCyberWarfare && (
            <button
              onClick={onToggleCyberWarfare}
              className={`px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer shadow-sm group ${
                isCyberWarfareActive
                  ? 'bg-gradient-to-r from-cyan-950 via-slate-900 to-rose-950/80 border-cyan-400 text-cyan-200 shadow-[0_0_15px_rgba(34,211,238,0.25)]'
                  : 'bg-slate-900/90 hover:bg-slate-850 border-slate-700/80 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/50'
              }`}
              title="Toggle Cyber Threat Intelligence Warfare Visuals (Globe, Radar & Kill-Chain)"
            >
              <Globe className="w-3.5 h-3.5 text-cyan-400 group-hover:rotate-45 transition-transform" />
              <span className="hidden md:inline">Cyber Warfare HUD</span>
              <span className="md:hidden">Warfare</span>
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  isCyberWarfareActive ? 'bg-cyan-400 animate-ping' : 'bg-slate-500'
                }`}
              />
            </button>
          )}

          {/* SIEM & SOAR Integration Quick Button (Restricted to Admin Only) */}
          {isAdmin && onOpenSiemSoar && (
            <button
              onClick={onOpenSiemSoar}
              className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-all flex items-center gap-1.5 cursor-pointer shadow-sm group ${
                activeSiemCount > 0
                  ? 'bg-gradient-to-r from-cyan-950/80 to-slate-900 hover:from-cyan-900/90 hover:to-slate-800 border-cyan-500/40 hover:border-cyan-400 text-cyan-200 shadow-[0_0_12px_rgba(34,211,238,0.15)]'
                  : 'bg-slate-900/90 hover:bg-slate-800 border-slate-700/80 hover:border-slate-600 text-slate-300'
              }`}
              title="Configure Enterprise SIEM & SOAR Connectors (Admin Access)"
            >
              <Cable className="w-3.5 h-3.5 text-cyan-400 group-hover:rotate-12 transition-transform" />
              <span className="font-semibold">SIEM / SOAR</span>
              {activeSiemCount > 0 ? (
                <span className="flex items-center gap-1 font-mono text-[10px] text-emerald-300 bg-emerald-950/80 px-1.5 py-0.2 rounded border border-emerald-800/80 ml-0.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  {activeSiemCount}
                </span>
              ) : (
                <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700 ml-0.5">
                  Admin
                </span>
              )}
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
                  <span className={`text-[9px] font-mono mt-0.5 leading-none ${isAdmin ? 'text-amber-400 font-bold' : 'text-cyan-400'}`}>
                    {isAdmin ? 'SOC Admin' : 'SOC Analyst'}
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
                <div className="absolute right-0 mt-2 w-76 rounded-xl bg-white dark:bg-[#0D131F] border border-slate-200 dark:border-slate-700/90 shadow-[0_10px_30px_rgba(0,0,0,0.3)] dark:shadow-[0_10px_30px_rgba(0,0,0,0.7)] text-slate-800 dark:text-slate-200 py-2 z-50 animate-in fade-in duration-100">
                  {/* Analyst Details Ribbon */}
                  <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isAdmin ? 'bg-amber-400 shadow-[0_0_6px_#F59E0B]' : 'bg-emerald-400 shadow-[0_0_6px_#10B981]'}`} />
                      <span className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">
                        {user.displayName || analystDisplayName}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono truncate mt-0.5">
                      {user.email}
                    </p>
                    <div className="mt-1.5 flex items-center gap-1.5 flex-wrap">
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded font-bold border ${
                        isAdmin
                          ? 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/40 shadow-sm'
                          : 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                      }`}>
                        {isAdmin ? 'SOC Admin (Full Access)' : 'SOC Analyst'}
                      </span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                        {user.providerData?.some(p => p.providerId === 'google.com') ? 'Google Auth' : 'Password Auth'}
                      </span>
                    </div>
                  </div>

                  {/* Appearance & Theme Selector (Moved under user profile) */}
                  <div className="px-3.5 py-2.5 border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-950/30">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                        Appearance & Theme
                      </span>
                      <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 font-semibold">
                        {theme === 'light' ? 'Light Active' : 'Dark Active'}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          if (theme !== 'light') toggleTheme();
                        }}
                        className={`px-2.5 py-1.5 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                          theme === 'light'
                            ? 'bg-amber-500/20 border-amber-500/60 text-amber-800 dark:text-amber-300 shadow-sm'
                            : 'border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'
                        }`}
                      >
                        <Sun className="w-3.5 h-3.5 text-amber-500" />
                        <span>Light Mode</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          if (theme !== 'dark') toggleTheme();
                        }}
                        className={`px-2.5 py-1.5 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                          theme === 'dark'
                            ? 'bg-cyan-500/25 border-cyan-500/60 text-cyan-200 shadow-sm'
                            : 'border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'
                        }`}
                      >
                        <Moon className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Dark Mode</span>
                      </button>
                    </div>
                  </div>

                  {/* Integration Menu Items */}
                  <div className="p-1 space-y-0.5 text-xs font-medium">
                    {/* Autonomous Agentic AI SOC Mode */}
                    {onToggleAgenticMode && (
                      <button
                        onClick={() => {
                          setProfileDropdownOpen(false);
                          onToggleAgenticMode();
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-violet-500/10 hover:text-violet-600 dark:hover:text-violet-300 flex items-center justify-between transition-colors cursor-pointer group"
                      >
                        <div className="flex items-center gap-2.5">
                          <Bot className="w-4 h-4 text-violet-400 group-hover:scale-110 transition-transform" />
                          <div>
                            <span className="block font-semibold">Autonomous Agentic AI SOC</span>
                            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                              Multi-Agent ReAct Hunter & Triage Swarm
                            </span>
                          </div>
                        </div>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                            isAgenticMode
                              ? 'bg-violet-950 text-violet-300 border-violet-800'
                              : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700'
                          }`}
                        >
                          {isAgenticMode ? 'Active' : 'Switch'}
                        </span>
                      </button>
                    )}

                    {/* Cyber Warfare HUD */}
                    {onToggleCyberWarfare && (
                      <button
                        onClick={() => {
                          setProfileDropdownOpen(false);
                          onToggleCyberWarfare();
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-cyan-500/10 hover:text-cyan-600 dark:hover:text-cyan-300 flex items-center justify-between transition-colors cursor-pointer group"
                      >
                        <div className="flex items-center gap-2.5">
                          <Globe className="w-4 h-4 text-cyan-500 group-hover:rotate-45 transition-transform" />
                          <div>
                            <span className="block font-semibold">Cyber Warfare Visuals HUD</span>
                            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                              Attack Globe, 360° Radar & Kill-Chain
                            </span>
                          </div>
                        </div>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                            isCyberWarfareActive
                              ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                              : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700'
                          }`}
                        >
                          {isCyberWarfareActive ? 'Active' : 'Open'}
                        </span>
                      </button>
                    )}

                    {/* SIEM & SOAR Connectors (RESTRICTED TO ADMIN ONLY) */}
                    {isAdmin && onOpenSiemSoar && (
                      <button
                        onClick={() => {
                          setProfileDropdownOpen(false);
                          onOpenSiemSoar();
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-cyan-500/10 hover:text-cyan-600 dark:hover:text-cyan-300 flex items-center justify-between transition-colors cursor-pointer group"
                      >
                        <div className="flex items-center gap-2.5">
                          <Cable className="w-4 h-4 text-cyan-500" />
                          <div>
                            <div className="flex items-center gap-1.5">
                              <span className="block font-semibold">SIEM & SOAR Connectors</span>
                              <span className="text-[9px] font-mono px-1 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30">
                                Admin
                              </span>
                            </div>
                            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                              Sentinel, Splunk, XSOAR, Chronicle
                            </span>
                          </div>
                        </div>
                        {activeSiemCount > 0 ? (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-300 border border-emerald-500/30">
                            {activeSiemCount} Active
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                            Configure
                          </span>
                        )}
                      </button>
                    )}

                    {/* Create & Manage API Keys (RESTRICTED TO ADMIN ONLY) */}
                    {isAdmin && onOpenApiKeyModal && (
                      <button
                        onClick={() => {
                          setProfileDropdownOpen(false);
                          onOpenApiKeyModal();
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-violet-500/10 hover:text-violet-600 dark:hover:text-violet-300 flex items-center justify-between transition-colors cursor-pointer group"
                      >
                        <div className="flex items-center gap-2.5">
                          <Key className="w-4 h-4 text-violet-500" />
                          <div>
                            <div className="flex items-center gap-1.5">
                              <span className="block font-semibold">Create & Manage API Keys</span>
                              <span className="text-[9px] font-mono px-1 rounded bg-violet-500/20 text-violet-600 dark:text-violet-400 border border-violet-500/30 font-semibold">
                                Admin
                              </span>
                            </div>
                            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                              Generate Ingest Tokens & Webhooks
                            </span>
                          </div>
                        </div>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-600 dark:text-violet-300 border border-violet-500/30">
                          Create
                        </span>
                      </button>
                    )}

                    {/* Investigation History (All Analysts) */}
                    <button
                      onClick={() => {
                        setProfileDropdownOpen(false);
                        onOpenHistory();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 text-slate-700 dark:text-slate-300 flex items-center gap-2.5 transition-colors cursor-pointer"
                    >
                      <History className="w-4 h-4 text-cyan-500" />
                      <div>
                        <span className="block font-semibold">24-Hour Investigation Feed</span>
                        <span className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                          Audit Trail & Case Cache
                        </span>
                      </div>
                    </button>
                  </div>

                  {/* Sign Out Action */}
                  <div className="p-1 pt-1.5 border-t border-slate-200 dark:border-slate-800/80 mt-1">
                    <button
                      onClick={() => {
                        setProfileDropdownOpen(false);
                        signOut();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-rose-500/10 text-rose-600 dark:text-rose-400 flex items-center gap-2.5 transition-colors cursor-pointer text-xs font-semibold"
                    >
                      <LogOut className="w-4 h-4 text-rose-500" />
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
