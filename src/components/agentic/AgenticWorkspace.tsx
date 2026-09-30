import React, { useState, useEffect } from 'react';
import {
  Bot,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Play,
  RefreshCw,
  Terminal,
  Activity,
  Layers,
  Code2,
  Copy,
  Check,
  Lock,
  ArrowRight,
  Flame,
  Globe,
  Radio,
  Clock,
  Cpu,
  Server,
  Zap,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  Sliders,
  FileCode,
  LayoutGrid
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext.js';
import { authenticatedFetch } from '../../lib/apiClient.js';
import { AgenticMissionResult, AgentStep } from '../../types/agentic.js';

interface AgenticWorkspaceProps {
  onSwitchToClassic: () => void;
}

const PRESET_SCENARIOS = [
  {
    id: 'cobalt-strike',
    title: 'Cobalt Strike C2 Beacon & Memory Injection',
    indicator: '194.26.29.112',
    category: 'APT Infrastructure',
    description: 'Active HTTPS listener on port 4444 observed in brute-force reconnaissance.',
    badge: 'CRITICAL C2'
  },
  {
    id: 'lockbit-dropper',
    title: 'Weaponized DLL Stager (Reflective Injection)',
    indicator: 'a3f890b2c1d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abc',
    category: 'Ransomware Precursor',
    description: 'Packed executable with sleep evasion techniques targeting svchost.exe memory.',
    badge: 'HIGH RISK'
  },
  {
    id: 'spear-phish',
    title: 'Executive Credential Harvesting Domain',
    indicator: 'optiv-sso-auth-portal.com',
    category: 'Credential Access',
    description: 'Recently registered domain typosquatting enterprise identity portal.',
    badge: 'SUSPICIOUS'
  }
];

export const AgenticWorkspace: React.FC<AgenticWorkspaceProps> = ({ onSwitchToClassic }) => {
  const { user, isAdmin, userRole } = useAuth();
  const [targetInput, setTargetInput] = useState<string>('194.26.29.112');
  const [selectedScenario, setSelectedScenario] = useState<string>('cobalt-strike');
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [missionData, setMissionData] = useState<AgenticMissionResult | null>(null);
  const [activeTab, setActiveTab] = useState<'trace' | 'mitre' | 'rules' | 'containment'>('trace');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [executedActions, setExecutedActions] = useState<Record<string, boolean>>({});
  const initialRunRef = React.useRef<boolean>(false);

  // Auto-run initial investigation on first mount (guard against React strict-mode double-run)
  useEffect(() => {
    if (!initialRunRef.current) {
      initialRunRef.current = true;
      handleRunAgent('194.26.29.112', 'cobalt-strike');
    }
  }, []);

  const handleRunAgent = async (indicatorToRun: string, scenarioId?: string) => {
    setIsExecuting(true);
    try {
      const res = await authenticatedFetch('/api/agent/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: indicatorToRun || targetInput,
          scenarioId: scenarioId || selectedScenario,
          analystName: user?.displayName || 'Jai Kumar Singh P'
        })
      });

      if (res.ok) {
        const data = await res.json();
        setMissionData(data);
      }
    } catch (err) {
      console.error('Agentic execution error:', err);
    } finally {
      setIsExecuting(false);
    }
  };

  const handleCopy = (text: string, id: string) => {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(id);
      setTimeout(() => setCopiedKey(null), 2500);
    }
  };

  const handleExecuteContainment = (actionId: string) => {
    if (!isAdmin) return;
    setExecutedActions((prev) => ({ ...prev, [actionId]: true }));
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans pb-16">
      {/* Top Banner & Control Ribbon */}
      <div className="border-b border-cyan-500/20 bg-gradient-to-r from-slate-950 via-[#0a1226] to-slate-950 px-4 sm:px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="relative">
              <div className="w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.25)]">
                <Bot className="w-6 h-6 animate-pulse" />
              </div>
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
              </span>
            </div>

            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-lg font-bold text-slate-100 tracking-tight flex items-center gap-2">
                  <span>S.T.O.R.M Autonomous Agentic AI</span>
                  <span className="text-cyan-400 font-mono text-xs px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800">
                    ReAct Loop Active
                  </span>
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/30 flex items-center gap-1 font-semibold">
                  <Sparkles className="w-3 h-3 text-violet-400" />
                  Gemini 3.8 Multi-Agent Crew
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Autonomous SOC threat hunter & triage swarm · Dynamic tool execution with human-in-the-loop governance
              </p>
            </div>
          </div>

          {/* Mode Switcher Toggle Button */}
          <div className="flex items-center gap-2 self-end md:self-center">
            <button
              onClick={onSwitchToClassic}
              className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 hover:border-cyan-400 text-xs font-semibold text-cyan-300 flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(34,211,238,0.15)] group"
              title="Return to Classic SOC View"
            >
              <LayoutGrid className="w-4 h-4 text-cyan-400 group-hover:rotate-12 transition-transform" />
              <span>Switch to Classic SOC View</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Workspace */}
      <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Multi-Agent Crew Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            {
              name: 'S.T.O.R.M Orchestrator',
              role: 'Planning & Delegation',
              status: isExecuting ? 'Reasoning' : 'Standby / Ready',
              icon: '🤖',
              border: 'border-cyan-500/30',
              accent: 'text-cyan-400',
              desc: 'Deconstructs incoming IOCs into prioritized sub-tasks'
            },
            {
              name: 'Malware Forensics Agent',
              role: 'Dynamic Sandbox Detonation',
              status: isExecuting ? 'Hooking Syscalls' : 'Completed (3 Hooks)',
              icon: '🔬',
              border: 'border-emerald-500/30',
              accent: 'text-emerald-400',
              desc: 'Captures reflective DLL injection & memory evasion'
            },
            {
              name: 'Threat Hunter Agent',
              role: 'Graph Pivoting & ASN Traversal',
              status: isExecuting ? 'Traversing Graph' : 'Resolved (3 Linked FQDNs)',
              icon: '🌐',
              border: 'border-violet-500/30',
              accent: 'text-violet-400',
              desc: 'Identifies lateral C2 infrastructure and passive DNS clusters'
            },
            {
              name: 'Incident Commander',
              role: 'SOAR Containment & Rules',
              status: isExecuting ? 'Compiling Rules' : 'Staged (3 Playbooks)',
              icon: '🛡️',
              border: 'border-amber-500/30',
              accent: 'text-amber-400',
              desc: 'Maps MITRE techniques, generates Sigma/YARA & stages blocks'
            }
          ].map((agent, i) => (
            <div
              key={i}
              className={`p-3.5 rounded-xl bg-slate-900/70 border ${agent.border} flex flex-col justify-between shadow-lg relative overflow-hidden backdrop-blur-sm`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xl">{agent.icon}</span>
                  <div>
                    <span className="text-xs font-bold text-slate-100 block">{agent.name}</span>
                    <span className="text-[10px] text-slate-400 font-mono">{agent.role}</span>
                  </div>
                </div>
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded border flex items-center gap-1 font-semibold ${
                    isExecuting
                      ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/40 animate-pulse'
                      : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  {agent.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-2.5 leading-snug">{agent.desc}</p>
            </div>
          ))}
        </div>

        {/* Mission Launcher & Preset Scenarios */}
        <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                  Autonomous Mission Launcher
                </h2>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Input any live IP, hash, domain, or select a pre-configured threat simulation
              </p>
            </div>

            {/* Indicator Type Input & Run */}
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                placeholder="Enter IP, Hash, or Domain..."
                className="px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 font-mono text-xs text-cyan-300 focus:border-cyan-400 focus:outline-none w-full sm:w-64"
              />
              <button
                onClick={() => handleRunAgent(targetInput)}
                disabled={isExecuting}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs flex items-center gap-2 transition-all cursor-pointer disabled:opacity-50 shrink-0 shadow-[0_0_15px_rgba(34,211,238,0.25)]"
              >
                {isExecuting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Investigating...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    <span>Run Agent</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Preset Threat Scenarios */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-2">
            {PRESET_SCENARIOS.map((sc) => (
              <button
                key={sc.id}
                onClick={() => {
                  setSelectedScenario(sc.id);
                  setTargetInput(sc.indicator);
                  handleRunAgent(sc.indicator, sc.id);
                }}
                className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between group ${
                  targetInput === sc.indicator
                    ? 'bg-cyan-950/40 border-cyan-500/50 shadow-[0_0_12px_rgba(34,211,238,0.15)]'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="text-xs font-bold text-slate-200 group-hover:text-cyan-300">
                      {sc.title}
                    </span>
                    <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">
                      {sc.badge}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                    {sc.description}
                  </p>
                </div>
                <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
                  <span className="text-cyan-400 font-semibold truncate max-w-[180px]">
                    {sc.indicator}
                  </span>
                  <span className="text-slate-400 group-hover:translate-x-0.5 transition-transform flex items-center gap-0.5">
                    Select <ChevronRight className="w-3 h-3" />
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Mission Status Header */}
        {missionData && (
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-500 font-bold font-mono">
                {missionData.riskScore}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-slate-100">{missionData.verdict}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 font-semibold">
                    Risk Score: {missionData.riskScore}/100
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    Confidence: {(missionData.confidence * 100).toFixed(0)}%
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5 font-mono">
                  Actor: <span className="text-cyan-400">{missionData.threatActor}</span> · Malware: <span className="text-amber-400">{missionData.malwareFamily}</span> · Target: <span className="text-slate-200">{missionData.indicator}</span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1.5 self-end md:self-center font-mono text-xs">
              <button
                onClick={() => setActiveTab('trace')}
                className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                  activeTab === 'trace'
                    ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-bold'
                    : 'border-slate-800 text-slate-400 hover:bg-slate-800'
                }`}
              >
                ReAct Trace ({missionData.steps.length})
              </button>
              <button
                onClick={() => setActiveTab('mitre')}
                className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                  activeTab === 'mitre'
                    ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-bold'
                    : 'border-slate-800 text-slate-400 hover:bg-slate-800'
                }`}
              >
                MITRE Matrix ({missionData.mitreMatrix.length})
              </button>
              <button
                onClick={() => setActiveTab('rules')}
                className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                  activeTab === 'rules'
                    ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-bold'
                    : 'border-slate-800 text-slate-400 hover:bg-slate-800'
                }`}
              >
                Sigma & YARA
              </button>
              <button
                onClick={() => setActiveTab('containment')}
                className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer flex items-center gap-1 ${
                  activeTab === 'containment'
                    ? 'bg-rose-500/20 border-rose-500/50 text-rose-300 font-bold'
                    : 'border-slate-800 text-slate-400 hover:bg-slate-800'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                <span>Containment ({missionData.containmentActions.length})</span>
              </button>
            </div>
          </div>
        )}

        {/* Tab 1: Live ReAct Execution Trace */}
        {missionData && activeTab === 'trace' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Autonomous Cognitive Execution Trace (Thought ➔ Action ➔ Observation)
              </span>
              <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> All 5 Phases Autonomous
              </span>
            </div>

            <div className="space-y-3">
              {missionData.steps.map((st) => (
                <div
                  key={st.step}
                  className="p-4 rounded-xl bg-slate-900/90 border border-slate-800/90 shadow-md space-y-2.5 transition-all hover:border-slate-700"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 border-b border-slate-800/80 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-700 text-cyan-300 font-mono text-[10px] flex items-center justify-center font-bold">
                        {st.step}
                      </span>
                      <span className="text-xs font-bold text-slate-100">{st.agent}</span>
                      <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
                        {st.phase}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500">
                      Duration: {st.durationMs}ms
                    </span>
                  </div>

                  {/* Thought */}
                  <div className="space-y-1">
                    <div className="flex items-center gap-1.5 text-[11px] font-mono font-semibold text-cyan-300">
                      <Bot className="w-3.5 h-3.5" />
                      <span>THOUGHT:</span>
                    </div>
                    <p className="text-xs text-slate-300 pl-5 font-sans leading-relaxed">
                      {st.thought}
                    </p>
                  </div>

                  {/* Action / Tool Call */}
                  <div className="space-y-1 bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-violet-400 font-semibold flex items-center gap-1">
                        <Terminal className="w-3.5 h-3.5" />
                        <span>ACTION:</span>
                        <code className="text-cyan-300">{st.toolCall.name}</code>
                      </span>
                      <span className="text-[10px] text-slate-500">Tool Execution</span>
                    </div>
                    <pre className="text-[11px] text-slate-400 mt-1 overflow-x-auto">
                      {JSON.stringify(st.toolCall.arguments, null, 2)}
                    </pre>
                  </div>

                  {/* Observation */}
                  <div className="space-y-1">
                    <div className="flex items-center gap-1.5 text-[11px] font-mono font-semibold text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>OBSERVATION:</span>
                    </div>
                    <p className="text-xs text-slate-300 pl-5 font-sans leading-relaxed">
                      {st.observation}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 2: MITRE ATT&CK Matrix Alignment */}
        {missionData && activeTab === 'mitre' && (
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Mapped Adversary Kill-Chain Techniques ({missionData.mitreMatrix.length})
              </span>
              <span className="text-[10px] font-mono text-slate-400">
                Automated Correlation vs. MITRE v14
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {missionData.mitreMatrix.map((m, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                      {m.techniqueId}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 uppercase">
                      {m.tactic}
                    </span>
                  </div>
                  <span className="text-xs font-bold text-slate-100 block">
                    {m.techniqueName}
                  </span>
                  <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                    {m.evidence}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 3: Auto-Compiled Sigma & YARA Rules */}
        {missionData && activeTab === 'rules' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Sigma Rule */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                  <FileCode className="w-4 h-4" /> Synthesized Sigma Rule (SIEM Ingestion)
                </span>
                <button
                  onClick={() => handleCopy(missionData.synthesizedRules.sigmaRule, 'sigma')}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 flex items-center gap-1"
                >
                  {copiedKey === 'sigma' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'sigma' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 text-cyan-300 font-mono text-[11px] overflow-x-auto max-h-80 leading-relaxed">
                {missionData.synthesizedRules.sigmaRule}
              </pre>
            </div>

            {/* YARA Rule */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                  <Code2 className="w-4 h-4" /> Synthesized YARA Rule (Endpoint Memory)
                </span>
                <button
                  onClick={() => handleCopy(missionData.synthesizedRules.yaraRule, 'yara')}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 flex items-center gap-1"
                >
                  {copiedKey === 'yara' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'yara' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 text-emerald-300 font-mono text-[11px] overflow-x-auto max-h-80 leading-relaxed">
                {missionData.synthesizedRules.yaraRule}
              </pre>
            </div>
          </div>
        )}

        {/* Tab 4: Human-in-the-Loop SOAR Containment Center with RBAC */}
        {missionData && activeTab === 'containment' && (
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-500" />
                  <h3 className="text-sm font-bold text-slate-100 font-mono uppercase">
                    Autonomous SOAR Containment Playbooks (Staged)
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  High-impact network block and host isolation playbooks staged by Incident Commander agent
                </p>
              </div>

              {/* RBAC State Badge */}
              <div className="flex items-center gap-2">
                <span
                  className={`text-xs font-mono px-2.5 py-1 rounded-lg border font-bold flex items-center gap-1.5 ${
                    isAdmin
                      ? 'bg-amber-500/15 text-amber-400 border-amber-500/40'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {isAdmin ? (
                    <>
                      <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                      <span>Admin Authorized (Jai Kumar Singh P)</span>
                    </>
                  ) : (
                    <>
                      <Lock className="w-3.5 h-3.5 text-slate-400" />
                      <span>Restricted: Analyst Read-Only</span>
                    </>
                  )}
                </span>
              </div>
            </div>

            <div className="space-y-3">
              {missionData.containmentActions.map((act) => (
                <div
                  key={act.id}
                  className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-slate-100">{act.title}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 font-semibold">
                        {act.severity}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                        {act.platform}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono">
                      Action: <span className="text-slate-200">{act.action}</span> · Target: <span className="text-cyan-400">{act.target}</span>
                    </p>
                  </div>

                  <div className="flex items-center gap-2 self-end md:self-center">
                    {executedActions[act.id] ? (
                      <span className="px-3.5 py-1.5 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-mono flex items-center gap-1.5 font-bold">
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Dispatched to {act.platform}</span>
                      </span>
                    ) : isAdmin ? (
                      <button
                        onClick={() => handleExecuteContainment(act.id)}
                        className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold font-mono transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(244,63,94,0.3)] cursor-pointer"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>Approve & Execute</span>
                      </button>
                    ) : (
                      <button
                        disabled
                        className="px-3.5 py-1.5 rounded-lg bg-slate-800 text-slate-500 border border-slate-700 text-xs font-mono flex items-center gap-1.5 cursor-not-allowed"
                        title="Only Admin (Jai Kumar Singh P via Google) has permission to execute containment"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        <span>Admin Approval Required</span>
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
