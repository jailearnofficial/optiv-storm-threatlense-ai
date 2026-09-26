import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ChevronRight,
  Crosshair,
  Lock,
  Unlock,
  Radio,
  Terminal,
  FileCode,
  Zap,
  ArrowRight,
  CheckCircle2,
  ExternalLink,
  Info
} from 'lucide-react';
import { AIAnalysisVerdict, EvidenceObject, MitreAttackRecord } from '../../types/index.js';

interface CyberKillChainProps {
  analysis?: AIAnalysisVerdict | null;
  evidence?: EvidenceObject | null;
}

export interface KillChainStage {
  id: string;
  order: number;
  name: string;
  codename: string;
  description: string;
  iconName: string;
  status: 'active' | 'suspected' | 'mitigated' | 'unobserved';
  techniques: string[];
  evidenceTelemetry: string;
  mitigationPlaybook: string[];
}

export const CyberKillChain: React.FC<CyberKillChainProps> = ({ analysis, evidence }) => {
  const [selectedStageId, setSelectedStageId] = useState<string>('c2');

  const ruleScore =
    typeof evidence?.rule_score === 'number'
      ? evidence.rule_score
      : (evidence?.rule_score?.value ?? analysis?.risk_score ?? analysis?.confidence ?? 75);
  const isMalicious = ruleScore >= 70;
  const isSuspicious = ruleScore >= 35 && ruleScore < 70;

  // Map MITRE techniques and indicator data to the 7 Kill Chain stages
  const mitreList: MitreAttackRecord[] = analysis?.mitre_attack || [];
  const hasDelivery = mitreList.some((m: MitreAttackRecord) =>
    ['T1566', 'T1189', 'T1190', 'T1566.001', 'T1566.002'].includes(m.technique_id)
  );
  const hasExploitation = mitreList.some((m: MitreAttackRecord) =>
    ['T1203', 'T1059', 'T1059.004', 'T1068', 'T1210'].includes(m.technique_id)
  );
  const hasInstallation = mitreList.some((m: MitreAttackRecord) =>
    ['T1547', 'T1053', 'T1543', 'T1112', 'T1574'].includes(m.technique_id)
  );
  const hasC2 = mitreList.some((m: MitreAttackRecord) =>
    ['T1071', 'T1071.001', 'T1573', 'T1090', 'T1105'].includes(m.technique_id)
  );
  const hasActions = mitreList.some((m: MitreAttackRecord) =>
    ['T1486', 'T1041', 'T1048', 'T1490', 'T1485'].includes(m.technique_id)
  );

  const stages: KillChainStage[] = [
    {
      id: 'recon',
      order: 1,
      name: 'Reconnaissance',
      codename: 'STAGE 01 · TARGET ACQUISITION',
      description: 'Adversary probes perimeter infrastructure, harvests DNS records, and identifies unpatched public services.',
      iconName: 'crosshair',
      status: 'active',
      techniques: ['T1595 (Active Scanning)', 'T1596 (Search Open Technical Databases)', 'T1590 (Gather Victim Network Info)'],
      evidenceTelemetry: 'Shodan port banners and AbuseIPDB mass-scanning telemetry correlate with aggressive perimeter reconnaissance.',
      mitigationPlaybook: [
        'Block scanning origin IP subnet at external firewall / border router.',
        'Obfuscate public server headers and restrict perimeter exposure via Cloudflare / CDN.',
        'Review honeypot telemetry for targeted credential probes.'
      ]
    },
    {
      id: 'weaponization',
      order: 2,
      name: 'Weaponization',
      codename: 'STAGE 02 · PAYLOAD CRAFTING',
      description: 'Coupling automated exploit kits, malicious shellcode, and trojanized backdoors into deliverable packages.',
      iconName: 'zap',
      status: evidence?.indicator.type === 'hash' || isMalicious ? 'active' : 'suspected',
      techniques: ['T1587 (Develop Capabilities)', 'T1588 (Obtain Capabilities)', 'T1608 (Stage Capabilities)'],
      evidenceTelemetry: 'Hybrid Analysis sandbox confirms compiled executable with packed entropy and anti-analysis evasion routines.',
      mitigationPlaybook: [
        'Deploy EDR heuristic memory inspection to intercept packed PE loaders.',
        'Update endpoint anti-malware signatures with verified SHA-256 hash.',
        'Quarantine related file attachments across Microsoft 365 / Google Workspace.'
      ]
    },
    {
      id: 'delivery',
      order: 3,
      name: 'Delivery',
      codename: 'STAGE 03 · PERIMETER INGRESS',
      description: 'Transmitting the weaponized payload to the victim environment via spearphishing, drive-by downloads, or watering holes.',
      iconName: 'radio',
      status: hasDelivery || evidence?.indicator.type === 'url' ? 'active' : 'suspected',
      techniques: ['T1566.002 (Spearphishing Link)', 'T1189 (Drive-by Compromise)', 'T1190 (Exploit Public-Facing App)'],
      evidenceTelemetry: 'URLhaus and urlscan.io detected active payload delivery mechanisms redirecting to hostile landing pages.',
      mitigationPlaybook: [
        'Blacklist destination FQDN/URL in secure web gateways (Zscaler, Cisco Umbrella).',
        'Purge inbound email messages matching the sender domain or attachment name.',
        'Revoke active browser sessions for users who navigated to the indicator.'
      ]
    },
    {
      id: 'exploitation',
      order: 4,
      name: 'Exploitation',
      codename: 'STAGE 04 · EXECUTION & BREACH',
      description: 'Triggering remote code execution or client-side vulnerability to execute arbitrary instructions.',
      iconName: 'unlock',
      status: hasExploitation || isMalicious ? 'active' : 'unobserved',
      techniques: ['T1203 (Exploitation for Client Execution)', 'T1059.004 (Unix Shell)', 'T1059.001 (PowerShell)'],
      evidenceTelemetry: 'Falcon Sandbox execution tree confirms spawned cmd.exe/bash subprocess with encoded parameters.',
      mitigationPlaybook: [
        'Isolate compromised endpoint host from local corporate subnet via EDR.',
        'Kill parent and spawned rogue processes; preserve memory dump for forensics.',
        'Enforce AppLocker / Software Restriction Policies to block script interpreters.'
      ]
    },
    {
      id: 'installation',
      order: 5,
      name: 'Installation',
      codename: 'STAGE 05 · HOST PERSISTENCE',
      description: 'Establishing persistent footprint on target host to survive system reboots and maintain covert presence.',
      iconName: 'lock',
      status: hasInstallation || isMalicious ? 'active' : 'suspected',
      techniques: ['T1547.001 (Registry Run Keys)', 'T1053 (Scheduled Task/Job)', 'T1543 (Create or Modify System Process)'],
      evidenceTelemetry: 'Registry run key hooks and scheduled cron triggers identified in sandbox dynamic behavioral trace.',
      mitigationPlaybook: [
        'Remove persistence hooks: delete malicious Scheduled Tasks and Run/RunOnce keys.',
        'Verify integrity of system binary hashes (SFC / scannow or RPM verify).',
        'Initiate full host reimaging if kernel-level rootkit presence is confirmed.'
      ]
    },
    {
      id: 'c2',
      order: 6,
      name: 'Command & Control',
      codename: 'STAGE 06 · ADVERSARY BEACONING',
      description: 'Establishing encrypted two-way communication channel between infected host and threat actor infrastructure.',
      iconName: 'radio',
      status: hasC2 || evidence?.indicator.type === 'ip' ? 'active' : isMalicious ? 'active' : 'suspected',
      techniques: ['T1071.001 (Web Protocols C2)', 'T1573 (Encrypted Channel)', 'T1090 (Proxy / TOR Relay)'],
      evidenceTelemetry: 'AlienVault OTX and GreyNoise confirm indicator as known Cobalt Strike C2 listener or TOR exit relay.',
      mitigationPlaybook: [
        'Null-route (Blackhole) C2 destination IP on edge firewalls and BGP routing tables.',
        'Deploy SSL/TLS deep packet inspection to detect beacon jitter and heartbeat regularity.',
        'Sinkhole associated DNS domains to redirect beacon traffic to an internal honeypot.'
      ]
    },
    {
      id: 'actions',
      order: 7,
      name: 'Actions on Objectives',
      codename: 'STAGE 07 · EXFILTRATION & IMPACT',
      description: 'Adversary achieves mission goals: data exfiltration, extortion encryption, or lateral destruction.',
      iconName: 'shieldAlert',
      status: hasActions || isMalicious ? 'active' : 'mitigated',
      techniques: ['T1486 (Data Encrypted for Impact)', 'T1041 (Exfiltration Over C2)', 'T1490 (Inhibit System Recovery)'],
      evidenceTelemetry: 'Multi-engine consensus classifies artifact as extortion ransomware / automated exfiltration kit.',
      mitigationPlaybook: [
        'Enforce Emergency Data Loss Prevention (DLP) egress chokeholds on cloud uploads.',
        'Lock enterprise Active Directory accounts exhibiting sudden mass file touch activity.',
        'Trigger immutable offline backup restoration protocols.'
      ]
    }
  ];

  const currentStage = stages.find((s) => s.id === selectedStageId) || stages[5];

  return (
    <div className="rounded-2xl border border-cyan-500/30 bg-[#070B14] p-4 sm:p-5 relative overflow-hidden shadow-[0_0_40px_rgba(34,211,238,0.1)]">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.2)]">
            <Zap className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold tracking-wider uppercase text-slate-100 flex items-center gap-1.5">
                <span>Lockheed Martin 7-Stage Cyber Kill-Chain</span>
                <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 border border-rose-800/80 text-rose-300">
                Attack Pipeline Intercept
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Interactive intrusion pipeline correlating observed provider evidence and containment actions.
            </p>
          </div>
        </div>

        {/* Global Progress Indicator */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-slate-400">Pipeline Penetration:</span>
          <div className="w-32 h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full transition-all duration-500 ${
                isMalicious
                  ? 'w-[85%] bg-gradient-to-r from-amber-500 to-rose-500'
                  : 'w-[45%] bg-gradient-to-r from-cyan-500 to-amber-500'
              }`}
            />
          </div>
          <span className="font-bold text-rose-400">
            {isMalicious ? 'Stage 6 / 7 (C2 ACTIVE)' : 'Stage 3 / 7 (DELIVERY)'}
          </span>
        </div>
      </div>

      {/* The 7-Stage Horizontal / Grid Pipeline Conduits */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 mb-5">
        {stages.map((stage, idx) => {
          const isSelected = stage.id === selectedStageId;
          const isActive = stage.status === 'active';
          const isSuspected = stage.status === 'suspected';

          return (
            <button
              key={stage.id}
              onClick={() => setSelectedStageId(stage.id)}
              className={`relative p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between group ${
                isSelected
                  ? 'bg-slate-900 border-cyan-400 shadow-[0_0_20px_rgba(34,211,238,0.25)] ring-1 ring-cyan-400'
                  : isActive
                  ? 'bg-slate-950/80 border-rose-800/80 hover:border-rose-600'
                  : isSuspected
                  ? 'bg-slate-950/70 border-amber-800/60 hover:border-amber-600'
                  : 'bg-slate-950/40 border-slate-800/80 opacity-60 hover:opacity-100'
              }`}
            >
              {/* Top Step Number & Status Beacon */}
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-[10px] text-slate-400 font-bold">
                  0{stage.order}
                </span>
                <span
                  className={`w-2 h-2 rounded-full ${
                    isActive
                      ? 'bg-rose-500 shadow-[0_0_8px_#f43f5e] animate-pulse'
                      : isSuspected
                      ? 'bg-amber-400'
                      : 'bg-slate-600'
                  }`}
                />
              </div>

              {/* Stage Name */}
              <div>
                <div className="font-bold text-xs text-slate-100 group-hover:text-cyan-300 transition-colors leading-tight mb-1">
                  {stage.name}
                </div>
                <span
                  className={`text-[9px] font-mono uppercase px-1.5 py-0.2 rounded inline-block ${
                    isActive
                      ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                      : isSuspected
                      ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                      : 'bg-slate-900 text-slate-400 border border-slate-800'
                  }`}
                >
                  {stage.status}
                </span>
              </div>

              {/* Arrow Connector Indicator for all except last */}
              {idx < stages.length - 1 && (
                <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 z-20 text-slate-600 group-hover:text-cyan-400 pointer-events-none">
                  <ChevronRight className="w-3.5 h-3.5" />
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Selected Stage Interactive Deep-Dive Drawer */}
      <div className="p-4 sm:p-5 rounded-xl bg-slate-950 border border-slate-800/90 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <span
              className={`p-2 rounded-lg ${
                currentStage.status === 'active'
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                  : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
              }`}
            >
              <Crosshair className="w-5 h-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-bold text-slate-100">
                  {currentStage.name}
                </h4>
                <span className="font-mono text-[10px] text-slate-400 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                  {currentStage.codename}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">{currentStage.description}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-slate-400">Intrusion Status:</span>
            <span
              className={`text-xs font-mono font-bold px-2.5 py-1 rounded-md uppercase ${
                currentStage.status === 'active'
                  ? 'bg-rose-950 border border-rose-700 text-rose-300'
                  : currentStage.status === 'suspected'
                  ? 'bg-amber-950 border border-amber-700 text-amber-300'
                  : 'bg-slate-900 border border-slate-700 text-slate-300'
              }`}
            >
              {currentStage.status === 'active' ? '⚠️ Active Intrusion Detected' : currentStage.status}
            </span>
          </div>
        </div>

        {/* 2-Column: Observed Provider Telemetry vs Mitigation Containment Playbook */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Column 1: Evidence & Associated MITRE ATT&CK Techniques */}
          <div className="p-3.5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-3">
            <div>
              <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold block mb-1">
                Observed Provider Telemetry & Forensics
              </span>
              <p className="text-slate-300 leading-relaxed">
                {currentStage.evidenceTelemetry}
              </p>
            </div>

            <div>
              <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block mb-1.5">
                Associated MITRE ATT&CK Techniques
              </span>
              <div className="flex flex-wrap gap-1.5">
                {currentStage.techniques.map((tech) => (
                  <span
                    key={tech}
                    className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-cyan-800/80"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Column 2: Recommended Incident Containment Actions */}
          <div className="p-3.5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-2">
            <span className="text-[10px] font-mono uppercase text-emerald-400 font-bold block mb-1">
              Active SOC Containment Playbook
            </span>
            <div className="space-y-1.5">
              {currentStage.mitigationPlaybook.map((step, idx) => (
                <div key={idx} className="flex items-start gap-2 text-slate-300 text-[11px]">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{step}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
