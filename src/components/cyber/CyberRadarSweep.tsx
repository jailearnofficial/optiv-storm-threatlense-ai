import React, { useState, useEffect, useRef } from 'react';
import {
  Radio,
  Crosshair,
  Volume2,
  VolumeX,
  RotateCw,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Layers,
  Activity,
  CheckCircle2,
  ExternalLink
} from 'lucide-react';
import { ProviderResult } from '../../types/index.js';

interface CyberRadarSweepProps {
  providers?: ProviderResult[];
  ruleScore?: number;
  indicator?: string;
  indicatorType?: string;
  onSelectProvider?: (provider: ProviderResult) => void;
}

interface RadarTarget {
  id: string;
  name: string;
  displayName: string;
  angleDeg: number; // 0 to 360
  distance: number; // 0 to 1 radius
  status: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  maliciousCount: number;
  totalEngines?: number;
  category: string;
  providerRef?: ProviderResult;
}

// Fixed radar angle coordinates for the 7 primary threat intel feeds
const RADAR_LAYOUT: Record<string, { angle: number; displayName: string; category: string }> = {
  virustotal: { angle: 35, displayName: 'VirusTotal', category: 'Multiscanner & Sandboxes' },
  hybrid_analysis: { angle: 85, displayName: 'Hybrid Analysis', category: 'CrowdStrike Falcon Sandbox' },
  alienvault_otx: { angle: 140, displayName: 'AlienVault OTX', category: 'Threat Pulses & Indicators' },
  greynoise: { angle: 195, displayName: 'GreyNoise', category: 'Internet Noise & Mass Scanners' },
  abuseipdb: { angle: 245, displayName: 'AbuseIPDB', category: 'IP Blacklists & Abuse Reports' },
  urlscan: { angle: 295, displayName: 'urlscan.io', category: 'Web Page Behavioral DOM' },
  shodan: { angle: 345, displayName: 'Shodan', category: 'Port Scan & Vulnerability Banner' }
};

export const CyberRadarSweep: React.FC<CyberRadarSweepProps> = ({
  providers = [],
  ruleScore = 0,
  indicator = '185.220.101.5',
  indicatorType = 'ip',
  onSelectProvider
}) => {
  const [rotationAngle, setRotationAngle] = useState<number>(0);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(false);
  const [selectedTarget, setSelectedTarget] = useState<RadarTarget | null>(null);
  const [sweepSpeed, setSweepSpeed] = useState<'normal' | 'fast' | 'slow'>('normal');

  const audioCtxRef = useRef<AudioContext | null>(null);
  const lastBeepAngleRef = useRef<number>(-1);

  // Map providers to radar targets
  const radarTargets: RadarTarget[] = Object.keys(RADAR_LAYOUT).map((key) => {
    const layout = RADAR_LAYOUT[key];
    const prov = providers.find((p) => p.name === key);

    let status: RadarTarget['status'] = 'unknown';
    let maliciousCount = 0;
    let distance = 0.65; // default distance from center

    if (prov && prov.status === 'ok') {
      const mal = prov.score?.malicious || 0;
      const susp = prov.score?.suspicious || 0;
      const threatScore = prov.score?.threat_score || 0;
      const abuseConf = prov.score?.abuse_confidence || 0;
      const pulseCount = prov.score?.pulse_count || 0;

      if (mal > 0 || threatScore >= 70 || abuseConf >= 70 || pulseCount > 5) {
        status = 'malicious';
        maliciousCount = mal || Math.round(threatScore / 10) || 1;
        distance = 0.82; // Farther out for severe threats
      } else if (susp > 0 || threatScore >= 35 || abuseConf >= 25 || pulseCount > 0) {
        status = 'suspicious';
        maliciousCount = susp || 1;
        distance = 0.68;
      } else if (prov.score?.harmless !== undefined || threatScore < 20) {
        status = 'clean';
        distance = 0.45;
      } else {
        status = 'clean';
        distance = 0.5;
      }
    }

    const totalEngines =
      prov?.score?.undetected !== undefined && prov?.score?.malicious !== undefined
        ? (prov.score.malicious || 0) +
          (prov.score.suspicious || 0) +
          (prov.score.harmless || 0) +
          (prov.score.undetected || 0)
        : undefined;

    return {
      id: key,
      name: key,
      displayName: layout.displayName,
      angleDeg: layout.angle,
      distance: distance,
      status: status,
      maliciousCount: maliciousCount,
      totalEngines: totalEngines,
      category: layout.category,
      providerRef: prov
    };
  });

  // Synthesize gentle military sonar radar beep when sweep passes a malicious target
  const triggerSonarPing = (freq = 880) => {
    if (!soundEnabled) return;
    try {
      if (!audioCtxRef.current) {
        audioCtxRef.current = new (window.AudioContext || (window as any).webkitAudioContext)();
      }
      const ctx = audioCtxRef.current;
      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(freq * 0.5, ctx.currentTime + 0.12);

      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.16);
    } catch {
      // Audio not permitted or supported
    }
  };

  // Continuous 360° radar sweep animation loop
  useEffect(() => {
    let animId: number;
    let step = sweepSpeed === 'fast' ? 2.5 : sweepSpeed === 'slow' ? 0.8 : 1.5;

    const animate = () => {
      setRotationAngle((prev) => {
        const next = (prev + step) % 360;

        // Check if sweeping through any malicious target
        const currentTarget = radarTargets.find((t) => Math.abs(t.angleDeg - next) < 3);
        if (currentTarget && Math.floor(next / 10) !== lastBeepAngleRef.current) {
          lastBeepAngleRef.current = Math.floor(next / 10);
          if (currentTarget.status === 'malicious') {
            triggerSonarPing(1100);
          } else if (currentTarget.status === 'suspicious') {
            triggerSonarPing(750);
          }
        }

        return next;
      });
      animId = requestAnimationFrame(animate);
    };

    animId = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animId);
  }, [sweepSpeed, soundEnabled, radarTargets]);

  const radarSize = 360;
  const center = radarSize / 2;
  const radius = center - 20;

  return (
    <div className="rounded-2xl border border-cyan-500/30 bg-[#070B14] p-4 sm:p-5 relative overflow-hidden shadow-[0_0_40px_rgba(34,211,238,0.1)]">
      {/* Top HUD Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.2)]">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold tracking-wider uppercase text-slate-100 flex items-center gap-1.5">
                <span>360° Threat Intelligence Radar Scanner</span>
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300">
                Bearing & Range HUD
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Sweeping 7 parallel intelligence feeds with dynamic radial bearing coordinates.
            </p>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 text-xs">
          {/* Audio Sonar Toggle */}
          <button
            onClick={() => {
              setSoundEnabled(!soundEnabled);
              if (!soundEnabled) triggerSonarPing(880);
            }}
            className={`px-2.5 py-1.5 rounded-lg border font-mono flex items-center gap-1.5 transition-colors cursor-pointer ${
              soundEnabled
                ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
            title="Toggle audio sonar telemetry pings"
          >
            {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-cyan-400" /> : <VolumeX className="w-3.5 h-3.5" />}
            <span>{soundEnabled ? 'Sonar Audio ON' : 'Audio Muted'}</span>
          </button>

          {/* Speed Selector */}
          <button
            onClick={() =>
              setSweepSpeed((prev) => (prev === 'normal' ? 'fast' : prev === 'fast' ? 'slow' : 'normal'))
            }
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono hover:border-slate-700 cursor-pointer"
          >
            <span>Scan: {sweepSpeed.toUpperCase()}</span>
          </button>
        </div>
      </div>

      {/* Main Radar Display Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
        {/* Left / Center: Circular 360° Radar Canvas */}
        <div className="lg:col-span-7 flex flex-col items-center justify-center relative">
          <div className="relative w-[340px] h-[340px] sm:w-[360px] sm:h-[360px] rounded-full border border-cyan-500/40 bg-[#040810] shadow-[0_0_50px_rgba(34,211,238,0.15)] flex items-center justify-center overflow-hidden">
            {/* Concentric Range Rings */}
            <div className="absolute w-[80px] h-[80px] rounded-full border border-cyan-500/15" />
            <div className="absolute w-[160px] h-[160px] rounded-full border border-cyan-500/20" />
            <div className="absolute w-[240px] h-[240px] rounded-full border border-cyan-500/25" />
            <div className="absolute w-[320px] h-[320px] rounded-full border border-cyan-500/30" />

            {/* Crosshair Axes */}
            <div className="absolute w-full h-[1px] bg-cyan-500/25" />
            <div className="absolute h-full w-[1px] bg-cyan-500/25" />
            <div className="absolute w-full h-[1px] bg-cyan-500/10 rotate-45" />
            <div className="absolute w-full h-[1px] bg-cyan-500/10 -rotate-45" />

            {/* Rotating 360° Radar Sweep Beam & Glowing Sweep Wedge */}
            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                transform: `rotate(${rotationAngle}deg)`,
                transformOrigin: 'center center'
              }}
            >
              {/* Sweep Line */}
              <div className="absolute top-0 left-1/2 w-[2px] h-1/2 bg-gradient-to-t from-cyan-400 via-cyan-300 to-transparent shadow-[0_0_12px_#22d3ee]" />

              {/* Fading Sweep Wedge Fan Effect */}
              <div
                className="absolute top-0 right-1/2 w-1/2 h-1/2"
                style={{
                  background:
                    'conic-gradient(from 0deg at 100% 100%, rgba(34,211,238,0.3) 0deg, rgba(34,211,238,0.05) 45deg, transparent 60deg)',
                  transformOrigin: 'bottom right'
                }}
              />
            </div>

            {/* Compass Degrees Markings */}
            <span className="absolute top-2 text-[9px] font-mono text-cyan-400/80 font-bold">0° / N</span>
            <span className="absolute bottom-2 text-[9px] font-mono text-cyan-400/80 font-bold">180° / S</span>
            <span className="absolute right-2 text-[9px] font-mono text-cyan-400/80 font-bold">90° / E</span>
            <span className="absolute left-2 text-[9px] font-mono text-cyan-400/80 font-bold">270° / W</span>

            {/* Center Target Indicator Hub */}
            <div className="relative z-20 flex flex-col items-center justify-center p-2 rounded-full bg-slate-950/90 border border-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.4)]">
              <Crosshair className="w-4 h-4 text-cyan-400 animate-spin-slow" />
            </div>

            {/* Provider Radar Blips / Target Nodes */}
            {radarTargets.map((target) => {
              // Convert polar to cartesian coordinates
              const rad = (target.angleDeg - 90) * (Math.PI / 180);
              const distPx = target.distance * radius;
              const x = center + distPx * Math.cos(rad);
              const y = center + distPx * Math.sin(rad);

              // Angular difference between sweep beam and target for flash illumination
              const angleDiff = Math.abs(rotationAngle - target.angleDeg);
              const isSweepingOver = angleDiff < 18 || angleDiff > 342;
              const isSelected = selectedTarget?.id === target.id;

              let dotColor = 'bg-slate-500 border-slate-400';
              let ringColor = 'border-slate-500';
              let glowStyle = '';

              if (target.status === 'malicious') {
                dotColor = 'bg-rose-500 border-rose-300';
                ringColor = 'border-rose-500';
                glowStyle = 'shadow-[0_0_16px_#f43f5e]';
              } else if (target.status === 'suspicious') {
                dotColor = 'bg-amber-400 border-amber-200';
                ringColor = 'border-amber-400';
                glowStyle = 'shadow-[0_0_12px_#fbbf24]';
              } else if (target.status === 'clean') {
                dotColor = 'bg-emerald-400 border-emerald-200';
                ringColor = 'border-emerald-400';
                glowStyle = 'shadow-[0_0_10px_#34d399]';
              }

              return (
                <div
                  key={target.id}
                  onClick={() => {
                    setSelectedTarget(target);
                    if (target.providerRef && onSelectProvider) {
                      onSelectProvider(target.providerRef);
                    }
                  }}
                  className="absolute z-20 cursor-pointer group -translate-x-1/2 -translate-y-1/2"
                  style={{ left: `${x}px`, top: `${y}px` }}
                >
                  {/* Blip Dot */}
                  <div
                    className={`w-3.5 h-3.5 rounded-full border-2 ${dotColor} ${glowStyle} transition-transform ${
                      isSweepingOver ? 'scale-150 animate-ping' : ''
                    } ${isSelected ? 'ring-2 ring-cyan-300 scale-125' : ''}`}
                  />

                  {/* Sonar Ping Ring on Sweep Hit */}
                  {isSweepingOver && (
                    <div
                      className={`absolute -inset-2 rounded-full border ${ringColor} animate-ping pointer-events-none`}
                    />
                  )}

                  {/* Target Label */}
                  <div className="absolute top-4 left-1/2 -translate-x-1/2 whitespace-nowrap opacity-75 group-hover:opacity-100 transition-opacity pointer-events-none">
                    <span className="font-mono text-[9px] px-1 py-0.2 rounded bg-slate-950/90 text-slate-200 border border-slate-800">
                      {target.displayName}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Current Sweep Telemetry Bar */}
          <div className="mt-3 flex items-center gap-4 text-[11px] font-mono text-slate-400">
            <span>Bearing: <strong className="text-cyan-300">{Math.round(rotationAngle)}°</strong></span>
            <span>·</span>
            <span>Radar Scale: <strong className="text-slate-200">100km / 7 Feeds</strong></span>
            <span>·</span>
            <span>Risk Index: <strong className="text-rose-400">{ruleScore}/100</strong></span>
          </div>
        </div>

        {/* Right: Target Inspection & Provider Intel Breakdown */}
        <div className="lg:col-span-5 space-y-3 text-xs">
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-slate-500 font-bold">
                Radar Telemetry Target
              </span>
              <span className="font-mono text-[10px] text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                {indicatorType.toUpperCase()}
              </span>
            </div>
            <div className="font-mono text-sm text-cyan-300 font-bold break-all">
              {indicator}
            </div>
          </div>

          {/* Selected Target Deep-Dive or Guidance */}
          {selectedTarget ? (
            <div className="p-3.5 rounded-xl bg-slate-950 border border-cyan-500/50 space-y-2.5 animate-in fade-in duration-150 shadow-lg">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      selectedTarget.status === 'malicious'
                        ? 'bg-rose-500 shadow-[0_0_8px_#f43f5e]'
                        : selectedTarget.status === 'suspicious'
                        ? 'bg-amber-400'
                        : 'bg-emerald-400'
                    }`}
                  />
                  <span className="font-bold text-slate-100">{selectedTarget.displayName}</span>
                </div>
                <span className="font-mono text-[10px] text-slate-400">
                  {selectedTarget.angleDeg}° Azimuth
                </span>
              </div>

              <div className="text-[11px] text-slate-400">
                {selectedTarget.category}
              </div>

              <div className="grid grid-cols-2 gap-2 font-mono text-[11px] pt-1">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[9px]">Verdict</span>
                  <span
                    className={`font-bold uppercase ${
                      selectedTarget.status === 'malicious'
                        ? 'text-rose-400'
                        : selectedTarget.status === 'suspicious'
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {selectedTarget.status}
                  </span>
                </div>

                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[9px]">Detections</span>
                  <span className="font-bold text-slate-200">
                    {selectedTarget.maliciousCount}
                    {selectedTarget.totalEngines ? ` / ${selectedTarget.totalEngines}` : ' hits'}
                  </span>
                </div>
              </div>

              {selectedTarget.providerRef && (
                <button
                  onClick={() => onSelectProvider && onSelectProvider(selectedTarget.providerRef!)}
                  className="w-full mt-2 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 font-semibold text-xs flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <span>Examine Raw Telemetry Dossier</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              )}
            </div>
          ) : (
            <div className="p-3.5 rounded-xl bg-slate-950/60 border border-dashed border-slate-800 text-center space-y-1.5">
              <Crosshair className="w-6 h-6 text-cyan-400/60 mx-auto" />
              <p className="text-xs text-slate-300 font-medium">Click Any Radar Target Node</p>
              <p className="text-[11px] text-slate-500">
                Select a threat intelligence blip on the 360° radar screen to lock azimuth coordinates and inspect detections.
              </p>
            </div>
          )}

          {/* Quick Target Feeds List */}
          <div className="space-y-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-bold block mb-1">
              Active Radar Array Status
            </span>
            <div className="grid grid-cols-2 gap-1.5">
              {radarTargets.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setSelectedTarget(t)}
                  className={`p-1.5 rounded-md border text-left transition-colors flex items-center justify-between cursor-pointer ${
                    selectedTarget?.id === t.id
                      ? 'bg-slate-800 border-cyan-500/60'
                      : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <span className="font-mono text-[11px] text-slate-300 truncate max-w-[90px]">
                    {t.displayName}
                  </span>
                  <span
                    className={`w-2 h-2 rounded-full ${
                      t.status === 'malicious'
                        ? 'bg-rose-500'
                        : t.status === 'suspicious'
                        ? 'bg-amber-400'
                        : t.status === 'clean'
                        ? 'bg-emerald-400'
                        : 'bg-slate-600'
                    }`}
                  />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
