import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Globe,
  Radio,
  Play,
  Pause,
  Maximize2,
  Crosshair,
  ShieldAlert,
  Zap,
  Filter,
  Layers,
  MapPin,
  ExternalLink,
  Info
} from 'lucide-react';
import { EvidenceObject, AIAnalysisVerdict } from '../../types/index.js';

interface CyberAttackGlobeProps {
  evidence?: EvidenceObject | null;
  analysis?: AIAnalysisVerdict | null;
  height?: number | string;
}

interface AttackTrajectory {
  id: string;
  sourceCity: string;
  sourceCountry: string;
  sourceCountryCode: string;
  sourceCoords: [number, number]; // [lat, lng]
  sourceIp: string;
  targetCity: string;
  targetCountry: string;
  targetCoords: [number, number]; // [lat, lng]
  targetOrg: string;
  threatType: string;
  threatActor?: string;
  severity: 'critical' | 'high' | 'medium';
  cveOrTechnique?: string;
  timestamp: string;
  progress: number; // 0 to 1
  speed: number;
}

// Global cyber coordinates (lat, lng) for high-frequency attack hubs & SOC perimeters
const LOCATION_COORDS: Record<string, [number, number]> = {
  // Threat Origins
  'Moscow, RU': [55.7558, 37.6173],
  'St. Petersburg, RU': [59.9343, 30.3351],
  'Beijing, CN': [39.9042, 116.4074],
  'Shanghai, CN': [31.2304, 121.4737],
  'Pyongyang, KP': [39.0392, 125.7625],
  'Tehran, IR': [35.6892, 51.3890],
  'Bucharest, RO': [44.4268, 26.1025],
  'Amsterdam, NL': [52.3676, 4.9041],
  'Frankfurt, DE': [50.1109, 8.6821],
  'Lagos, NG': [6.5244, 3.3792],
  'Sao Paulo, BR': [-23.5505, -46.6333],

  // Target Perimeters (Enterprise SOCs)
  'Washington DC, US': [38.9072, -77.0369],
  'New York, US': [40.7128, -74.0060],
  'Chicago, US': [41.8781, -87.6298],
  'London, UK': [51.5074, -0.1278],
  'Tokyo, JP': [35.6762, 139.6503],
  'Sydney, AU': [-33.8688, 151.2093],
  'Singapore, SG': [1.3521, 103.8198],
  'Paris, FR': [48.8566, 2.3522]
};

// Simplified SVG projection: converts [lat, lng] to SVG view coordinates [x, y]
// Standard equirectangular projection centered on prime meridian
function projectCoords(lat: number, lng: number, width: number, height: number): [number, number] {
  // Latitude: +90 (North) -> 0, -90 (South) -> height
  // Longitude: -180 (West) -> 0, +180 (East) -> width
  const x = ((lng + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return [x, y];
}

// World continent polygon data (simplified low-poly cyber aesthetic)
const CONTINENT_PATHS = [
  // North America
  'M 120,45 L 210,40 L 260,65 L 245,110 L 215,130 L 190,120 L 170,160 L 160,195 L 140,165 L 105,140 L 80,95 L 95,65 Z',
  // South America
  'M 180,215 L 235,225 L 255,270 L 240,340 L 205,370 L 185,340 L 175,260 Z',
  // Europe
  'M 350,60 L 400,55 L 430,75 L 410,120 L 375,130 L 345,105 L 340,75 Z',
  // Africa
  'M 355,145 L 420,140 L 445,190 L 440,250 L 410,310 L 375,300 L 350,230 L 335,170 Z',
  // Asia
  'M 430,55 L 560,50 L 630,70 L 650,120 L 590,160 L 530,150 L 480,185 L 440,150 L 435,100 Z',
  // Australia
  'M 580,240 L 645,245 L 665,285 L 635,325 L 585,305 L 570,270 Z'
];

export const CyberAttackGlobe: React.FC<CyberAttackGlobeProps> = ({
  evidence,
  analysis,
  height = 420
}) => {
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [activeFilter, setActiveFilter] = useState<'all' | 'critical' | 'high'>('all');
  const [selectedTrajectory, setSelectedTrajectory] = useState<AttackTrajectory | null>(null);
  const [speedMultiplier, setSpeedMultiplier] = useState<number>(1);
  const [projectionMode, setProjectionMode] = useState<'tactical' | 'radar'>('tactical');

  // Simulated base trajectories combined with real evidence indicator
  const [trajectories, setTrajectories] = useState<AttackTrajectory[]>(() => [
    {
      id: 'traj-1',
      sourceCity: 'Moscow',
      sourceCountry: 'Russia',
      sourceCountryCode: 'RU',
      sourceCoords: LOCATION_COORDS['Moscow, RU'],
      sourceIp: '185.220.101.5',
      targetCity: 'Washington DC',
      targetCountry: 'United States',
      targetCoords: LOCATION_COORDS['Washington DC, US'],
      targetOrg: 'Federal Defense Contractor',
      threatType: 'Cobalt Strike C2 Beaconing',
      threatActor: 'APT29 (Cozy Bear)',
      severity: 'critical',
      cveOrTechnique: 'T1071.001',
      timestamp: 'Just now',
      progress: 0.15,
      speed: 0.003
    },
    {
      id: 'traj-2',
      sourceCity: 'Shanghai',
      sourceCountry: 'China',
      sourceCountryCode: 'CN',
      sourceCoords: LOCATION_COORDS['Shanghai, CN'],
      sourceIp: '218.92.0.141',
      targetCity: 'Chicago',
      targetCountry: 'United States',
      targetCoords: LOCATION_COORDS['Chicago, US'],
      targetOrg: 'Financial Core Routing Infrastructure',
      threatType: 'Brute-Force SSH Infiltration',
      threatActor: 'Volt Typhoon',
      severity: 'high',
      cveOrTechnique: 'T1110.001',
      timestamp: '1m ago',
      progress: 0.45,
      speed: 0.0025
    },
    {
      id: 'traj-3',
      sourceCity: 'Pyongyang',
      sourceCountry: 'North Korea',
      sourceCountryCode: 'KP',
      sourceCoords: LOCATION_COORDS['Pyongyang, KP'],
      sourceIp: '175.45.176.12',
      targetCity: 'Tokyo',
      targetCountry: 'Japan',
      targetCoords: LOCATION_COORDS['Tokyo, JP'],
      targetOrg: 'Crypto Asset Custody Gateway',
      threatType: 'Phishing Payload Delivery',
      threatActor: 'Lazarus Group (HIDDEN COBRA)',
      severity: 'critical',
      cveOrTechnique: 'T1566.002',
      timestamp: '2m ago',
      progress: 0.75,
      speed: 0.0035
    },
    {
      id: 'traj-4',
      sourceCity: 'Bucharest',
      sourceCountry: 'Romania',
      sourceCountryCode: 'RO',
      sourceCoords: LOCATION_COORDS['Bucharest, RO'],
      sourceIp: '94.177.248.88',
      targetCity: 'London',
      targetCountry: 'United Kingdom',
      targetCoords: LOCATION_COORDS['London, UK'],
      targetOrg: 'National Healthcare Backbone',
      threatType: 'Exploit Kit Scan (Log4Shell)',
      threatActor: 'Automated Botnet Mesh',
      severity: 'high',
      cveOrTechnique: 'CVE-2021-44228',
      timestamp: '3m ago',
      progress: 0.3,
      speed: 0.0028
    },
    {
      id: 'traj-5',
      sourceCity: 'Tehran',
      sourceCountry: 'Iran',
      sourceCountryCode: 'IR',
      sourceCoords: LOCATION_COORDS['Tehran, IR'],
      sourceIp: '185.141.63.120',
      targetCity: 'Paris',
      targetCountry: 'France',
      targetCoords: LOCATION_COORDS['Paris, FR'],
      targetOrg: 'Energy Grid Telemetry Center',
      threatType: 'MuddyWater Lateral Recon',
      threatActor: 'APT33',
      severity: 'critical',
      cveOrTechnique: 'T1046',
      timestamp: '4m ago',
      progress: 0.6,
      speed: 0.0022
    }
  ]);

  // If evidence is available, dynamically bind the active indicator into the trajectory map!
  useEffect(() => {
    if (evidence && evidence.indicator) {
      const scoreVal = typeof evidence.rule_score === 'number' ? evidence.rule_score : (evidence.rule_score?.value ?? 0);
      const isMalicious = scoreVal >= 70;
      const isSuspicious = scoreVal >= 35 && scoreVal < 70;
      const severity = isMalicious ? 'critical' : isSuspicious ? 'high' : 'medium';

      // Pick an origin point based on evidence data or plausible geo
      const originKeys = Object.keys(LOCATION_COORDS).filter((k) => !k.includes('US') && !k.includes('UK') && !k.includes('JP'));
      const originKey = originKeys[Math.floor(Math.random() * originKeys.length)];
      const [originCity, originCountry] = originKey.split(', ');

      const targetKey = 'Washington DC, US';
      const [targetCity, targetCountry] = targetKey.split(', ');

      const activeTraj: AttackTrajectory = {
        id: `active-${evidence.id}`,
        sourceCity: originCity,
        sourceCountry: originCountry,
        sourceCountryCode: originCountry.toUpperCase().slice(0, 2),
        sourceCoords: LOCATION_COORDS[originKey] || [55.7558, 37.6173],
        sourceIp: evidence.indicator.type === 'ip' ? evidence.indicator.normalized : '185.220.101.5',
        targetCity: targetCity,
        targetCountry: targetCountry,
        targetCoords: LOCATION_COORDS[targetKey] || [38.9072, -77.0369],
        targetOrg: 'Monitored Enterprise Infrastructure',
        threatType: analysis?.executive_summary || `${evidence.indicator.type.toUpperCase()} Investigation Triage`,
        threatActor: analysis?.malware_family || 'Unknown Threat Cluster',
        severity: severity,
        cveOrTechnique: analysis?.mitre_attack?.[0]?.technique_id || 'T1190',
        timestamp: 'Active Now',
        progress: 0.05,
        speed: 0.004
      };

      setTrajectories((prev) => [activeTraj, ...prev.filter((t) => !t.id.startsWith('active-'))]);
      setSelectedTrajectory(activeTraj);
    }
  }, [evidence, analysis]);

  // Animation frame loop for traveling laser pulses
  useEffect(() => {
    if (!isPlaying) return;

    let animId: number;
    const animate = () => {
      setTrajectories((prev) =>
        prev.map((t) => {
          let nextProgress = t.progress + t.speed * speedMultiplier;
          if (nextProgress > 1) {
            nextProgress = 0;
          }
          return { ...t, progress: nextProgress };
        })
      );
      animId = requestAnimationFrame(animate);
    };

    animId = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animId);
  }, [isPlaying, speedMultiplier]);

  // Canvas / SVG coordinate dimensions
  const svgWidth = 800;
  const svgHeight = 420;

  const filteredTrajectories = useMemo(() => {
    if (activeFilter === 'all') return trajectories;
    return trajectories.filter((t) => t.severity === activeFilter);
  }, [trajectories, activeFilter]);

  return (
    <div className="rounded-2xl border border-cyan-500/30 bg-[#070B14] p-4 sm:p-5 relative overflow-hidden shadow-[0_0_40px_rgba(34,211,238,0.1)]">
      {/* Background Matrix Grid Overlay */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage:
            'linear-gradient(to right, rgba(34,211,238,0.1) 1px, transparent 1px), linear-gradient(to bottom, rgba(34,211,238,0.1) 1px, transparent 1px)',
          backgroundSize: '24px 24px'
        }}
      />

      {/* Top HUD Controls Ribbon */}
      <div className="relative z-10 flex flex-wrap items-center justify-between gap-3 mb-4 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.2)]">
            <Globe className="w-5 h-5 animate-spin-slow" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold tracking-wider uppercase text-slate-100 flex items-center gap-1.5">
                <span>Global Threat Vector Holographic Map</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300">
                Live Attack Telemetry
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Real-time ballistic attack trajectory arcs & origin-to-target adversary vectors.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-slate-900/90 border border-slate-800 p-0.5 rounded-lg text-xs">
            <button
              onClick={() => setActiveFilter('all')}
              className={`px-2.5 py-1 rounded-md font-mono text-[11px] transition-colors cursor-pointer ${
                activeFilter === 'all'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({trajectories.length})
            </button>
            <button
              onClick={() => setActiveFilter('critical')}
              className={`px-2.5 py-1 rounded-md font-mono text-[11px] transition-colors cursor-pointer ${
                activeFilter === 'critical'
                  ? 'bg-rose-500 text-white font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Critical
            </button>
            <button
              onClick={() => setActiveFilter('high')}
              className={`px-2.5 py-1 rounded-md font-mono text-[11px] transition-colors cursor-pointer ${
                activeFilter === 'high'
                  ? 'bg-amber-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              High
            </button>
          </div>

          {/* Speed Multiplier */}
          <button
            onClick={() => setSpeedMultiplier((prev) => (prev === 1 ? 2 : prev === 2 ? 4 : 1))}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 font-mono text-xs flex items-center gap-1 cursor-pointer"
            title="Adjust trajectory speed"
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>{speedMultiplier}x Speed</span>
          </button>

          {/* Play/Pause Button */}
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 transition-colors cursor-pointer"
            title={isPlaying ? 'Pause animation' : 'Play animation'}
          >
            {isPlaying ? <Pause className="w-4 h-4 text-cyan-400" /> : <Play className="w-4 h-4 text-emerald-400" />}
          </button>
        </div>
      </div>

      {/* Main Holographic Map Canvas */}
      <div className="relative rounded-xl border border-slate-800/90 bg-[#050811] overflow-hidden">
        {/* Latitude / Longitude Radar Reticle Lines */}
        <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
          <div className="w-[500px] h-[500px] rounded-full border border-cyan-500/10 pointer-events-none" />
          <div className="w-[300px] h-[300px] rounded-full border border-cyan-500/15 pointer-events-none" />
        </div>

        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="w-full h-auto select-none"
          style={{ minHeight: '340px' }}
        >
          <defs>
            {/* Holographic Glowing Filters */}
            <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="glow-crimson" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Linear Gradients for Attack Trajectory Arcs */}
            <linearGradient id="arc-gradient-critical" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#fb7185" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.9" />
            </linearGradient>

            <linearGradient id="arc-gradient-high" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#fbbf24" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.9" />
            </linearGradient>
          </defs>

          {/* Background Grid Lines */}
          <g stroke="rgba(34,211,238,0.08)" strokeWidth="0.5">
            {[...Array(9)].map((_, i) => (
              <line key={`h-${i}`} x1="0" y1={(svgHeight / 8) * i} x2={svgWidth} y2={(svgHeight / 8) * i} />
            ))}
            {[...Array(13)].map((_, i) => (
              <line key={`v-${i}`} x1={(svgWidth / 12) * i} y1="0" x2={(svgWidth / 12) * i} y2={svgHeight} />
            ))}
          </g>

          {/* Simplified Continents Silhouette */}
          <g fill="rgba(15,23,42,0.85)" stroke="rgba(56,189,248,0.3)" strokeWidth="1.2">
            {CONTINENT_PATHS.map((path, idx) => (
              <path key={idx} d={path} className="hover:fill-slate-800 transition-colors" />
            ))}
          </g>

          {/* Attack Trajectory Arcs & Laser Pulses */}
          {filteredTrajectories.map((t) => {
            const [sx, sy] = projectCoords(t.sourceCoords[0], t.sourceCoords[1], svgWidth, svgHeight);
            const [tx, ty] = projectCoords(t.targetCoords[0], t.targetCoords[1], svgWidth, svgHeight);

            // Compute quadratic curved control point
            const midX = (sx + tx) / 2;
            const midY = Math.min(sy, ty) - Math.abs(sx - tx) * 0.22;
            const arcPath = `M ${sx},${sy} Q ${midX},${midY} ${tx},${ty}`;

            // Quadratic bezier calculation for pulse location along curve
            const p = t.progress;
            const pulseX = (1 - p) * (1 - p) * sx + 2 * (1 - p) * p * midX + p * p * tx;
            const pulseY = (1 - p) * (1 - p) * sy + 2 * (1 - p) * p * midY + p * p * ty;

            const isSelected = selectedTrajectory?.id === t.id;
            const strokeColor =
              t.severity === 'critical' ? 'url(#arc-gradient-critical)' : 'url(#arc-gradient-high)';
            const pulseColor = t.severity === 'critical' ? '#f43f5e' : '#f59e0b';

            return (
              <g
                key={t.id}
                className="cursor-pointer"
                onClick={() => setSelectedTrajectory(t)}
              >
                {/* Background Arc Path */}
                <path
                  d={arcPath}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={isSelected ? 2.5 : 1.4}
                  strokeDasharray="4 3"
                  className="transition-all hover:stroke-width-3"
                  opacity={isSelected ? 1 : 0.65}
                />

                {/* Traveling Energy Laser Pulse */}
                <circle
                  cx={pulseX}
                  cy={pulseY}
                  r={isSelected ? 4.5 : 3.5}
                  fill={pulseColor}
                  filter={t.severity === 'critical' ? 'url(#glow-crimson)' : 'url(#glow-cyan)'}
                />

                {/* Source Origin Beacon Node */}
                <circle cx={sx} cy={sy} r="4" fill={pulseColor} />
                <circle
                  cx={sx}
                  cy={sy}
                  r="9"
                  fill="none"
                  stroke={pulseColor}
                  strokeWidth="1"
                  className="animate-ping"
                  style={{ transformOrigin: `${sx}px ${sy}px`, animationDuration: '2.5s' }}
                />

                {/* Target SOC Perimeter Node */}
                <circle cx={tx} cy={ty} r="4" fill="#22d3ee" />
                <circle
                  cx={tx}
                  cy={ty}
                  r="8"
                  fill="none"
                  stroke="#22d3ee"
                  strokeWidth="1"
                  opacity="0.8"
                />
              </g>
            );
          })}
        </svg>

        {/* Selected Trajectory Telemetry Card Overlay */}
        {selectedTrajectory && (
          <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:max-w-md p-3.5 rounded-xl bg-slate-950/95 border border-cyan-500/50 backdrop-blur-md shadow-2xl text-xs z-20 animate-in fade-in slide-in-from-bottom-2 duration-150">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
              <div className="flex items-center gap-2">
                <span
                  className={`w-2.5 h-2.5 rounded-full ${
                    selectedTrajectory.severity === 'critical'
                      ? 'bg-rose-500 shadow-[0_0_8px_#f43f5e]'
                      : 'bg-amber-400'
                  }`}
                />
                <span className="font-bold text-slate-100">{selectedTrajectory.threatType}</span>
              </div>
              <button
                onClick={() => setSelectedTrajectory(null)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer font-mono"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px] mb-2 font-mono">
              <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                <span className="text-slate-500 block text-[9px] uppercase">Origin Node</span>
                <span className="text-rose-300 font-bold block">{selectedTrajectory.sourceCity} ({selectedTrajectory.sourceCountryCode})</span>
                <span className="text-slate-400 text-[10px]">{selectedTrajectory.sourceIp}</span>
              </div>
              <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                <span className="text-slate-500 block text-[9px] uppercase">Target Perimeter</span>
                <span className="text-cyan-300 font-bold block">{selectedTrajectory.targetCity}</span>
                <span className="text-slate-400 text-[10px] truncate block">{selectedTrajectory.targetOrg}</span>
              </div>
            </div>

            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono pt-1">
              <span>Actor: <strong className="text-amber-300">{selectedTrajectory.threatActor || 'Undetermined'}</strong></span>
              <span>Technique: <strong className="text-cyan-300">{selectedTrajectory.cveOrTechnique || 'T1190'}</strong></span>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Live Adversary Attack Feed Ribbon */}
      <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 text-slate-400">
          <Crosshair className="w-3.5 h-3.5 text-cyan-400 animate-spin-slow" />
          <span className="text-slate-300 font-semibold">Active Inbound Intercepts:</span>
          <span className="text-cyan-300">{trajectories.length} Active Vectors</span>
        </div>
        <div className="hidden sm:flex items-center gap-3 text-[11px] text-slate-500">
          <span>Projection: Equirectangular Hologram</span>
          <span>·</span>
          <span>Coverage: Global 360°</span>
        </div>
      </div>
    </div>
  );
};
