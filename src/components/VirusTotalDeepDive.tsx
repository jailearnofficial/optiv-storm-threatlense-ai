import React, { useState, useMemo } from 'react';
import {
  Network,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Search,
  Copy,
  Check,
  Maximize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Layers,
  FileCode,
  Globe,
  Radio,
  Lock,
  ArrowRight,
  Info,
  Server,
  FileText,
  Binary
} from 'lucide-react';
import { ProviderResult, IndicatorType, VTGraphNode } from '../types/index.js';

interface VirusTotalDeepDiveProps {
  provider: ProviderResult;
  indicator: string;
  indicatorType: IndicatorType;
  onPivotIndicator?: (newIndicator: string, type?: IndicatorType) => void;
}

export const VirusTotalDeepDive: React.FC<VirusTotalDeepDiveProps> = ({
  provider,
  indicator,
  indicatorType,
  onPivotIndicator
}) => {
  const [activeTab, setActiveTab] = useState<'graph' | 'engines' | 'metadata'>('graph');
  const [engineFilter, setEngineFilter] = useState<'all' | 'malicious' | 'suspicious' | 'clean'>('all');
  const [engineSearch, setEngineSearch] = useState('');
  const [selectedNode, setSelectedNode] = useState<VTGraphNode | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('all');

  const vtDetails = provider.vt_details;
  const vtGraph = provider.vt_graph || vtDetails?.vt_graph;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  // Filtered engines
  const filteredEngines = useMemo(() => {
    if (!vtDetails?.engines) return [];
    return vtDetails.engines.filter((eng) => {
      const matchSearch =
        eng.engine_name.toLowerCase().includes(engineSearch.toLowerCase()) ||
        (eng.result && eng.result.toLowerCase().includes(engineSearch.toLowerCase()));

      if (!matchSearch) return false;

      if (engineFilter === 'malicious') return eng.category === 'malicious';
      if (engineFilter === 'suspicious') return eng.category === 'suspicious';
      if (engineFilter === 'clean') return eng.category === 'harmless' || eng.category === 'undetected';
      return true;
    });
  }, [vtDetails?.engines, engineSearch, engineFilter]);

  // Nodes for graph
  const nodes = vtGraph?.nodes || [];
  const links = vtGraph?.links || [];

  // Filtered nodes
  const displayNodes = useMemo(() => {
    if (selectedCategoryFilter === 'all') return nodes;
    return nodes.filter((n, idx) => idx === 0 || n.type === selectedCategoryFilter);
  }, [nodes, selectedCategoryFilter]);

  // Compute circular layout for nodes
  const nodePositions = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    if (displayNodes.length === 0) return map;

    // Center node
    map.set(displayNodes[0].id, { x: 380, y: 220 });

    const outerNodes = displayNodes.slice(1);
    const count = outerNodes.length;
    const radius = 160;

    outerNodes.forEach((node, i) => {
      const angle = (i / count) * 2 * Math.PI - Math.PI / 2;
      const x = 380 + radius * Math.cos(angle);
      const y = 220 + radius * Math.sin(angle);
      map.set(node.id, { x, y });
    });

    return map;
  }, [displayNodes]);

  const getNodeColor = (status: VTGraphNode['status']) => {
    switch (status) {
      case 'malicious':
        return {
          fill: '#ef4444',
          stroke: '#dc2626',
          glow: 'rgba(239, 68, 68, 0.4)',
          text: 'text-rose-400',
          bg: 'bg-rose-950/80',
          border: 'border-rose-700'
        };
      case 'suspicious':
        return {
          fill: '#f59e0b',
          stroke: '#d97706',
          glow: 'rgba(245, 158, 11, 0.4)',
          text: 'text-amber-400',
          bg: 'bg-amber-950/80',
          border: 'border-amber-700'
        };
      case 'clean':
        return {
          fill: '#10b981',
          stroke: '#059669',
          glow: 'rgba(16, 185, 129, 0.4)',
          text: 'text-emerald-400',
          bg: 'bg-emerald-950/80',
          border: 'border-emerald-700'
        };
      default:
        return {
          fill: '#06b6d4',
          stroke: '#0891b2',
          glow: 'rgba(6, 182, 212, 0.4)',
          text: 'text-cyan-400',
          bg: 'bg-cyan-950/80',
          border: 'border-cyan-700'
        };
    }
  };

  const getNodeIconType = (type: VTGraphNode['type']) => {
    switch (type) {
      case 'file':
        return 'FILE';
      case 'domain':
        return 'DOM';
      case 'ip':
        return 'IP';
      case 'url':
        return 'URL';
      case 'certificate':
        return 'CERT';
      case 'threat_actor':
        return 'ACTOR';
      default:
        return 'NODE';
    }
  };

  const scoreObj = provider.score || {};
  const maliciousCount = vtDetails?.analysis_stats?.malicious ?? scoreObj.malicious ?? 0;
  const suspiciousCount = vtDetails?.analysis_stats?.suspicious ?? scoreObj.suspicious ?? 0;
  const harmlessCount = vtDetails?.analysis_stats?.harmless ?? scoreObj.harmless ?? 0;
  const undetectedCount = vtDetails?.analysis_stats?.undetected ?? scoreObj.undetected ?? 0;
  const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount || 74;

  const vtGraphUrl =
    vtGraph?.vt_graph_url ||
    `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}/graph`;

  return (
    <div className="relative z-10 max-w-5xl mx-auto px-4 my-8">
      <div className="rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl backdrop-blur-xl overflow-hidden">
        {/* Top Header Banner */}
        <div className="p-5 sm:p-6 border-b border-slate-800 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h3 className="font-extrabold text-base sm:text-lg text-slate-100 tracking-wide">
                  VirusTotal Intelligence & VT Graph Explorer
                </h3>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
                  v3 Telemetry
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Graph relationships, multi-AV vendor detections, cryptohashes, and infrastructure telemetry
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto justify-between md:justify-end">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-mono font-bold text-slate-200">
                <span className={maliciousCount > 0 ? 'text-rose-400' : 'text-emerald-400'}>
                  {maliciousCount}
                </span>
                <span className="text-slate-500"> / {totalEngines}</span>
              </div>
              <div className="text-[10px] text-slate-400 uppercase tracking-wider">
                Detection Ratio
              </div>
            </div>

            <a
              href={vtGraphUrl}
              target="_blank"
              rel="noreferrer"
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 hover:text-cyan-200 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(6,182,212,0.15)] cursor-pointer"
            >
              <span>Launch VirusTotal Graph</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-2 px-6 pt-3 border-b border-slate-800 bg-slate-950/60 overflow-x-auto">
          <button
            onClick={() => setActiveTab('graph')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'graph'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Interactive VT Graph ({displayNodes.length} Nodes)</span>
          </button>

          <button
            onClick={() => setActiveTab('engines')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'engines'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Security Vendors Matrix ({vtDetails?.engines?.length || totalEngines} Engines)</span>
          </button>

          <button
            onClick={() => setActiveTab('metadata')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'metadata'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Deep Forensic Metadata & Hashes</span>
          </button>
        </div>

        {/* TAB 1: INTERACTIVE VT GRAPH */}
        {activeTab === 'graph' && (
          <div className="p-5 sm:p-6 space-y-4">
            {/* Filter pills & canvas controls bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-slate-400 text-[11px] font-medium mr-1">Filter Nodes:</span>
                {[
                  { id: 'all', label: 'All Connected' },
                  { id: 'domain', label: 'Domains' },
                  { id: 'ip', label: 'IP Nodes' },
                  { id: 'file', label: 'Files' },
                  { id: 'threat_actor', label: 'Actors / ASNs' }
                ].map((f) => (
                  <button
                    key={f.id}
                    onClick={() => setSelectedCategoryFilter(f.id)}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer ${
                      selectedCategoryFilter === f.id
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200 border border-slate-700'
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setZoomLevel((z) => Math.min(1.4, z + 0.1))}
                  className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                  title="Zoom In"
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setZoomLevel((z) => Math.max(0.7, z - 0.1))}
                  className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                  title="Zoom Out"
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setZoomLevel(1)}
                  className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                  title="Reset Zoom"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Canvas Area */}
            <div className="relative w-full h-[440px] rounded-xl bg-[#070B12] border border-slate-800 overflow-hidden flex items-center justify-center">
              {/* Grid Background */}
              <div
                className="absolute inset-0 opacity-20 pointer-events-none"
                style={{
                  backgroundImage:
                    'radial-gradient(circle at 1px 1px, #0891b2 1px, transparent 0)',
                  backgroundSize: '24px 24px'
                }}
              />

              {/* Interactive SVG Diagram */}
              <svg
                viewBox="0 0 760 440"
                className="w-full h-full transition-transform duration-200"
                style={{ transform: `scale(${zoomLevel})` }}
              >
                {/* SVG Links */}
                {links.map((link, idx) => {
                  const srcPos = nodePositions.get(link.source);
                  const tgtPos = nodePositions.get(link.target);
                  if (!srcPos || !tgtPos) return null;

                  const midX = (srcPos.x + tgtPos.x) / 2;
                  const midY = (srcPos.y + tgtPos.y) / 2;

                  return (
                    <g key={`link-${idx}`}>
                      <line
                        x1={srcPos.x}
                        y1={srcPos.y}
                        x2={tgtPos.x}
                        y2={tgtPos.y}
                        stroke="#334155"
                        strokeWidth="1.5"
                        strokeDasharray={link.label.includes('dropped') ? '4 2' : undefined}
                      />
                      {/* Label on link */}
                      <rect
                        x={midX - 35}
                        y={midY - 8}
                        width="70"
                        height="16"
                        rx="4"
                        fill="#0f172a"
                        stroke="#1e293b"
                        strokeWidth="1"
                      />
                      <text
                        x={midX}
                        y={midY + 3}
                        textAnchor="middle"
                        fill="#94a3b8"
                        fontSize="8.5"
                        fontFamily="monospace"
                      >
                        {link.label.replace('_', ' ')}
                      </text>
                    </g>
                  );
                })}

                {/* SVG Nodes */}
                {displayNodes.map((node, index) => {
                  const pos = nodePositions.get(node.id);
                  if (!pos) return null;

                  const isRoot = index === 0;
                  const col = getNodeColor(node.status);
                  const isSelected = selectedNode?.id === node.id;

                  return (
                    <g
                      key={`node-${node.id}`}
                      onClick={() => setSelectedNode(node)}
                      className="cursor-pointer group"
                      transform={`translate(${pos.x}, ${pos.y})`}
                    >
                      {/* Pulsing ring for root node */}
                      {isRoot && (
                        <circle
                          r="36"
                          fill="none"
                          stroke={col.stroke}
                          strokeWidth="1.5"
                          opacity="0.4"
                          className="animate-ping"
                        />
                      )}

                      {/* Selection ring */}
                      {isSelected && (
                        <circle
                          r={isRoot ? '32' : '26'}
                          fill="none"
                          stroke="#22d3ee"
                          strokeWidth="2.5"
                          strokeDasharray="4 2"
                        />
                      )}

                      {/* Main node circle */}
                      <circle
                        r={isRoot ? '24' : '18'}
                        fill="#0f172a"
                        stroke={col.stroke}
                        strokeWidth={isRoot ? '3' : '2'}
                        filter="drop-shadow(0 0 8px rgba(0,0,0,0.5))"
                      />

                      {/* Inner status dot */}
                      <circle r={isRoot ? '12' : '8'} fill={col.fill} opacity="0.85" />

                      {/* Node Icon / Type Code */}
                      <text
                        y={isRoot ? '3.5' : '3'}
                        textAnchor="middle"
                        fill="#ffffff"
                        fontSize={isRoot ? '9' : '7.5'}
                        fontWeight="bold"
                        fontFamily="sans-serif"
                      >
                        {getNodeIconType(node.type)}
                      </text>

                      {/* Node label underneath */}
                      <text
                        y={isRoot ? '38' : '30'}
                        textAnchor="middle"
                        fill={isSelected ? '#67e8f9' : '#cbd5e1'}
                        fontSize="9.5"
                        fontWeight={isRoot ? 'bold' : 'normal'}
                        fontFamily="sans-serif"
                        className="transition-colors drop-shadow-md"
                      >
                        {node.label.length > 20
                          ? node.label.substring(0, 18) + '...'
                          : node.label}
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Node Inspector Drawer in Canvas */}
              {selectedNode && (
                <div className="absolute bottom-3 left-3 right-3 sm:left-auto sm:right-3 sm:w-80 p-3.5 rounded-xl bg-slate-900/95 border border-cyan-500/40 shadow-2xl backdrop-blur-md animate-in fade-in slide-in-from-bottom-2 duration-150">
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                        {selectedNode.type.toUpperCase()}
                      </span>
                      <h4 className="font-bold text-xs text-slate-100 mt-1 truncate max-w-[200px]">
                        {selectedNode.label}
                      </h4>
                    </div>
                    <button
                      onClick={() => setSelectedNode(null)}
                      className="text-slate-400 hover:text-slate-200 text-xs px-1.5 py-0.5 rounded bg-slate-800"
                    >
                      ✕
                    </button>
                  </div>

                  <p className="text-[11px] text-slate-300 mb-2.5">
                    {selectedNode.details || 'Active entity linked in VirusTotal knowledge graph.'}
                  </p>

                  <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800">
                    <span
                      className={`text-[10px] font-mono font-bold uppercase ${
                        getNodeColor(selectedNode.status).text
                      }`}
                    >
                      Status: {selectedNode.status}
                    </span>

                    {onPivotIndicator && selectedNode.id !== indicator && (
                      <button
                        onClick={() => {
                          const pivotType =
                            selectedNode.type === 'file'
                              ? 'hash'
                              : selectedNode.type === 'domain'
                              ? 'domain'
                              : selectedNode.type === 'ip'
                              ? 'ip'
                              : 'url';
                          onPivotIndicator(selectedNode.id, pivotType as IndicatorType);
                        }}
                        className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-[10px] font-bold flex items-center gap-1 transition-colors cursor-pointer"
                      >
                        <span>Pivot Triage</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Bottom Legend */}
            <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-400">
              <div className="flex items-center gap-4 flex-wrap">
                <span className="font-semibold text-slate-300">Graph Legend:</span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_6px_#ef4444]" />
                  <span>Malicious</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                  <span>Suspicious</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                  <span>Clean</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
                  <span>Neutral / Route</span>
                </span>
              </div>

              <div className="text-[11px] font-mono text-slate-500">
                Click nodes to inspect · Directed edges denote telemetry communications
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: SECURITY VENDORS MATRIX */}
        {activeTab === 'engines' && (
          <div className="p-5 sm:p-6 space-y-4">
            {/* Filter & Search Controls */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="relative w-full sm:w-72">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={engineSearch}
                  onChange={(e) => setEngineSearch(e.target.value)}
                  placeholder="Search vendors (e.g. CrowdStrike, Microsoft)..."
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto pb-1 sm:pb-0">
                <button
                  onClick={() => setEngineFilter('all')}
                  className={`px-3 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors ${
                    engineFilter === 'all'
                      ? 'bg-slate-700 text-slate-100 font-bold'
                      : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All ({vtDetails?.engines?.length || 0})
                </button>
                <button
                  onClick={() => setEngineFilter('malicious')}
                  className={`px-3 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors flex items-center gap-1 ${
                    engineFilter === 'malicious'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800 font-bold'
                      : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldAlert className="w-3 h-3 text-rose-400" />
                  <span>Malicious ({maliciousCount})</span>
                </button>
                <button
                  onClick={() => setEngineFilter('suspicious')}
                  className={`px-3 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors flex items-center gap-1 ${
                    engineFilter === 'suspicious'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800 font-bold'
                      : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <AlertTriangle className="w-3 h-3 text-amber-400" />
                  <span>Suspicious ({suspiciousCount})</span>
                </button>
                <button
                  onClick={() => setEngineFilter('clean')}
                  className={`px-3 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors flex items-center gap-1 ${
                    engineFilter === 'clean'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold'
                      : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                  <span>Clean / Undetected</span>
                </button>
              </div>
            </div>

            {/* Vendor Detection Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 max-h-[460px] overflow-y-auto pr-1">
              {filteredEngines.map((engine) => {
                const isMal = engine.category === 'malicious';
                const isSusp = engine.category === 'suspicious';
                const isClean = engine.category === 'harmless' || engine.category === 'undetected';

                return (
                  <div
                    key={engine.engine_name}
                    className={`p-3 rounded-xl border transition-all flex flex-col justify-between gap-1.5 ${
                      isMal
                        ? 'bg-rose-950/20 border-rose-900/60 hover:border-rose-700/80'
                        : isSusp
                        ? 'bg-amber-950/20 border-amber-900/60 hover:border-amber-700/80'
                        : 'bg-slate-950/40 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-xs text-slate-200">
                        {engine.engine_name}
                      </span>
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded uppercase ${
                          isMal
                            ? 'bg-rose-950 text-rose-400 border border-rose-800'
                            : isSusp
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                      >
                        {engine.category}
                      </span>
                    </div>

                    <div className="font-mono text-[11px] truncate text-slate-300">
                      {engine.result ? (
                        <span className={isMal ? 'text-rose-300' : 'text-slate-400'}>
                          {engine.result}
                        </span>
                      ) : (
                        <span className="text-slate-500 italic">No threat detected</span>
                      )}
                    </div>

                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-800/50">
                      <span>Method: {engine.method}</span>
                      {engine.update && <span>Updated: {engine.update}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* TAB 3: DEEP FORENSIC METADATA & HASHES */}
        {activeTab === 'metadata' && (
          <div className="p-5 sm:p-6 space-y-6">
            {/* File Hashes (If Hash) */}
            {vtDetails?.file_details && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Binary className="w-4 h-4 text-cyan-400" />
                  <span>Cryptographic File Hashes</span>
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                  {[
                    { label: 'SHA-256', val: vtDetails.file_details.sha256 },
                    { label: 'MD5', val: vtDetails.file_details.md5 },
                    { label: 'SHA-1', val: vtDetails.file_details.sha1 },
                    { label: 'Imphash', val: vtDetails.file_details.pe_info?.imphash },
                    { label: 'SSDEEP', val: vtDetails.file_details.ssdeep },
                    { label: 'TLSH', val: vtDetails.file_details.tlsh }
                  ]
                    .filter((h) => Boolean(h.val))
                    .map((h) => (
                      <div
                        key={h.label}
                        className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center justify-between gap-2"
                      >
                        <div className="truncate">
                          <span className="text-slate-500 text-[11px] block">{h.label}:</span>
                          <span className="text-slate-200 text-xs select-all truncate block">
                            {h.val}
                          </span>
                        </div>
                        <button
                          onClick={() => handleCopy(h.val || '', h.label)}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-300 transition-colors shrink-0"
                          title={`Copy ${h.label}`}
                        >
                          {copiedKey === h.label ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* PE Header & Authenticode Signatures */}
            {vtDetails?.file_details?.pe_info && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span>Portable Executable (PE) & Digital Signatures</span>
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-slate-500 text-[10px] uppercase font-mono block">
                      Compilation Date
                    </span>
                    <span className="font-mono text-slate-200 text-xs">
                      {vtDetails.file_details.pe_info.compilation_timestamp || 'N/A'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-slate-500 text-[10px] uppercase font-mono block">
                      Entry Point
                    </span>
                    <span className="font-mono text-cyan-300 text-xs">
                      {vtDetails.file_details.pe_info.entry_point || '0x00401000'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-slate-500 text-[10px] uppercase font-mono block">
                      PE Sections
                    </span>
                    <span className="font-mono text-slate-200 text-xs">
                      {vtDetails.file_details.pe_info.sections_count || 4} sections
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-slate-500 text-[10px] uppercase font-mono block">
                      Authenticode Signer
                    </span>
                    <span className="font-mono text-slate-200 text-xs truncate block">
                      {vtDetails.file_details.signature_info?.signer || 'Unsigned'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Crowdsourced YARA Rules */}
            {vtDetails?.file_details?.crowdsourced_yara &&
              vtDetails.file_details.crowdsourced_yara.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-cyan-400" />
                    <span>Crowdsourced YARA & Threat Rules</span>
                  </h4>

                  <div className="space-y-2">
                    {vtDetails.file_details.crowdsourced_yara.map((yara, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono font-bold text-xs text-rose-300">
                            {yara.rule_name}
                          </span>
                          {yara.author && (
                            <span className="text-[10px] text-slate-400 font-mono">
                              Author: {yara.author}
                            </span>
                          )}
                        </div>
                        {yara.description && (
                          <p className="text-xs text-slate-300">{yara.description}</p>
                        )}
                        {yara.source && (
                          <span className="text-[10px] text-cyan-400 font-mono block">
                            Source: {yara.source}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Network / Domain / IP Details */}
            {vtDetails?.network_details && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  <span>Network, DNS & Routing Infrastructure</span>
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-xs">
                  {vtDetails.network_details.asn && (
                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-500 text-[10px] uppercase font-mono block">
                        Autonomous System (ASN)
                      </span>
                      <span className="font-mono text-cyan-300 font-bold">
                        AS{vtDetails.network_details.asn}
                      </span>
                      <span className="text-slate-400 text-[11px] block mt-0.5">
                        {vtDetails.network_details.as_owner} ({vtDetails.network_details.country})
                      </span>
                    </div>
                  )}

                  {vtDetails.network_details.registrar && (
                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-500 text-[10px] uppercase font-mono block">
                        Domain Registrar
                      </span>
                      <span className="font-mono text-slate-200">
                        {vtDetails.network_details.registrar}
                      </span>
                    </div>
                  )}

                  {vtDetails.network_details.ssl_cert && (
                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-500 text-[10px] uppercase font-mono block">
                        SSL / TLS Certificate
                      </span>
                      <span className="font-mono text-slate-200 block truncate">
                        Issuer: {vtDetails.network_details.ssl_cert.issuer}
                      </span>
                      {vtDetails.network_details.ssl_cert.valid_to && (
                        <span className="text-[10px] text-slate-400 font-mono block">
                          Valid until: {vtDetails.network_details.ssl_cert.valid_to}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {/* DNS Records */}
                {vtDetails.network_details.dns_records &&
                  vtDetails.network_details.dns_records.length > 0 && (
                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-400 text-[10px] uppercase font-mono font-bold block mb-2">
                        Active DNS Resolutions
                      </span>
                      <div className="space-y-1.5 font-mono text-xs">
                        {vtDetails.network_details.dns_records.map((rec, i) => (
                          <div key={i} className="flex items-center justify-between text-slate-300">
                            <span className="text-cyan-400 font-bold w-16">{rec.type}</span>
                            <span className="flex-1 text-slate-200">{rec.value}</span>
                            {rec.ttl && <span className="text-slate-500 text-[11px]">TTL: {rec.ttl}s</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
