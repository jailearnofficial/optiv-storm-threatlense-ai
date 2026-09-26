import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Network,
  Maximize2,
  Minimize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Filter,
  Layers,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Share2,
  Download,
  Copy,
  Check,
  Globe,
  Server,
  FileCode,
  Lock,
  Target
} from 'lucide-react';
import { IndicatorType, ProviderResult, VTGraphNode, VTGraphLink } from '../types/index.js';

interface ThreatGraphPanelProps {
  indicator: string;
  indicatorType: IndicatorType;
  providers: ProviderResult[];
  related?: {
    domains: string[];
    ips: string[];
    urls: string[];
    hashes: string[];
  };
  onPivotIndicator?: (newIndicator: string, type?: IndicatorType) => void;
}

interface GraphNodeInternal extends VTGraphNode {
  x: number;
  y: number;
  vx?: number;
  vy?: number;
}

export const ThreatGraphPanel: React.FC<ThreatGraphPanelProps> = ({
  indicator,
  indicatorType,
  providers,
  related,
  onPivotIndicator
}) => {
  const [selectedNode, setSelectedNode] = useState<VTGraphNode | null>(null);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [filterType, setFilterType] = useState<string>('all');
  const [isFullScreen, setIsFullScreen] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);

  // Extract VT graph or synthesize unified multi-provider graph
  const { nodes, links } = useMemo(() => {
    const vtProvider = providers.find((p) => p.name === 'virustotal');
    const existingVtGraph = vtProvider?.vt_graph || vtProvider?.vt_details?.vt_graph;

    const baseNodes: VTGraphNode[] = [];
    const baseLinks: VTGraphLink[] = [];
    const nodeMap = new Set<string>();

    const isMalicious = providers.some((p) => (p.score?.malicious ?? 0) > 0);
    const isSuspicious = providers.some((p) => (p.score?.suspicious ?? 0) > 0);
    const rootStatus: VTGraphNode['status'] = isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'clean';

    // 1. Root Node
    baseNodes.push({
      id: indicator,
      label: indicatorType === 'hash' ? indicator.substring(0, 16) + '...' : indicator,
      type: indicatorType === 'hash' ? 'file' : indicatorType,
      status: rootStatus,
      details: `Primary ${indicatorType.toUpperCase()} target under active SOC investigation`
    });
    nodeMap.add(indicator);

    // If existing VT graph is present, incorporate its rich relations
    if (existingVtGraph?.nodes) {
      for (const n of existingVtGraph.nodes) {
        if (!nodeMap.has(n.id)) {
          nodeMap.add(n.id);
          baseNodes.push(n);
        }
      }
      for (const l of existingVtGraph.links || []) {
        baseLinks.push(l);
      }
    }

    // Incorporate related IPs, Domains, Hashes from other providers
    if (related) {
      (related.domains || []).slice(0, 5).forEach((d) => {
        if (!nodeMap.has(d)) {
          nodeMap.add(d);
          baseNodes.push({
            id: d,
            label: d,
            type: 'domain',
            status: 'suspicious',
            details: 'Correlated domain observed in live telemetry'
          });
          baseLinks.push({
            source: indicator,
            target: d,
            label: 'contacted_domain'
          });
        }
      });

      (related.ips || []).slice(0, 5).forEach((ip) => {
        if (!nodeMap.has(ip)) {
          nodeMap.add(ip);
          baseNodes.push({
            id: ip,
            label: ip,
            type: 'ip',
            status: 'malicious',
            details: 'Resolved IP infrastructure / C2 node'
          });
          baseLinks.push({
            source: indicator,
            target: ip,
            label: 'resolves_to'
          });
        }
      });

      (related.hashes || []).slice(0, 4).forEach((h) => {
        if (!nodeMap.has(h)) {
          nodeMap.add(h);
          baseNodes.push({
            id: h,
            label: h.substring(0, 14) + '...',
            type: 'file',
            status: 'malicious',
            details: 'Secondary dropped artifact / payload hash'
          });
          baseLinks.push({
            source: indicator,
            target: h,
            label: 'dropped_file'
          });
        }
      });
    }

    return { nodes: baseNodes, links: baseLinks };
  }, [indicator, indicatorType, providers, related]);

  // Filter nodes by type
  const filteredNodes = useMemo(() => {
    if (filterType === 'all') return nodes;
    return nodes.filter((n, idx) => idx === 0 || n.type === filterType);
  }, [nodes, filterType]);

  // Compute 2D node layout coordinates
  const positionedNodes: GraphNodeInternal[] = useMemo(() => {
    if (filteredNodes.length === 0) return [];
    const width = 800;
    const height = 480;
    const cx = width / 2;
    const cy = height / 2;

    const result: GraphNodeInternal[] = [];
    const root = filteredNodes[0];
    result.push({ ...root, x: cx, y: cy });

    const outer = filteredNodes.slice(1);
    const count = outer.length;

    // Arrange in concentric orbits if multiple nodes
    outer.forEach((node, i) => {
      // Determine radius based on node type
      let radius = 170;
      if (node.type === 'ip') radius = 150;
      if (node.type === 'file') radius = 190;
      if (node.type === 'threat_actor' || node.type === 'certificate') radius = 220;

      const angle = (i / count) * 2 * Math.PI - Math.PI / 2;
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      result.push({ ...node, x, y });
    });

    return result;
  }, [filteredNodes]);

  // Node position map for link drawing
  const nodeCoordMap = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    for (const n of positionedNodes) {
      map.set(n.id, { x: n.x, y: n.y });
    }
    return map;
  }, [positionedNodes]);

  // Pan interaction
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === 'circle' || (e.target as HTMLElement).tagName === 'text') {
      return;
    }
    setIsDragging(true);
    setDragStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPanOffset({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const getNodeColor = (node: VTGraphNode) => {
    if (node.status === 'malicious') return { fill: '#ef4444', stroke: '#b91c1c', ring: 'rgba(239, 68, 68, 0.4)' };
    if (node.status === 'suspicious') return { fill: '#f59e0b', stroke: '#d97706', ring: 'rgba(245, 158, 11, 0.4)' };
    if (node.status === 'clean') return { fill: '#10b981', stroke: '#059669', ring: 'rgba(16, 185, 129, 0.4)' };
    return { fill: '#06b6d4', stroke: '#0891b2', ring: 'rgba(6, 182, 212, 0.4)' };
  };

  return (
    <div className={`relative z-10 max-w-5xl mx-auto my-6 px-4 ${isFullScreen ? 'fixed inset-0 z-50 p-4 bg-slate-950/95 max-w-none' : ''}`}>
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-5 md:p-6 backdrop-blur-md shadow-xl flex flex-col h-full">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Interactive Node-Link Threat & Infrastructure Graph
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Interactive relationship canvas linking analyzed indicators, resolutions, and contacted C2 nodes
            </p>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-center">
            {/* Filter buttons */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[11px] font-mono">
              <button
                type="button"
                onClick={() => setFilterType('all')}
                className={`px-2 py-0.5 rounded cursor-pointer ${filterType === 'all' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                All ({nodes.length})
              </button>
              <button
                type="button"
                onClick={() => setFilterType('ip')}
                className={`px-2 py-0.5 rounded cursor-pointer ${filterType === 'ip' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                IPs
              </button>
              <button
                type="button"
                onClick={() => setFilterType('domain')}
                className={`px-2 py-0.5 rounded cursor-pointer ${filterType === 'domain' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Domains
              </button>
              <button
                type="button"
                onClick={() => setFilterType('file')}
                className={`px-2 py-0.5 rounded cursor-pointer ${filterType === 'file' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Files
              </button>
            </div>

            {/* Canvas controls */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
              <button
                type="button"
                onClick={() => setZoomLevel((z) => Math.min(2.2, z + 0.15))}
                className="p-1 rounded text-slate-400 hover:text-cyan-300 cursor-pointer"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => setZoomLevel((z) => Math.max(0.6, z - 0.15))}
                className="p-1 rounded text-slate-400 hover:text-cyan-300 cursor-pointer"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => {
                  setZoomLevel(1);
                  setPanOffset({ x: 0, y: 0 });
                }}
                className="p-1 rounded text-slate-400 hover:text-cyan-300 cursor-pointer"
                title="Reset View"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => setIsFullScreen(!isFullScreen)}
                className="p-1 rounded text-slate-400 hover:text-cyan-300 cursor-pointer"
                title={isFullScreen ? 'Exit Full Screen' : 'Full Screen'}
              >
                {isFullScreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        {/* SVG Canvas Area */}
        <div
          ref={containerRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          className={`relative rounded-xl border border-slate-800 bg-[#040711] overflow-hidden select-none cursor-grab active:cursor-grabbing ${
            isFullScreen ? 'flex-1 h-[calc(100vh-180px)]' : 'h-[440px]'
          }`}
        >
          {/* Subtle Cyber Grid Background */}
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b14_1px,transparent_1px),linear-gradient(to_bottom,#1e293b14_1px,transparent_1px)] bg-[size:28px_28px] pointer-events-none" />

          {/* SVG Canvas */}
          <svg
            className="w-full h-full"
            viewBox="0 0 800 480"
            preserveAspectRatio="xMidYMid meet"
          >
            <defs>
              <filter id="node-glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <marker
                id="graph-arrow"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" fillOpacity="0.7" />
              </marker>
            </defs>

            <g
              transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}
              transform-origin="400 240"
            >
              {/* Background Concentric Radar Guides */}
              <circle cx="400" cy="240" r="150" stroke="#06b6d4" strokeOpacity="0.08" strokeWidth="1" strokeDasharray="3 4" fill="none" />
              <circle cx="400" cy="240" r="190" stroke="#06b6d4" strokeOpacity="0.06" strokeWidth="1" strokeDasharray="4 6" fill="none" />
              <circle cx="400" cy="240" r="230" stroke="#38bdf8" strokeOpacity="0.04" strokeWidth="1" fill="none" />

              {/* Connecting Laser Links */}
              {links.map((link, idx) => {
                const sCoord = nodeCoordMap.get(link.source) || { x: 400, y: 240 };
                const tCoord = nodeCoordMap.get(link.target);
                if (!tCoord) return null;

                const midX = (sCoord.x + tCoord.x) / 2;
                const midY = (sCoord.y + tCoord.y) / 2;

                return (
                  <g key={`link-${idx}`}>
                    <line
                      x1={sCoord.x}
                      y1={sCoord.y}
                      x2={tCoord.x}
                      y2={tCoord.y}
                      stroke="#38bdf8"
                      strokeOpacity="0.35"
                      strokeWidth="1.5"
                      strokeDasharray="4 3"
                      markerEnd="url(#graph-arrow)"
                    />
                    {link.label && (
                      <text
                        x={midX}
                        y={midY - 4}
                        fill="#64748b"
                        fontSize="9"
                        fontFamily="monospace"
                        textAnchor="middle"
                        className="pointer-events-none select-none"
                      >
                        {link.label.replace('_', ' ')}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Node Circles */}
              {positionedNodes.map((node) => {
                const colors = getNodeColor(node);
                const isSelected = selectedNode?.id === node.id;
                const isRoot = node.id === indicator;

                return (
                  <g
                    key={`node-${node.id}`}
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNode(node);
                    }}
                    className="cursor-pointer group"
                  >
                    {/* Outer Glow Ring on Selected / Root */}
                    {(isSelected || isRoot) && (
                      <circle
                        r={isRoot ? 24 : 19}
                        fill="none"
                        stroke={colors.fill}
                        strokeWidth="2"
                        strokeOpacity="0.8"
                        filter="url(#node-glow)"
                        className="animate-pulse"
                      />
                    )}

                    {/* Node Main Circle */}
                    <circle
                      r={isRoot ? 17 : 13}
                      fill={colors.fill}
                      stroke="#0f172a"
                      strokeWidth="2.5"
                      className="transition-all duration-200 group-hover:scale-125"
                    />

                    {/* Node Type Indicator Icon Letter */}
                    <text
                      y="4"
                      textAnchor="middle"
                      fill="#0f172a"
                      fontSize={isRoot ? '10' : '8'}
                      fontWeight="bold"
                      fontFamily="monospace"
                      className="pointer-events-none select-none"
                    >
                      {node.type === 'file' ? 'F' : node.type === 'ip' ? 'IP' : node.type === 'domain' ? 'D' : node.type === 'threat_actor' ? 'A' : 'C'}
                    </text>

                    {/* Node Label Below */}
                    <text
                      y={isRoot ? 32 : 26}
                      textAnchor="middle"
                      fill={isSelected ? '#38bdf8' : '#cbd5e1'}
                      fontSize="9.5"
                      fontWeight={isRoot ? 'bold' : 'normal'}
                      fontFamily="monospace"
                      className="pointer-events-none select-none"
                    >
                      {node.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Quick HUD legend on bottom-left */}
          <div className="absolute bottom-3 left-3 flex items-center gap-3 bg-slate-950/80 px-3 py-1.5 rounded-lg border border-slate-800 text-[10px] font-mono backdrop-blur-sm pointer-events-none">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-rose-500" />
              <span className="text-slate-400">Malicious</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              <span className="text-slate-400">Suspicious</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="text-slate-400">Clean</span>
            </span>
            <span className="text-slate-500">· Click node to inspect/pivot</span>
          </div>
        </div>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="mt-4 p-4 rounded-xl bg-slate-950/90 border border-cyan-500/40 shadow-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 animate-in fade-in duration-200">
            <div className="flex items-start gap-3">
              <div
                className={`p-2 rounded-lg shrink-0 mt-0.5 ${
                  selectedNode.status === 'malicious'
                    ? 'bg-rose-500/20 text-rose-400'
                    : selectedNode.status === 'suspicious'
                    ? 'bg-amber-500/20 text-amber-400'
                    : 'bg-emerald-500/20 text-emerald-400'
                }`}
              >
                {selectedNode.type === 'ip' ? (
                  <Server className="w-4 h-4" />
                ) : selectedNode.type === 'domain' ? (
                  <Globe className="w-4 h-4" />
                ) : selectedNode.type === 'file' ? (
                  <FileCode className="w-4 h-4" />
                ) : (
                  <Lock className="w-4 h-4" />
                )}
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-100 font-mono">
                    {selectedNode.label}
                  </span>
                  <span
                    className={`text-[9px] font-mono uppercase px-2 py-0.2 rounded font-bold ${
                      selectedNode.status === 'malicious'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : selectedNode.status === 'suspicious'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}
                  >
                    {selectedNode.status}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800">
                    {selectedNode.type}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  {selectedNode.details || `Associated ${selectedNode.type} observed during threat infrastructure correlation.`}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
              <button
                type="button"
                onClick={() => handleCopy(selectedNode.id, 'node_id')}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 flex items-center gap-1 transition-colors cursor-pointer"
              >
                {copiedKey === 'node_id' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'node_id' ? 'Copied' : 'Copy IOC'}</span>
              </button>

              {onPivotIndicator && selectedNode.id !== indicator && (
                <button
                  type="button"
                  onClick={() => onPivotIndicator(selectedNode.id, (selectedNode.type === 'file' ? 'hash' : selectedNode.type) as IndicatorType)}
                  className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-bold text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer shadow-md"
                >
                  <span>Pivot Target</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
