/**
 * PDF / HTML Report and IOC Export Generator
 * Implements Section 8 & Section 10 of SOC Analysis Design Spec
 */

import { StoredAnalysis, StoredLookup } from '../db.js';
import { AIAnalysisVerdict } from '../ai/gemini.js';
import { VirusTotalGraphData } from '../providers/types.js';
import { IndicatorType } from '../detect.js';

export function generateIOCsCsv(analysis: AIAnalysisVerdict): string {
  // Prevent CSV Formula Injection (CWE-1236): Prepend single quote if cell starts with formula characters
  const sanitizeCell = (val: string): string => {
    let str = String(val || '');
    if (/^[=+\-@\t\r]/.test(str)) {
      str = `'${str}`;
    }
    return `"${str.replace(/"/g, '""')}"`;
  };

  const lines = ['Type,Value (Defanged),Context,Source'];
  for (const ioc of analysis.iocs) {
    const safeType = sanitizeCell(ioc.type);
    const safeVal = sanitizeCell(ioc.value);
    const safeCtx = sanitizeCell(ioc.context || '');
    const safeSrc = sanitizeCell(ioc.source || '');
    lines.push(`${safeType},${safeVal},${safeCtx},${safeSrc}`);
  }
  return lines.join('\n');
}

function escapeHtml(str: string): string {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function safeUrl(rawUrl?: string): string {
  if (!rawUrl) return '#';
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return escapeHtml(rawUrl);
    }
  } catch {
    // Malformed URL
  }
  return '#';
}

export function generateSTIXBundle(analysis: AIAnalysisVerdict, lookup: StoredLookup): any {
  const timestamp = analysis.created_at;
  const bundleId = `bundle--${analysis.id}`;

  const stixObjects: any[] = analysis.iocs.map((ioc, idx) => {
    let pattern = `[domain-name:value = '${ioc.value}']`;
    if (ioc.type === 'ip') pattern = `[ipv4-addr:value = '${ioc.value.replace(/\[\.\]/g, '.')}']`;
    else if (ioc.type === 'url') pattern = `[url:value = '${ioc.value.replace(/hxxp/i, 'http').replace(/\[\.\]/g, '.')}']`;
    else if (ioc.type === 'sha256') pattern = `[file:hashes.'SHA-256' = '${ioc.value}']`;
    else if (ioc.type === 'md5') pattern = `[file:hashes.MD5 = '${ioc.value}']`;

    return {
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${analysis.id}-${idx}`,
      created: timestamp,
      modified: timestamp,
      name: `${analysis.verdict} Indicator: ${ioc.value}`,
      description: ioc.context,
      indicator_types: [analysis.verdict.toLowerCase().replace(/\s+/g, '-')],
      pattern,
      pattern_type: 'stix',
      valid_from: timestamp,
      confidence: Math.round(analysis.confidence * 100),
      labels: analysis.threat_categories
    };
  });

  const otxProvider = lookup.evidence?.providers?.find((p: any) => p.name === 'alienvault_otx');
  const adversary = otxProvider?.otx_details?.adversary || otxProvider?.key_facts?.adversary;

  if (adversary) {
    const actorId = `threat-actor--${analysis.id}-actor`;
    stixObjects.push({
      type: 'threat-actor',
      spec_version: '2.1',
      id: actorId,
      created: timestamp,
      modified: timestamp,
      name: adversary,
      description: `Attributed adversary reported by AlienVault OTX community threat intelligence for indicator ${lookup.defanged}.`,
      threat_actor_types: ['nation-state', 'cybercrime-syndicate'],
      confidence: 85
    });

    if (stixObjects[0]) {
      stixObjects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${analysis.id}-actor-ind`,
        created: timestamp,
        modified: timestamp,
        relationship_type: 'indicates',
        source_ref: stixObjects[0].id,
        target_ref: actorId
      });
    }
  }

  // Correlate AlienVault OTX pulses as STIX campaigns
  const pulses = otxProvider?.otx_details?.pulses || [];
  for (const pulse of pulses.slice(0, 5)) {
    const campId = `campaign--${analysis.id}-${pulse.id || Math.random().toString(36).substring(2, 7)}`;
    stixObjects.push({
      type: 'campaign',
      spec_version: '2.1',
      id: campId,
      created: pulse.created || timestamp,
      modified: pulse.modified || timestamp,
      name: pulse.name,
      description: pulse.description || `AlienVault OTX Community Threat Pulse authored by ${pulse.author_name || 'Community'}`,
      aliases: pulse.tags || [],
      confidence: 80
    });
  }

  if (analysis.malware_family) {
    const malwareId = `malware--${analysis.id}-mal`;
    stixObjects.push({
      type: 'malware',
      spec_version: '2.1',
      id: malwareId,
      created: timestamp,
      modified: timestamp,
      name: analysis.malware_family,
      is_family: true,
      description: `Identified malware family ${analysis.malware_family} isolated via multi-engine telemetry and behavioral sandbox execution.`,
      malware_types: analysis.threat_categories
    });
  }

  return {
    type: 'bundle',
    id: bundleId,
    objects: stixObjects
  };
}

function renderVTGraphSvg(graph?: VirusTotalGraphData): string {
  if (!graph || !graph.nodes || graph.nodes.length === 0) return '';

  const width = 760;
  const height = 260;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = 95;

  const rootNode = graph.nodes[0];
  const otherNodes = graph.nodes.slice(1, 8);

  const nodePositions = new Map<string, { x: number; y: number }>();
  nodePositions.set(rootNode.id, { x: centerX, y: centerY });

  otherNodes.forEach((node, idx) => {
    const angle = (idx / otherNodes.length) * 2 * Math.PI - Math.PI / 2;
    const x = centerX + Math.cos(angle) * (radius + (idx % 2 === 0 ? 18 : -10));
    const y = centerY + Math.sin(angle) * (radius * 0.85);
    nodePositions.set(node.id, { x, y });
  });

  // Render connector links
  const linksSvg = graph.links.slice(0, 10).map((link) => {
    const sourcePos = nodePositions.get(link.source) || { x: centerX, y: centerY };
    const targetPos = nodePositions.get(link.target) || { x: centerX + 40, y: centerY + 40 };
    const midX = (sourcePos.x + targetPos.x) / 2;
    const midY = (sourcePos.y + targetPos.y) / 2;

    return `
      <g>
        <line x1="${sourcePos.x}" y1="${sourcePos.y}" x2="${targetPos.x}" y2="${targetPos.y}" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="4 2" />
        <rect x="${midX - 35}" y="${midY - 7}" width="70" height="14" fill="#ffffff" rx="3" stroke="#cbd5e1" stroke-width="0.8" />
        <text x="${midX}" y="${midY + 3}" font-size="8" font-family="monospace" fill="#475569" text-anchor="middle">${link.label}</text>
      </g>
    `;
  }).join('');

  // Render nodes
  const nodesSvg = [rootNode, ...otherNodes].map((node) => {
    const pos = nodePositions.get(node.id) || { x: centerX, y: centerY };
    const isRoot = node.id === rootNode.id;
    const nodeColor = node.status === 'malicious' ? '#ef4444' : node.status === 'suspicious' ? '#f59e0b' : '#10b981';
    const bgColor = node.status === 'malicious' ? '#fee2e2' : node.status === 'suspicious' ? '#fef3c7' : '#dcfce7';
    const r = isRoot ? 20 : 13;
    const label = node.label.length > 20 ? node.label.substring(0, 17) + '...' : node.label;

    return `
      <g>
        <circle cx="${pos.x}" cy="${pos.y}" r="${r}" fill="${bgColor}" stroke="${nodeColor}" stroke-width="${isRoot ? 3 : 2}" />
        <text x="${pos.x}" y="${pos.y + (isRoot ? 4 : 3)}" font-size="${isRoot ? 9 : 7}" font-weight="bold" font-family="sans-serif" fill="${nodeColor}" text-anchor="middle">${node.type.substring(0, 3).toUpperCase()}</text>
        <text x="${pos.x}" y="${pos.y + r + 11}" font-size="8.5" font-family="monospace" font-weight="${isRoot ? 'bold' : 'normal'}" fill="#0f172a" text-anchor="middle">${label}</text>
      </g>
    `;
  }).join('');

  return `
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; margin-bottom: 12px; text-align: center;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-size: 11px;">
        <span style="font-weight: 700; color: #0f172a; text-transform: uppercase;">VT Graph Topological Schema</span>
        <a href="${safeUrl(graph.vt_graph_url)}" target="_blank" rel="noopener noreferrer" style="color: #0284c7; text-decoration: none; font-weight: 600;">Open in VirusTotal Graph Explorer &rarr;</a>
      </div>
      <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: auto; max-height: 240px;">
        <rect width="${width}" height="${height}" fill="#f8fafc" rx="6" />
        ${linksSvg}
        ${nodesSvg}
      </svg>
    </div>
  `;
}

function renderRecommendedActionsTable(actions: string[]): string {
  if (!actions || actions.length === 0) {
    return '<p style="font-size: 11px; color: #64748b; font-style: italic; margin-top: 4px;">No immediate incident response actions designated.</p>';
  }

  const rows = actions.map((rawAction, idx) => {
    // Strip leading numbering e.g. "1. " or "1) "
    const cleanAction = rawAction.replace(/^\d+[\.\)]\s*/, '').trim();

    let domain = '';
    let procedure = cleanAction;

    const colonIdx = cleanAction.indexOf(':');
    if (colonIdx > 0 && colonIdx < 45) {
      domain = cleanAction.substring(0, colonIdx).trim();
      procedure = cleanAction.substring(colonIdx + 1).trim();
    } else {
      if (/perimeter|egress|firewall|proxy|edl|border|network|dns/i.test(cleanAction)) {
        domain = 'Perimeter & Egress';
      } else if (/edr|endpoint|falcon|defender|memory|mutex|process|antivirus/i.test(cleanAction)) {
        domain = 'EDR & Endpoint';
      } else if (/siem|splunk|sentinel|hunt|beacon|query|log/i.test(cleanAction)) {
        domain = 'SIEM Threat Hunting';
      } else if (/contain|isolate|quarantine|credential|reset|eradication/i.test(cleanAction)) {
        domain = 'Containment & Eradication';
      } else if (/patch|vulnerability|update|remediat/i.test(cleanAction)) {
        domain = 'Remediation & Patching';
      } else {
        domain = `Response Phase ${idx + 1}`;
      }
    }

    // Determine Priority and SLA
    let priority = 'P2 - High';
    let priorityBadge = 'badge-suspicious';
    let sla = '< 2 Hours';

    const textLower = cleanAction.toLowerCase();
    if (
      idx === 0 ||
      textLower.includes('perimeter') ||
      textLower.includes('block') ||
      textLower.includes('isolate') ||
      textLower.includes('quarantine') ||
      textLower.includes('ban') ||
      textLower.includes('immediate')
    ) {
      priority = 'P1 - Critical';
      priorityBadge = 'badge-malicious';
      sla = 'Immediate (< 1h)';
    } else if (
      textLower.includes('edr') ||
      textLower.includes('endpoint') ||
      textLower.includes('siem') ||
      textLower.includes('hunt') ||
      textLower.includes('sweep')
    ) {
      priority = 'P2 - High';
      priorityBadge = 'badge-suspicious';
      sla = '< 4 Hours';
    } else if (
      textLower.includes('credential') ||
      textLower.includes('reset') ||
      textLower.includes('patch') ||
      textLower.includes('audit')
    ) {
      priority = 'P2 - High';
      priorityBadge = 'badge-suspicious';
      sla = '< 8 Hours';
    } else {
      priority = 'P3 - Medium';
      priorityBadge = 'badge-clean';
      sla = '< 24 Hours';
    }

    // Escape and highlight MD5, SHA-1, SHA-256 hashes cleanly
    const escapedProc = escapeHtml(procedure)
      // SHA-256 (64 hex characters)
      .replace(/\b([a-fA-F0-9]{64})\b/g, '<code class="monospace" style="background: #f1f5f9; padding: 1.5px 5px; border-radius: 4px; border: 1px solid #cbd5e1; font-size: 10px; color: #0f172a; word-break: break-all;">$1</code>')
      // SHA-1 (40 hex characters)
      .replace(/\b([a-fA-F0-9]{40})\b/g, '<code class="monospace" style="background: #f1f5f9; padding: 1.5px 5px; border-radius: 4px; border: 1px solid #cbd5e1; font-size: 10px; color: #0f172a; word-break: break-all;">$1</code>')
      // MD5 (32 hex characters)
      .replace(/\b([a-fA-F0-9]{32})\b/g, '<code class="monospace" style="background: #f1f5f9; padding: 1.5px 5px; border-radius: 4px; border: 1px solid #cbd5e1; font-size: 10px; color: #0f172a; word-break: break-all;">$1</code>');

    const stepNum = idx < 9 ? `0${idx + 1}` : `${idx + 1}`;

    return `
      <tr style="${idx % 2 === 1 ? 'background: #f8fafc;' : 'background: #ffffff;'}">
        <td style="text-align: center; vertical-align: top; font-family: monospace; font-weight: 700; color: #64748b; font-size: 11px; padding: 9px 6px;">
          ${stepNum}
        </td>
        <td style="vertical-align: top; padding: 9px 10px; width: 175px;">
          <div style="font-weight: 700; color: #0f172a; font-size: 11px; margin-bottom: 2px;">
            ${escapeHtml(domain)}
          </div>
          <div style="font-size: 9.5px; color: #64748b; text-transform: uppercase; font-family: sans-serif; letter-spacing: 0.3px;">
            SOC Playbook
          </div>
        </td>
        <td style="vertical-align: top; text-align: center; padding: 9px 8px; width: 125px;">
          <span class="badge ${priorityBadge}" style="display: inline-block; font-size: 9.5px; font-weight: 700; padding: 2px 7px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.3px;">
            ${priority}
          </span>
          <div style="font-size: 9.5px; color: #64748b; margin-top: 3px; font-family: monospace;">
            ${sla}
          </div>
        </td>
        <td style="vertical-align: top; padding: 9px 12px; line-height: 1.6; color: #1e293b; font-size: 11px; word-break: break-word; overflow-wrap: anywhere;">
          ${escapedProc}
        </td>
      </tr>
    `;
  }).join('');

  return `
    <table style="width: 100%; border-collapse: collapse; margin-top: 8px; margin-bottom: 18px; font-size: 11px; border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden;">
      <thead>
        <tr style="background: #f1f5f9; border-bottom: 2px solid #cbd5e1;">
          <th style="width: 38px; text-align: center; padding: 8px 6px; font-size: 10px; text-transform: uppercase; color: #475569; letter-spacing: 0.5px;">#</th>
          <th style="width: 175px; text-align: left; padding: 8px 10px; font-size: 10px; text-transform: uppercase; color: #475569; letter-spacing: 0.5px;">IR Phase / Domain</th>
          <th style="width: 125px; text-align: center; padding: 8px 8px; font-size: 10px; text-transform: uppercase; color: #475569; letter-spacing: 0.5px;">Priority & SLA</th>
          <th style="text-align: left; padding: 8px 12px; font-size: 10px; text-transform: uppercase; color: #475569; letter-spacing: 0.5px;">Prescribed Mitigation & Countermeasure Action</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

export function generateHtmlReport(analysis: AIAnalysisVerdict, lookup: StoredLookup): string {
  const evidence = lookup.evidence;
  const verdictColors: Record<string, { bg: string; text: string; border: string }> = {
    Malicious: { bg: '#EF4444', text: '#FFFFFF', border: '#DC2626' },
    Suspicious: { bg: '#F59E0B', text: '#000000', border: '#D97706' },
    Benign: { bg: '#10B981', text: '#FFFFFF', border: '#059669' },
    'False Positive': { bg: '#3B82F6', text: '#FFFFFF', border: '#2563EB' },
    Inconclusive: { bg: '#6B7280', text: '#FFFFFF', border: '#4B5563' }
  };

  const vColor = verdictColors[analysis.verdict] || verdictColors.Inconclusive;

  // Extract VirusTotal details and graph
  const vtProvider = evidence.providers.find((p) => p.name === 'virustotal');
  const vtDetails = vtProvider?.vt_details;
  const vtGraph = vtProvider?.vt_graph;

  // Extract Hybrid Analysis details
  const haProvider = evidence.providers.find((p) => p.name === 'hybrid_analysis');
  const haDetails = haProvider?.ha_details;

  // Extract AlienVault OTX details
  const otxProvider = evidence.providers.find((p) => p.name === 'alienvault_otx');
  let otxDetails = otxProvider?.otx_details;
  if (!otxDetails && otxProvider) {
    const pulseCount = typeof otxProvider.score?.pulse_count === 'number'
      ? otxProvider.score.pulse_count
      : (otxProvider.key_facts?.pulse_count || 0);
    otxDetails = {
      indicator: lookup.indicator,
      indicator_type: lookup.type as IndicatorType,
      pulse_count: pulseCount,
      adversary: otxProvider.key_facts?.adversary,
      pulses: [],
      targeted_countries: (otxProvider.key_facts?.targeted_countries as string[]) || [],
      tags: otxProvider.tags || []
    };
  }

  const analystName = escapeHtml(
    analysis.analyst_name ||
    lookup.analystName ||
    lookup.evidence?.analyst_name ||
    'Unassigned Analyst'
  );

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>OPTIV S.T.O.R.M ThreatLense AI Report - ${escapeHtml(lookup.defanged)}</title>
  <style>
    @page { size: A4; margin: 14mm; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #1e293b;
      background: #ffffff;
      line-height: 1.5;
      font-size: 12px;
      margin: 0;
      padding: 24px;
    }
    .header-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #0f172a;
      padding-bottom: 12px;
      margin-bottom: 20px;
    }
    .brand-title {
      font-size: 19px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.5px;
    }
    .brand-subtitle {
      font-size: 10px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .verdict-box {
      background: ${vColor.bg};
      color: ${vColor.text};
      padding: 10px 18px;
      border-radius: 6px;
      text-align: right;
    }
    .verdict-label {
      font-size: 10px;
      text-transform: uppercase;
      opacity: 0.9;
    }
    .verdict-value {
      font-size: 20px;
      font-weight: 800;
      line-height: 1.1;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 10px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 10px;
      margin-bottom: 18px;
    }
    .meta-item .label {
      font-size: 10px;
      color: #64748b;
      text-transform: uppercase;
    }
    .meta-item .value {
      font-size: 12px;
      font-weight: 600;
      color: #0f172a;
      font-family: monospace;
      word-break: break-all;
    }
    h2 {
      font-size: 13px;
      font-weight: 700;
      color: #0f172a;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 4px;
      margin-top: 20px;
      margin-bottom: 8px;
    }
    h3 {
      font-size: 11px;
      font-weight: 700;
      color: #334155;
      text-transform: uppercase;
      margin-top: 10px;
      margin-bottom: 6px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 14px;
      font-size: 11px;
    }
    th, td {
      border: 1px solid #e2e8f0;
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f1f5f9;
      font-weight: 600;
      color: #334155;
    }
    .monospace { font-family: monospace; }
    .badge {
      display: inline-block;
      padding: 2px 5px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
    }
    .badge-malicious { background: #fee2e2; color: #991b1b; }
    .badge-suspicious { background: #fef3c7; color: #92400e; }
    .badge-clean { background: #dcfce7; color: #166534; }
    .sub-card {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 10px;
      margin-bottom: 14px;
    }
    .threat-score-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 6px;
      font-family: monospace;
      font-weight: 700;
      font-size: 12px;
    }
    .footer {
      margin-top: 32px;
      border-top: 1px solid #e2e8f0;
      padding-top: 10px;
      font-size: 10px;
      color: #64748b;
      display: flex;
      justify-content: space-between;
    }
    @media print {
      body { padding: 0; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="header-banner">
    <div>
      <div class="brand-title">OPTIV S.T.O.R.M · ThreatLense AI</div>
      <div class="brand-subtitle">Automated Multi-Source Threat Intelligence & Incident Dossier</div>
    </div>
    <div class="verdict-box">
      <div class="verdict-label">Analysis Verdict</div>
      <div class="verdict-value">${analysis.verdict}</div>
      <div style="font-size: 10px;">Confidence: ${Math.round(analysis.confidence * 100)}% · Risk: ${analysis.risk_score}/100</div>
    </div>
  </div>

  <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-left: 4px solid #0284c7; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between;">
    <div>
      <span style="font-size: 13px; font-weight: 700; color: #0369a1; font-family: monospace;">
        SOC analyst name: ${analystName}
      </span>
    </div>
    <div style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">
      OPTIV S.T.O.R.M Incident Response Investigator
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-item">
      <div class="label">Target Indicator</div>
      <div class="value">${escapeHtml(lookup.defanged)}</div>
    </div>
    <div class="meta-item">
      <div class="label">Indicator Type</div>
      <div class="value">${escapeHtml(lookup.type.toUpperCase())}</div>
    </div>
    <div class="meta-item">
      <div class="label">Investigator Profile</div>
      <div class="value" style="color: #0369a1;">SOC analyst name: ${analystName}</div>
    </div>
    <div class="meta-item">
      <div class="label">Report Timestamp (UTC)</div>
      <div class="value">${escapeHtml(analysis.created_at.replace('T', ' ').substring(0, 19))}</div>
    </div>
    <div class="meta-item">
      <div class="label">Platform / AI Engine</div>
      <div class="value" style="color: #4f46e5;">OPTIV S.T.O.R.M · ThreatLense AI (${escapeHtml(analysis.model)})</div>
    </div>
  </div>

  <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 18px;">
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px;">
      <div style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 600;">VirusTotal Multi-Scanner</div>
      <div style="font-size: 13px; font-weight: 800; color: ${vtDetails?.analysis_stats?.malicious ? '#dc2626' : '#166534'}; margin-top: 2px;">
        ${vtDetails?.analysis_stats?.malicious ? `${vtDetails.analysis_stats.malicious} Security Engines Flagged` : escapeHtml(vtProvider?.headline || 'Clean / Undetected')}
      </div>
    </div>
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px;">
      <div style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 600;">Hybrid Analysis Falcon Sandbox</div>
      <div style="font-size: 13px; font-weight: 800; color: ${haDetails && haDetails.threat_score >= 70 ? '#dc2626' : haDetails && haDetails.threat_score >= 35 ? '#d97706' : '#166534'}; margin-top: 2px;">
        ${haDetails ? `Threat Score ${haDetails.threat_score}/100 (${escapeHtml(haDetails.threat_level.toUpperCase())})` : escapeHtml(haProvider?.headline || 'Not Tested')}
      </div>
    </div>
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px;">
      <div style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 600;">AlienVault OTX Community Intel</div>
      <div style="font-size: 13px; font-weight: 800; color: ${otxDetails && otxDetails.pulse_count > 0 ? '#dc2626' : '#166534'}; margin-top: 2px;">
        ${otxDetails && otxDetails.pulse_count > 0
          ? `${otxDetails.pulse_count} Threat Pulses${otxDetails.adversary ? ` · ${escapeHtml(otxDetails.adversary)}` : ''}`
          : '0 Threat Pulses (Clean)'}
      </div>
    </div>
  </div>

  <h2>1. Executive Summary</h2>
  <p style="font-size: 12px; line-height: 1.6; color: #334155;">
    ${escapeHtml(analysis.executive_summary)}
  </p>

  <h2>2. Recommended Incident Response Actions</h2>
  ${renderRecommendedActionsTable(analysis.recommended_actions)}

  ${haDetails ? `
    <h2>3. Hybrid Analysis (Falcon Sandbox) Detailed Assessment</h2>
    <div class="sub-card">
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 8px;">
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">Threat Score</div>
          <div style="font-size: 18px; font-weight: 800; font-family: monospace; color: ${haDetails.threat_score >= 70 ? '#b91c1c' : haDetails.threat_score >= 35 ? '#d97706' : '#166534'};">
            ${haDetails.threat_score} / 100
          </div>
        </div>
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">AV Detection Ratio</div>
          <div style="font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 2px;">
            ${haDetails.av_detect_ratio} (${haDetails.av_detect_percent}%)
          </div>
        </div>
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">Analyzed Indicator</div>
          <div style="font-size: 11px; font-family: monospace; color: #0f172a; word-break: break-all; margin-top: 2px;">
            ${haDetails.indicator}
          </div>
        </div>
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">Sandbox Verdict / Family</div>
          <div style="margin-top: 2px;">
            <span class="badge ${haDetails.threat_level === 'malicious' ? 'badge-malicious' : haDetails.threat_level === 'suspicious' ? 'badge-suspicious' : 'badge-clean'}">${haDetails.threat_level.toUpperCase()}</span>
            <span style="font-weight: 600; font-size: 11px; margin-left: 4px;">${haDetails.family || 'N/A'}</span>
          </div>
        </div>
      </div>
      <div style="font-size: 10px; color: #64748b;">
        Environment: <strong>${haDetails.environment || 'Falcon Sandbox 64-bit'}</strong>
      </div>
      ${analysis.category_breakdown?.hybrid_analysis ? `
        <div style="margin-top: 8px; background: #ffffff; border: 1px solid #e2e8f0; border-left: 3px solid #0284c7; padding: 8px 12px; border-radius: 4px; font-size: 11px; color: #334155; line-height: 1.5;">
          <strong style="color: #0369a1;">AI Detonation Analysis:</strong> ${escapeHtml(analysis.category_breakdown.hybrid_analysis)}
        </div>
      ` : ''}
    </div>

    <h3>Hybrid Analysis Multi-AV Scanner Detections</h3>
    <table>
      <thead>
        <tr>
          <th>Security Vendor / Scanner</th>
          <th>Verdict</th>
          <th>Detection Signature / Finding</th>
        </tr>
      </thead>
      <tbody>
        ${haDetails.av_detections.map((av) => `
          <tr>
            <td><strong>${av.scanner}</strong></td>
            <td><span class="badge ${av.verdict === 'malicious' ? 'badge-malicious' : av.verdict === 'suspicious' ? 'badge-suspicious' : 'badge-clean'}">${av.verdict.toUpperCase()}</span></td>
            <td class="monospace">${av.result || 'Clean'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h3>MITRE ATT&CK Techniques Identified by Hybrid Analysis</h3>
    <table>
      <thead>
        <tr>
          <th>Technique ID</th>
          <th>Tactic</th>
          <th>Technique Name</th>
          <th>Behavioral Sandbox Evidence</th>
        </tr>
      </thead>
      <tbody>
        ${haDetails.mitre_attack.map((m) => `
          <tr>
            <td class="monospace" style="color: #2563eb; font-weight: 700;">${m.technique_id}</td>
            <td><strong>${m.tactic}</strong></td>
            <td>${m.technique_name}</td>
            <td>${m.evidence}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : ''}

  ${(otxDetails || otxProvider) ? `
    <h2>4. AlienVault OTX Community Threat Intelligence & Pulses</h2>
    <div class="sub-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="font-weight: 700; color: #0f172a; text-transform: uppercase; font-size: 11px;">Open Threat Exchange (OTX) Telemetry Profile</span>
          <span class="badge ${otxDetails && otxDetails.pulse_count >= 3 ? 'badge-malicious' : otxDetails && otxDetails.pulse_count > 0 ? 'badge-suspicious' : 'badge-clean'}">
            ${otxDetails && otxDetails.pulse_count > 0 ? 'ACTIVE COMMUNITY SIGNALS' : 'CLEAN / UNINDEXED'}
          </span>
        </div>
        <a href="${safeUrl(otxProvider?.link || `https://otx.alienvault.com/indicator/${lookup.type}/${encodeURIComponent(lookup.indicator)}`)}" target="_blank" rel="noopener noreferrer" style="font-size: 11px; color: #0284c7; font-weight: 600; text-decoration: none;">
          Launch AlienVault OTX Portal &rarr;
        </a>
      </div>

      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 8px;">
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">Total Threat Pulses</div>
          <div style="font-size: 18px; font-weight: 800; font-family: monospace; color: ${otxDetails && otxDetails.pulse_count > 0 ? '#dc2626' : '#166534'};">
            ${otxDetails?.pulse_count || 0} Pulses
          </div>
        </div>
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">Attributed Adversary</div>
          <div style="font-size: 12px; font-weight: 700; color: #0f172a; margin-top: 3px;">
            ${otxDetails?.adversary ? `<span class="badge badge-malicious">${escapeHtml(otxDetails.adversary)}</span>` : '<span style="color:#64748b;">Unassigned / None</span>'}
          </div>
        </div>
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">Targeted Geographies</div>
          <div style="font-size: 11px; font-weight: 600; color: #334155; margin-top: 3px;">
            ${otxDetails?.targeted_countries?.length ? escapeHtml(otxDetails.targeted_countries.slice(0, 6).join(', ')) : 'Global / None'}
          </div>
        </div>
        <div>
          <div style="font-size: 10px; color: #64748b; text-transform: uppercase;">Community Reputation</div>
          <div style="margin-top: 3px;">
            <span class="badge ${otxDetails && otxDetails.pulse_count >= 3 ? 'badge-malicious' : otxDetails && otxDetails.pulse_count > 0 ? 'badge-suspicious' : 'badge-clean'}">
              ${otxDetails && otxDetails.pulse_count >= 3 ? 'HIGH COMMUNITY RISK' : otxDetails && otxDetails.pulse_count > 0 ? 'MODERATE COMMUNITY RISK' : 'NO THREAT SIGNALS'}
            </span>
          </div>
        </div>
      </div>

      ${analysis.category_breakdown?.alienvault_otx ? `
        <div style="margin-top: 8px; background: #ffffff; border: 1px solid #e2e8f0; border-left: 3px solid #7c3aed; padding: 8px 12px; border-radius: 4px; font-size: 11px; color: #334155; line-height: 1.5;">
          <strong style="color: #6d28d9;">AI Threat Pulse Synthesis:</strong> ${escapeHtml(analysis.category_breakdown.alienvault_otx)}
        </div>
      ` : ''}

      ${otxDetails?.tags && otxDetails.tags.length > 0 ? `
        <div style="margin-top: 8px; display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">
          <span style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 600; margin-right: 4px;">Community Tags:</span>
          ${otxDetails.tags.slice(0, 10).map((tag) => `<span class="badge" style="background: #f1f5f9; color: #334155;">#${escapeHtml(tag)}</span>`).join(' ')}
        </div>
      ` : ''}

      ${(!otxDetails || otxDetails.pulse_count === 0) ? `
        <div style="margin-top: 10px; padding: 10px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; font-size: 11px; color: #166534;">
          <strong>Clean / Unindexed in OTX:</strong> This indicator was queried against the AlienVault Open Threat Exchange global repository and has 0 associated community threat pulses. No security researchers or threat intelligence feeds have reported active malicious activity for this indicator in OTX.
        </div>
      ` : ''}
    </div>

    ${otxDetails && otxDetails.pulses && otxDetails.pulses.length > 0 ? `
      <h3>Correlated Community Threat Pulses (${otxDetails.pulses.length})</h3>
      <table>
        <thead>
          <tr>
            <th>Pulse Name / Intelligence Campaign</th>
            <th>Intel Author</th>
            <th>Observed</th>
            <th>Adversary</th>
            <th>ATT&CK IDs</th>
            <th>Indicators / Votes</th>
            <th>Tags</th>
          </tr>
        </thead>
        <tbody>
          ${otxDetails.pulses.slice(0, 8).map((pulse) => `
            <tr>
              <td>
                <strong>${escapeHtml(pulse.name)}</strong>
                ${pulse.description ? `<br/><span style="color: #64748b; font-size: 9.5px;">${escapeHtml(pulse.description.substring(0, 120))}${pulse.description.length > 120 ? '...' : ''}</span>` : ''}
              </td>
              <td>${escapeHtml(pulse.author_name || 'Community')}</td>
              <td class="monospace" style="font-size: 10px;">${pulse.created ? pulse.created.split('T')[0] : 'N/A'}</td>
              <td>${pulse.adversary ? `<span class="badge badge-malicious">${escapeHtml(pulse.adversary)}</span>` : '<span style="color:#94a3b8;">None</span>'}</td>
              <td class="monospace" style="color: #2563eb; font-weight: 600; font-size: 10px;">${pulse.attack_ids && pulse.attack_ids.length ? pulse.attack_ids.join(', ') : 'N/A'}</td>
              <td class="monospace" style="font-size: 10px;">${pulse.indicator_count ?? 1} IOCs / &uarr;${pulse.vote ?? 0}</td>
              <td>${pulse.tags && pulse.tags.length ? pulse.tags.slice(0, 3).map((t) => `<span class="badge" style="background:#f1f5f9; color:#475569; font-size: 9px;">${escapeHtml(t)}</span>`).join(' ') : 'None'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : ''}

    ${otxDetails && otxDetails.references && otxDetails.references.length > 0 ? `
      <div style="margin-top: 8px; font-size: 10.5px; color: #475569;">
        <strong>Advisory References:</strong> ${otxDetails.references.slice(0, 5).map((ref) => `<a href="${safeUrl(ref)}" target="_blank" rel="noopener noreferrer" style="color: #0284c7; margin-right: 8px; text-decoration: none;">${escapeHtml(ref)}</a>`).join(' ')}
      </div>
    ` : ''}
  ` : ''}

  ${vtDetails || vtGraph ? `
    <h2>5. VirusTotal Telemetry & VT Graph Visualization</h2>
    <div class="sub-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <div>
          <span style="font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600;">Detection Ratio: </span>
          <span style="font-size: 14px; font-weight: 800; font-family: monospace; color: ${vtDetails?.analysis_stats?.malicious ? '#dc2626' : '#166534'};">
            ${vtDetails?.analysis_stats?.malicious || 0} / ${((vtDetails?.analysis_stats?.malicious || 0) + (vtDetails?.analysis_stats?.suspicious || 0) + (vtDetails?.analysis_stats?.undetected || 0) + (vtDetails?.analysis_stats?.harmless || 0)) || 72}
          </span>
          <span style="font-size: 11px; color: #64748b;"> security vendors flagged</span>
        </div>
        ${vtGraph?.vt_graph_url ? `
          <a href="${safeUrl(vtGraph.vt_graph_url)}" target="_blank" rel="noopener noreferrer" style="font-size: 11px; color: #0284c7; font-weight: 600; text-decoration: none;">Launch External VT Graph &rarr;</a>
        ` : ''}
      </div>

      ${vtDetails?.file_details ? `
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px; font-size: 10.5px; margin-bottom: 8px; background: #ffffff; padding: 8px; border-radius: 4px; border: 1px solid #e2e8f0;">
          <div><span style="color:#64748b;">SHA-256:</span> <span class="monospace">${vtDetails.file_details.sha256 || 'N/A'}</span></div>
          <div><span style="color:#64748b;">MD5:</span> <span class="monospace">${vtDetails.file_details.md5 || 'N/A'}</span></div>
          <div><span style="color:#64748b;">File Type:</span> <strong>${vtDetails.file_details.file_type || 'Executable'}</strong> (${vtDetails.file_details.size_bytes ? `${Math.round(vtDetails.file_details.size_bytes / 1024)} KB` : 'N/A'})</div>
          <div><span style="color:#64748b;">Imphash:</span> <span class="monospace">${vtDetails.file_details.pe_info?.imphash || 'N/A'}</span></div>
        </div>
      ` : ''}

      ${vtDetails?.network_details ? `
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; font-size: 10.5px; margin-bottom: 8px; background: #ffffff; padding: 8px; border-radius: 4px; border: 1px solid #e2e8f0;">
          <div><span style="color:#64748b;">ASN:</span> <strong>AS${vtDetails.network_details.asn || '15169'}</strong> (${vtDetails.network_details.as_owner || 'Transit'})</div>
          <div><span style="color:#64748b;">Registrar:</span> ${vtDetails.network_details.registrar || 'MarkMonitor Inc.'}</div>
          <div><span style="color:#64748b;">Country:</span> ${vtDetails.network_details.country || 'US'}</div>
        </div>
      ` : ''}
    </div>

    ${renderVTGraphSvg(vtGraph)}

    ${vtGraph?.links && vtGraph.links.length > 0 ? `
      <h3>VT Graph Topological Entity Relationships</h3>
      <table>
        <thead>
          <tr>
            <th>Source Indicator</th>
            <th>Relationship Link</th>
            <th>Target Entity / Node</th>
            <th>Entity Type</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${vtGraph.links.slice(0, 8).map((link) => {
            const targetNode = vtGraph.nodes.find((n) => n.id === link.target);
            return `
              <tr>
                <td class="monospace">${link.source.length > 25 ? link.source.substring(0, 22) + '...' : link.source}</td>
                <td><span class="badge" style="background: #e0f2fe; color: #0369a1;">${link.label}</span></td>
                <td class="monospace" style="font-weight: 600;">${link.target}</td>
                <td>${(targetNode?.type || 'entity').toUpperCase()}</td>
                <td><span class="badge ${targetNode?.status === 'malicious' ? 'badge-malicious' : targetNode?.status === 'suspicious' ? 'badge-suspicious' : 'badge-clean'}">${(targetNode?.status || 'clean').toUpperCase()}</span></td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : ''}

    ${vtDetails?.engines && vtDetails.engines.length > 0 ? `
      <h3>Top Security Vendor AV Signatures (VirusTotal)</h3>
      <table>
        <thead>
          <tr>
            <th>Security Engine</th>
            <th>Category</th>
            <th>Detection Signature</th>
            <th>Method</th>
          </tr>
        </thead>
        <tbody>
          ${vtDetails.engines.slice(0, 8).map((eng) => `
            <tr>
              <td><strong>${eng.engine_name}</strong></td>
              <td><span class="badge ${eng.category === 'malicious' ? 'badge-malicious' : eng.category === 'suspicious' ? 'badge-suspicious' : 'badge-clean'}">${eng.category.toUpperCase()}</span></td>
              <td class="monospace" style="color: ${eng.result ? '#b91c1c' : '#64748b'};">${eng.result || 'Clean / Undetected'}</td>
              <td>${eng.method}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : ''}
  ` : ''}

  <h2>6. Threat Intelligence Provider Fan-Out</h2>
  <table>
    <thead>
      <tr>
        <th>Provider</th>
        <th>Status</th>
        <th>Detection / Finding Headline</th>
        <th>Latency</th>
      </tr>
    </thead>
    <tbody>
      ${evidence.providers.map((p) => `
        <tr>
          <td><strong>${escapeHtml(p.displayName)}</strong></td>
          <td><span class="badge ${p.score.malicious ? 'badge-malicious' : p.score.suspicious ? 'badge-suspicious' : 'badge-clean'}">${escapeHtml(p.status.toUpperCase())}</span></td>
          <td>${escapeHtml(p.headline)}</td>
          <td>${p.latency_ms} ms</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  ${analysis.mitre_attack.length > 0 ? `
    <h2>7. MITRE ATT&CK Matrix Mapping (Enterprise)</h2>
    <table>
      <thead>
        <tr>
          <th>Tactic</th>
          <th>Technique</th>
          <th>Evidence & Correlation</th>
          <th>Source</th>
          <th>Mitigation</th>
        </tr>
      </thead>
      <tbody>
        ${analysis.mitre_attack.map((m) => `
          <tr>
            <td><strong>${escapeHtml(m.tactic)}</strong><br/><span style="color:#64748b; font-size:9.5px;">${escapeHtml(m.tactic_id)}</span></td>
            <td><strong>${escapeHtml(m.technique)}</strong><br/><span class="monospace" style="color:#2563eb; font-weight: 600;">${escapeHtml(m.technique_id)}</span></td>
            <td>${escapeHtml(m.evidence)}</td>
            <td><span class="badge" style="background:#f1f5f9; color:#334155;">${escapeHtml(m.source)}</span></td>
            <td>${m.mitigation && m.mitigation.length ? escapeHtml(m.mitigation.join(', ')) : 'N/A'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : ''}

  ${analysis.iocs.length > 0 ? `
    <h2>8. Verified Indicators of Compromise (IOCs)</h2>
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Value (Defanged)</th>
          <th>Context / Role</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        ${analysis.iocs.map((ioc) => `
          <tr>
            <td><span class="monospace">${escapeHtml(ioc.type.toUpperCase())}</span></td>
            <td class="monospace" style="color:#b91c1c; font-weight:600;">${escapeHtml(ioc.value)}</td>
            <td>${escapeHtml(ioc.context)}</td>
            <td>${escapeHtml(ioc.source)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : ''}

  <h2>9. Technical Findings & ThreatLense AI Analysis Methodology</h2>
  <p style="font-size: 11.5px; color: #475569; line-height: 1.5;">
    ${escapeHtml(analysis.technical_summary)}
  </p>

  <h2>10. Analysis Limitations & Audit Disclaimers</h2>
  <ul style="color: #64748b; font-size: 10.5px; line-height: 1.5;">
    ${analysis.limitations.map((lim) => `<li>${escapeHtml(lim)}</li>`).join('')}
    <li>This document was compiled through automated multi-source threat intelligence aggregation and ThreatLense AI-assisted triage (${escapeHtml(analysis.model)}). Definitive blocking or legal actions must be validated by a certified SOC analyst.</li>
  </ul>

  <div class="footer">
    <div>OPTIV S.T.O.R.M Portal · ThreatLense AI · Generated on ${new Date().toUTCString()} · SOC analyst name: ${analystName}</div>
    <div>Document ID: ${analysis.id}</div>
  </div>
</body>
</html>`;
}
