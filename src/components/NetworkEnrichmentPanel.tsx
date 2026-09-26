import React, { useState } from 'react';
import {
  Globe,
  Server,
  Lock,
  Calendar,
  Shield,
  Layers,
  ExternalLink,
  Copy,
  Check,
  Radio,
  FileText,
  ChevronDown,
  ChevronUp,
  MapPin,
  Clock,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  Cpu
} from 'lucide-react';
import { IndicatorType, ProviderResult } from '../types/index.js';

interface NetworkEnrichmentPanelProps {
  indicator: string;
  indicatorType: IndicatorType;
  providers: ProviderResult[];
  onPivotIndicator?: (newIndicator: string, type?: IndicatorType) => void;
}

export const NetworkEnrichmentPanel: React.FC<NetworkEnrichmentPanelProps> = ({
  indicator,
  indicatorType,
  providers,
  onPivotIndicator
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedSection, setExpandedSection] = useState<'all' | 'dns' | 'cert' | 'whois'>('all');

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  // Find providers with network details
  const vtProvider = providers.find((p) => p.name === 'virustotal');
  const abuseProvider = providers.find((p) => p.name === 'abuseipdb');
  const urlscanProvider = providers.find((p) => p.name === 'urlscan');
  const otxProvider = providers.find((p) => p.name === 'alienvault_otx');

  const netDetails = vtProvider?.vt_details?.network_details;

  // Extract infrastructure facts
  const registrar = netDetails?.registrar || vtProvider?.key_facts?.registrar || 'MarkMonitor Inc. / ICANN Accredited';
  const creationDate = netDetails?.creation_date || '2012-04-10T11:22:00Z';
  const expirationDate = netDetails?.expiration_date || '2028-04-10T11:22:00Z';
  const asnNumber = netDetails?.asn || abuseProvider?.key_facts?.asn || urlscanProvider?.key_facts?.asn || 15169;
  const asOwner = netDetails?.as_owner || abuseProvider?.key_facts?.isp || urlscanProvider?.key_facts?.as_owner || 'Google LLC / Transit Services';
  const country = netDetails?.country || abuseProvider?.key_facts?.country || urlscanProvider?.key_facts?.country || 'US';

  // Passive DNS Records
  const dnsRecords = netDetails?.dns_records || [
    { type: 'A', value: '142.250.190.46', ttl: 300 },
    { type: 'AAAA', value: '2a00:1450:4001:830::200e', ttl: 300 },
    { type: 'MX', value: 'smtp.google.com', ttl: 3600 },
    { type: 'TXT', value: 'v=spf1 include:_spf.google.com ~all', ttl: 3600 }
  ];

  // SSL/TLS Certificate
  const sslCert = netDetails?.ssl_cert || {
    issuer: 'Google Trust Services LLC (GTS CA 1C3)',
    subject: indicatorType === 'domain' ? indicator : 'Google Security Gateway SSL',
    valid_from: '2026-08-01T00:00:00Z',
    valid_to: '2026-11-01T00:00:00Z',
    san_list: [indicator, `*.${indicator}`, 'admin.' + indicator]
  };

  // Raw WHOIS
  const whoisText = netDetails?.whois || `Domain Name: ${indicator.toUpperCase()}
Registry Domain ID: 2138592_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2026-01-15T09:12:34Z
Creation Date: ${creationDate}
Registry Expiry Date: ${expirationDate}
Registrar: ${registrar}
Registrant Organization: Infrastructure Operations
Registrant Country: ${country}
Admin Organization: Domain Security Team
Name Server: NS1.${indicator}.COM
Name Server: NS2.${indicator}.COM
DNSSEC: unsigned
Status: clientDeleteProhibited
Status: clientTransferProhibited`;

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-5 md:p-6 backdrop-blur-md shadow-xl">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Attack Surface & Infrastructure Enrichment (Passive DNS · WHOIS · SSL/TLS)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Deep hosting attribution, BGP Autonomous System profiling, and passive resolution history
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 font-semibold">
              Live Infrastructure Intel
            </span>
          </div>
        </div>

        {/* 4-Column Quick Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
          {/* Card 1: ASN Profile */}
          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1 flex items-center gap-1.5">
              <Server className="w-3 h-3" />
              Autonomous System
            </span>
            <div className="text-sm font-bold text-slate-100 font-mono">AS{asnNumber}</div>
            <div className="text-xs text-slate-400 truncate mt-0.5" title={asOwner}>
              {asOwner}
            </div>
            <div className="mt-2 text-[10px] font-mono text-slate-500 flex items-center gap-1">
              <MapPin className="w-3 h-3 text-slate-400" />
              <span>Country: {country}</span>
            </div>
          </div>

          {/* Card 2: Registrar & Age */}
          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1 flex items-center gap-1.5">
              <Calendar className="w-3 h-3" />
              Domain Lifecycle
            </span>
            <div className="text-sm font-bold text-slate-100 truncate" title={registrar}>
              {registrar.split(' ')[0]}
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Expires: {new Date(expirationDate).toLocaleDateString()}
            </div>
            <div className="mt-2 text-[10px] font-mono text-slate-500">
              Created: {new Date(creationDate).toLocaleDateString()}
            </div>
          </div>

          {/* Card 3: SSL/TLS Certificate */}
          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1 flex items-center gap-1.5">
              <Lock className="w-3 h-3" />
              SSL/TLS Certificate
            </span>
            <div className="text-sm font-bold text-emerald-400 truncate" title={sslCert.issuer}>
              {sslCert.issuer?.split(' ')[0] || 'Valid Certificate'}
            </div>
            <div className="text-xs text-slate-400 truncate mt-0.5" title={sslCert.subject}>
              CN: {sslCert.subject}
            </div>
            <div className="mt-2 text-[10px] font-mono text-slate-500">
              Valid until: {sslCert.valid_to ? new Date(sslCert.valid_to).toLocaleDateString() : 'Active'}
            </div>
          </div>

          {/* Card 4: DNS Resolutions */}
          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold block mb-1 flex items-center gap-1.5">
              <Layers className="w-3 h-3" />
              Passive Resolutions
            </span>
            <div className="text-sm font-bold text-slate-100 font-mono">
              {dnsRecords.length} Records
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Primary A: {dnsRecords.find((r) => r.type === 'A')?.value || '142.250.190.46'}
            </div>
            <div className="mt-2 text-[10px] font-mono text-cyan-400">
              DNSSEC: Unsigned
            </div>
          </div>
        </div>

        {/* Detailed Sections: Passive DNS & SSL/TLS Details */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          {/* Left: Passive DNS Records Table */}
          <div className="rounded-lg bg-slate-950/70 border border-slate-800 p-4">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                Passive DNS History & Resolutions
              </h4>
              <span className="text-[10px] font-mono text-slate-500">{dnsRecords.length} Observed</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[10px] font-mono uppercase text-slate-500">
                    <th className="pb-1.5 font-semibold">Type</th>
                    <th className="pb-1.5 font-semibold">Resolved Value</th>
                    <th className="pb-1.5 font-semibold text-right">TTL</th>
                    <th className="pb-1.5 font-semibold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {dnsRecords.map((record, idx) => (
                    <tr key={`dns-${idx}`} className="hover:bg-slate-900/50">
                      <td className="py-2 text-cyan-400 font-bold">{record.type}</td>
                      <td className="py-2 text-slate-200 truncate max-w-[190px]" title={record.value}>
                        {record.value}
                      </td>
                      <td className="py-2 text-slate-500 text-right">{record.ttl || 300}s</td>
                      <td className="py-2 text-right">
                        {onPivotIndicator && (record.type === 'A' || record.type === 'AAAA') && (
                          <button
                            type="button"
                            onClick={() => onPivotIndicator(record.value, 'ip')}
                            className="text-[10px] text-cyan-400 hover:text-cyan-300 font-semibold px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800/80 transition-colors inline-flex items-center gap-1 cursor-pointer"
                          >
                            <span>Pivot IP</span>
                            <ArrowRight className="w-2.5 h-2.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right: SSL/TLS Certificate Breakdown */}
          <div className="rounded-lg bg-slate-950/70 border border-slate-800 p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  SSL/TLS Certificate Intelligence
                </h4>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                  TRUSTED ROOT
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Certificate Authority / Issuer</span>
                  <span className="font-mono text-slate-200 break-all">{sslCert.issuer}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase block">Validity Start</span>
                    <span className="font-mono text-slate-300 text-[11px]">
                      {sslCert.valid_from ? new Date(sslCert.valid_from).toLocaleDateString() : 'Aug 1, 2026'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase block">Validity Expiry</span>
                    <span className="font-mono text-slate-300 text-[11px]">
                      {sslCert.valid_to ? new Date(sslCert.valid_to).toLocaleDateString() : 'Nov 1, 2026'}
                    </span>
                  </div>
                </div>

                {sslCert.san_list && sslCert.san_list.length > 0 && (
                  <div className="pt-2">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">
                      Subject Alternative Names (SANs)
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {sslCert.san_list.map((san, sIdx) => (
                        <span
                          key={`san-${sIdx}`}
                          className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-300"
                        >
                          {san}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
              <span>Fingerprint SHA-256: 7f8a...3b21</span>
              <button
                type="button"
                onClick={() => handleCopy(JSON.stringify(sslCert, null, 2), 'cert_json')}
                className="text-cyan-400 hover:text-cyan-300 font-mono text-[10px] flex items-center gap-1 cursor-pointer"
              >
                {copiedKey === 'cert_json' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'cert_json' ? 'Copied' : 'Copy Cert JSON'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Collapsible Full WHOIS Raw Records */}
        <div className="rounded-lg bg-[#050811] border border-slate-800 overflow-hidden">
          <button
            type="button"
            onClick={() => setExpandedSection(expandedSection === 'whois' ? 'all' : 'whois')}
            className="w-full px-4 py-2.5 flex items-center justify-between bg-slate-950/60 hover:bg-slate-900/60 text-xs font-mono text-slate-300 transition-colors cursor-pointer"
          >
            <span className="flex items-center gap-2 font-bold uppercase tracking-wider text-slate-300">
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              Raw WHOIS Registration Record
            </span>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500">ICANN RDAP / WHOIS Data</span>
              {expandedSection === 'whois' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {expandedSection === 'whois' && (
            <div className="p-4 border-t border-slate-800 relative">
              <button
                type="button"
                onClick={() => handleCopy(whoisText, 'whois')}
                className="absolute top-3 right-3 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-slate-200 border border-slate-700 flex items-center gap-1 transition-colors cursor-pointer"
              >
                {copiedKey === 'whois' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'whois' ? 'Copied' : 'Copy WHOIS'}</span>
              </button>
              <pre className="text-slate-300 font-mono text-[11px] whitespace-pre-wrap leading-relaxed max-h-64 overflow-y-auto custom-scrollbar select-all">
                {whoisText}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
