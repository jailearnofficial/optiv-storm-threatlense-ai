/**
 * Threat Intelligence Provider Interface & Types
 * Defined in Sections 4 & 5 of SOC Analysis Design Spec
 */

import { IndicatorType } from '../detect.js';

export type ProviderName =
  | 'virustotal'
  | 'hybrid_analysis'
  | 'malwarebazaar'
  | 'abuseipdb'
  | 'urlhaus'
  | 'urlscan'
  | 'alienvault_otx';

export type ProviderStatus = 'ok' | 'not_found' | 'rate_limited' | 'no_data' | 'error';

export interface ProviderScore {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  threat_score?: number; // 0-100 (e.g. HA or AbuseIPDB)
  abuse_confidence?: number;
  total_reports?: number;
  pulse_count?: number;
}

export interface VTGraphNode {
  id: string;
  label: string;
  type: 'file' | 'domain' | 'ip' | 'url' | 'certificate' | 'threat_actor';
  status: 'malicious' | 'suspicious' | 'clean' | 'neutral';
  details?: string;
  x?: number;
  y?: number;
}

export interface VTGraphLink {
  source: string;
  target: string;
  label: string;
}

export interface VirusTotalGraphData {
  graph_id?: string;
  vt_graph_url: string;
  nodes: VTGraphNode[];
  links: VTGraphLink[];
}

export interface VTEngineDetection {
  engine_name: string;
  category: 'malicious' | 'suspicious' | 'undetected' | 'harmless' | 'type-unsupported';
  result: string | null;
  method: string;
  update?: string;
}

export interface VirusTotalExtendedDetails {
  analysis_stats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    timeout?: number;
  };
  engines: VTEngineDetection[];
  file_details?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
    ssdeep?: string;
    tlsh?: string;
    vhash?: string;
    file_type?: string;
    magic?: string;
    size_bytes?: number;
    meaningful_name?: string;
    names?: string[];
    pe_info?: {
      imphash?: string;
      compilation_timestamp?: string;
      entry_point?: number | string;
      sections_count?: number;
    };
    signature_info?: {
      verified?: boolean;
      signer?: string;
      product?: string;
      copyright?: string;
    };
    sandbox_verdicts?: {
      sandbox_name: string;
      category: string;
      confidence?: number;
    }[];
    crowdsourced_yara?: {
      rule_name: string;
      author?: string;
      description?: string;
      source?: string;
    }[];
  };
  network_details?: {
    whois?: string;
    registrar?: string;
    creation_date?: string;
    expiration_date?: string;
    asn?: number;
    as_owner?: string;
    country?: string;
    dns_records?: { type: string; value: string; ttl?: number }[];
    ssl_cert?: {
      issuer?: string;
      subject?: string;
      valid_from?: string;
      valid_to?: string;
      san_list?: string[];
    };
    http_response?: {
      status_code?: number;
      body_length?: number;
      server?: string;
      title?: string;
    };
    categories?: { detector: string; category: string }[];
  };
  vt_graph?: VirusTotalGraphData;
}

export interface HAMitreTechnique {
  technique_id: string; // e.g. "T1486"
  tactic: string; // e.g. "Impact"
  technique_name: string; // e.g. "Data Encrypted for Impact"
  att_id?: string;
  evidence: string;
  confidence?: 'high' | 'medium' | 'low';
}

export interface HAAVDetection {
  scanner: string;
  verdict: 'malicious' | 'suspicious' | 'clean';
  result?: string;
}

export interface HybridAnalysisDetails {
  threat_score: number; // 0 - 100
  threat_level: 'malicious' | 'suspicious' | 'clean' | 'whitelisted' | 'no_threat';
  indicator: string;
  indicator_type: IndicatorType;
  av_detect_percent: number; // e.g. 92
  av_detect_ratio: string; // e.g. "48/52"
  av_detections: HAAVDetection[];
  family?: string;
  environment?: string;
  job_id?: string;
  sha256?: string;
  mitre_attack: HAMitreTechnique[];
  sandbox_verdicts?: Array<{
    environment: string;
    verdict: string;
    threat_score: number;
  }>;
}

export interface OTXPulse {
  id: string;
  name: string;
  description?: string;
  author_name?: string;
  adversary?: string;
  created?: string;
  modified?: string;
  tags?: string[];
  targeted_countries?: string[];
  attack_ids?: string[];
  references?: string[];
  indicator_count?: number;
  vote?: number;
}

export interface AlienVaultOTXDetails {
  indicator: string;
  indicator_type: IndicatorType;
  pulse_count: number;
  adversary?: string;
  pulses: OTXPulse[];
  threat_score?: number;
  country_name?: string;
  asn?: string;
  targeted_countries?: string[];
  tags?: string[];
  references?: string[];
  validation?: string[];
  tlp?: string;
}

export interface ProviderResult {
  name: ProviderName;
  displayName: string;
  status: ProviderStatus;
  latency_ms: number;
  score: ProviderScore;
  headline: string;
  tags: string[];
  key_facts: Record<string, any>;
  link?: string;
  raw: Record<string, any>;
  vt_details?: VirusTotalExtendedDetails;
  vt_graph?: VirusTotalGraphData;
  ha_details?: HybridAnalysisDetails;
  otx_details?: AlienVaultOTXDetails;
  error?: string;
}

export interface MitreHint {
  technique_id: string;
  provider: string;
  evidence: string;
}

export interface RuleScoreResult {
  value: number; // 0 - 100
  band: 'clean' | 'low' | 'medium' | 'high';
  coverage: string; // e.g. "6/7"
  activeProviders: number;
  totalQueried: number;
  breakdown: Record<string, number>;
}

export interface EvidenceObject {
  id: string;
  indicator: {
    value: string; // defanged
    type: IndicatorType;
    normalized: string;
  };
  analyst_name?: string;
  collected_at: string;
  providers: ProviderResult[];
  related: {
    domains: string[];
    ips: string[];
    urls: string[];
    hashes: string[];
  };
  mitre_hints: MitreHint[];
  rule_score: RuleScoreResult;
  cached?: boolean;
  cached_at?: string;
  cache_age_ms?: number;
  retention_window_hours?: number;
}

export interface FilePayload {
  buffer: Buffer;
  originalname: string;
  mimetype?: string;
}

export interface ProviderAdapter {
  name: ProviderName;
  displayName: string;
  supports(type: IndicatorType): boolean;
  lookup(indicator: string, type: IndicatorType, filePayload?: FilePayload): Promise<ProviderResult>;
  submit?(indicator: string, type: IndicatorType, options?: any): Promise<any>;
}
