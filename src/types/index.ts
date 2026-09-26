/**
 * Frontend Type Definitions
 */

export type IndicatorType = 'hash' | 'ip' | 'url' | 'domain';

export interface ProviderScore {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  threat_score?: number;
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

export interface ProviderResult {
  name: string;
  displayName: string;
  status: 'ok' | 'not_found' | 'rate_limited' | 'no_data' | 'error';
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

export interface HAMitreTechnique {
  technique_id: string;
  tactic: string;
  technique_name: string;
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
  threat_score: number;
  threat_level: 'malicious' | 'suspicious' | 'clean' | 'whitelisted' | 'no_threat';
  indicator: string;
  indicator_type: IndicatorType;
  av_detect_percent: number;
  av_detect_ratio: string;
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

export interface RuleScoreResult {
  value: number;
  band: 'clean' | 'low' | 'medium' | 'high';
  coverage: string;
  activeProviders: number;
  totalQueried: number;
  breakdown: Record<string, number>;
}

export interface EvidenceObject {
  id: string;
  indicator: {
    value: string;
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
  mitre_hints: Array<{
    technique_id: string;
    provider: string;
    evidence: string;
  }>;
  rule_score: RuleScoreResult;
  cached?: boolean;
  cached_at?: string;
  cache_age_ms?: number;
  retention_window_hours?: number;
}

export interface MitreAttackRecord {
  tactic_id: string;
  tactic: string;
  technique_id: string;
  technique: string;
  applies_to: {
    type: string;
    value: string;
  };
  evidence: string;
  source: 'provider' | 'ai_inferred';
  confidence: 'high' | 'medium' | 'low';
  detection: string;
  mitigation: string[];
  reference: string;
}

export interface IOCItem {
  type: 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';
  value: string;
  context: string;
  source: string;
}

export interface AIAnalysisVerdict {
  id: string;
  lookup_id: string;
  analyst_name?: string;
  verdict: 'Malicious' | 'Suspicious' | 'Benign' | 'False Positive' | 'Inconclusive';
  confidence: number;
  risk_score: number;
  threat_categories: string[];
  malware_family: string;
  executive_summary: string;
  technical_summary: string;
  category_breakdown: {
    file_hash?: string;
    domain?: string;
    ip?: string;
    url?: string;
    scoring?: string;
    hybrid_analysis?: string;
    alienvault_otx?: string;
    other?: string;
  };
  provider_agreement: Array<{
    provider: string;
    stance: 'malicious' | 'suspicious' | 'clean' | 'no_data';
    weight: number;
  }>;
  mitre_attack: MitreAttackRecord[];
  mitre_by_category: {
    file_hash: string[];
    domain: string[];
    ip: string[];
    url: string[];
  };
  iocs: IOCItem[];
  chart_data: {
    detections: Array<{ provider: string; malicious: number; total: number }>;
    score_by_provider: Array<{ provider: string; score: number }>;
    mitre_by_tactic: Array<{ tactic: string; count: number }>;
    timeline: Array<{ date: string; event: string }>;
  };
  recommended_actions: string[];
  limitations: string[];
  model: string;
  created_at: string;
}

export interface TrendingThreat {
  id: string;
  title: string;
  threat_actor: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  cves: string[];
  sectors: string[];
  region: string;
  source: string;
  timestamp: string;
  trend: string;
  summary: string;
  sample_indicator: {
    value: string;
    type: IndicatorType;
    label: string;
  };
  mitre_techniques: Array<{
    id: string;
    name: string;
  }>;
}

export interface HistoryItemDTO {
  id: string;
  indicator: string;
  defanged: string;
  type: string;
  createdAt: string;
  ruleScore: number;
  verdict?: string;
  analystName: string;
  actionType: 'file_submission' | 'indicator_search';
  fileName?: string;
  fileSize?: number;
  hashes: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

