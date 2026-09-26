/**
 * Persistent Storage for Lookups and Analyses with 24-Hour Retention Cache
 * Section 5: lookups (id, indicator, type, created_at, evidence_json)
 * and analyses (id, lookup_id, verdict_json, model, created_at)
 */

import fs from 'fs';
import path from 'path';
import { EvidenceObject } from './providers/types.js';
import { IndicatorType } from './detect.js';

export const RETENTION_WINDOW_MS = 24 * 60 * 60 * 1000; // 24-hour strict retention window

export interface StoredLookup {
  id: string;
  indicator: string;
  type: string;
  defanged: string;
  createdAt: string;
  evidence: EvidenceObject;
  analystName?: string;
  fileName?: string;
  fileSize?: number;
  actionType?: 'file_submission' | 'indicator_search';
  hashes?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

export interface StoredAnalysis {
  id: string;
  lookupId: string;
  verdict: any;
  model: string;
  createdAt: string;
  analystName?: string;
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

export interface CacheMatchResult {
  lookup: StoredLookup;
  ageMs: number;
  expiresInMs: number;
  matchType: 'exact' | 'hash_cross_match' | 'domain_normalized' | 'url_normalized';
}

function normalizeHash(str?: string | null): string | null {
  if (!str) return null;
  const clean = str.trim().toLowerCase();
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(clean)) {
    return clean;
  }
  return null;
}

function normalizeDomain(str?: string | null): string | null {
  if (!str) return null;
  let clean = str.trim().toLowerCase();
  clean = clean.replace(/^hxxps?:\/\//i, '');
  clean = clean.replace(/^https?:\/\//i, '');
  clean = clean.replace(/\[\.\]/g, '.');
  clean = clean.replace(/\[:\]/g, ':');
  // strip path and query if any
  const slashIdx = clean.indexOf('/');
  if (slashIdx !== -1) {
    clean = clean.substring(0, slashIdx);
  }
  // strip port
  const colonIdx = clean.indexOf(':');
  if (colonIdx !== -1) {
    clean = clean.substring(0, colonIdx);
  }
  clean = clean.replace(/\/+$/, '');
  return clean.length > 0 ? clean : null;
}

function normalizeUrl(str?: string | null): string | null {
  if (!str) return null;
  let clean = str.trim();
  clean = clean.replace(/^hxxps:\/\//i, 'https://');
  clean = clean.replace(/^hxxp:\/\//i, 'http://');
  clean = clean.replace(/\[\.\]/g, '.');
  clean = clean.replace(/\[:\]/g, ':');
  clean = clean.replace(/\/+$/, '');
  return clean.length > 0 ? clean : null;
}

class Database {
  private dbPath: string;
  private lookups: Map<string, StoredLookup> = new Map();
  private analyses: Map<string, StoredAnalysis> = new Map();
  private purgeInterval?: NodeJS.Timeout;

  constructor() {
    this.dbPath = path.resolve(process.cwd(), 'data');
    this.init();

    // Automatically purge records older than 24 hours every 5 minutes
    this.purgeInterval = setInterval(() => {
      this.purgeOldRecords();
    }, 5 * 60 * 1000);
    if (this.purgeInterval.unref) {
      this.purgeInterval.unref();
    }
  }

  private init() {
    try {
      if (!fs.existsSync(this.dbPath)) {
        fs.mkdirSync(this.dbPath, { recursive: true });
      }
      const lookupsFile = path.join(this.dbPath, 'lookups.json');
      const analysesFile = path.join(this.dbPath, 'analyses.json');

      if (fs.existsSync(lookupsFile)) {
        const raw = fs.readFileSync(lookupsFile, 'utf-8');
        const list: StoredLookup[] = JSON.parse(raw);
        for (const item of list) this.lookups.set(item.id, item);
      }
      if (fs.existsSync(analysesFile)) {
        const raw = fs.readFileSync(analysesFile, 'utf-8');
        const list: StoredAnalysis[] = JSON.parse(raw);
        for (const item of list) this.analyses.set(item.id, item);
      }

      // If store is empty or has fewer than 2 records, seed rich initial 24h investigations
      if (this.lookups.size < 2) {
        this.seedInitialHistory();
      }

      // Purge any existing records loaded from disk that exceed 24 hours
      this.purgeOldRecords();
    } catch (err) {
      console.error('Error initializing data store:', err);
    }
  }

  /**
   * Seed realistic 24-hour SOC investigation history across multiple analysts
   */
  private seedInitialHistory() {
    const now = Date.now();
    const seeds: Array<{
      lookup: StoredLookup;
      analysis: StoredAnalysis;
    }> = [
      {
        lookup: {
          id: 'lkp_seed_wannacry',
          indicator: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8',
          type: 'hash',
          defanged: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8',
          createdAt: new Date(now - 38 * 60 * 1000).toISOString(),
          analystName: 'Alex Rivera (Lead Threat Hunter)',
          actionType: 'indicator_search',
          hashes: {
            sha256: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8',
            md5: '514e9d5ecd9f3e8f68257640c1e0e844'
          },
          evidence: {
            id: 'lkp_seed_wannacry',
            indicator: {
              value: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8',
              type: 'hash',
              normalized: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8'
            },
            analyst_name: 'Alex Rivera (Lead Threat Hunter)',
            collected_at: new Date(now - 38 * 60 * 1000).toISOString(),
            providers: [
              {
                name: 'virustotal',
                displayName: 'VirusTotal v3',
                status: 'ok',
                latency_ms: 180,
                score: { malicious: 71, suspicious: 0, harmless: 0, undetected: 1 },
                headline: '71/72 security vendors flagged as Win32.WannaCry.Ransomware',
                tags: ['ransomware', 'wannacry', 'wcry', 'eternalblue'],
                key_facts: { file_type: 'Win32 EXE', family: 'WannaCry' },
                raw: { simulated: true }
              },
              {
                name: 'hybrid_analysis',
                displayName: 'Hybrid Analysis (Falcon Sandbox)',
                status: 'ok',
                latency_ms: 290,
                score: { threat_score: 100, malicious: 1 },
                headline: 'Falcon Sandbox: 100/100 Threat Score (Ransomware Execution)',
                tags: ['ransomware', 'vssadmin-tamper', 'tor-client-embedded'],
                key_facts: { family: 'WannaCry' },
                raw: { simulated: true }
              },
              {
                name: 'alienvault_otx',
                displayName: 'AlienVault OTX',
                status: 'ok',
                latency_ms: 210,
                score: { pulse_count: 118, malicious: 1 },
                headline: 'Linked to 118 pulses, APT38 / Lazarus Group',
                tags: ['ransomware', 'lazarus', 'wannacry'],
                key_facts: { adversary: 'Lazarus Group (APT38)', pulse_count: 118 },
                raw: { simulated: true }
              }
            ],
            related: {
              domains: ['www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com', 'iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com'],
              ips: ['194.109.6.93', '217.182.169.148'],
              urls: ['http://www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com'],
              hashes: ['ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8', '514e9d5ecd9f3e8f68257640c1e0e844']
            },
            mitre_hints: [
              { technique_id: 'T1486', provider: 'hybrid-analysis', evidence: 'Bulk AES encryption of user documents with .WNCRY extension' },
              { technique_id: 'T1490', provider: 'hybrid-analysis', evidence: 'Executed vssadmin delete shadows /all /quiet' },
              { technique_id: 'T1210', provider: 'virustotal', evidence: 'Exploited SMBv1 EternalBlue MS17-010 vulnerability' }
            ],
            rule_score: {
              value: 98,
              band: 'high',
              coverage: '6/6',
              activeProviders: 6,
              totalQueried: 6,
              breakdown: { virustotal: 100, hybrid_analysis: 100, alienvault_otx: 95 }
            }
          }
        },
        analysis: {
          id: 'anl_seed_wannacry',
          lookupId: 'lkp_seed_wannacry',
          model: 'gemini-2.5-flash',
          createdAt: new Date(now - 38 * 60 * 1000).toISOString(),
          analystName: 'Alex Rivera (Lead Threat Hunter)',
          verdict: {
            id: 'anl_seed_wannacry',
            lookup_id: 'lkp_seed_wannacry',
            indicator: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8',
            indicator_type: 'hash',
            analyst_name: 'Alex Rivera (Lead Threat Hunter)',
            verdict: 'Malicious',
            confidence: 0.99,
            model: 'gemini-2.5-flash',
            created_at: new Date(now - 38 * 60 * 1000).toISOString(),
            headline: 'Confirmed WannaCry 2.0 Ransomware Weaponized with EternalBlue Exploit',
            summary: 'High-confidence malware consensus across VirusTotal (71/72) and CrowdStrike Falcon Sandbox (100/100). The artifact demonstrates autonomous worm-like propagation via SMBv1 EternalBlue (MS17-010), disables Volume Shadow Copies (vssadmin), and initiates bulk AES file encryption. Attributed to Lazarus Group (APT38) across 118 AlienVault OTX community pulses.',
            threat_actors: ['Lazarus Group (APT38)'],
            malware_family: 'WannaCry',
            campaign: 'Global WannaCryptor Outbreak',
            targeted_sectors: ['Healthcare', 'Telecommunications', 'Financial Services', 'Government'],
            rule_vs_ai_comparison: {
              rule_score: 98,
              rule_band: 'high',
              ai_verdict: 'Malicious',
              agreement: true,
              divergence_reason: 'Complete multi-vendor rule consensus aligning with behavioral sandbox indicators and threat actor telemetry.'
            },
            mitre_attack: [
              { technique_id: 'T1486', technique_name: 'Data Encrypted for Impact', tactic: 'Impact', evidence: 'Encrypts targeted file extensions with AES-128 and appends .WNCRY' },
              { technique_id: 'T1490', technique_name: 'Inhibit System Recovery', tactic: 'Impact', evidence: 'Executes vssadmin delete shadows /all /quiet and disables Windows Startup Recovery' },
              { technique_id: 'T1210', technique_name: 'Exploitation of Remote Services', tactic: 'Lateral Movement', evidence: 'Worm functionality scanning TCP port 445 utilizing MS17-010 EternalBlue exploit' }
            ],
            iocs: [
              { type: 'sha256', value: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8', status: 'confirmed_malicious', source_feed: 'VirusTotal & Hybrid Analysis' },
              { type: 'domain', value: 'www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com', status: 'confirmed_malicious', source_feed: 'Hybrid Analysis Falcon Sandbox' },
              { type: 'ip', value: '194.109.6.93', status: 'suspicious', source_feed: 'urlscan.io' }
            ],
            recommended_actions: [
              'Perimeter Containment: Enforce immediate egress block on port 445 and block indicator across firewalls and web proxies',
              'Endpoint Isolation & EDR: Quarantine infected hosts and upload SHA-256 to CrowdStrike Falcon / Defender custom IOC blocklist',
              'Patch Verification: Audit enterprise-wide deployment of Microsoft Security Bulletin MS17-010 across all endpoints',
              'SIEM Threat Hunt: Correlate SMB connection spikes and vssadmin invocation within the last 90 days in Splunk/Sentinel'
            ],
            limitations: ['Sandbox execution terminated killswitch domain query without observing live encryption on airgapped environment']
          }
        }
      },
      {
        lookup: {
          id: 'lkp_seed_eicar',
          indicator: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
          type: 'hash',
          defanged: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
          createdAt: new Date(now - 110 * 60 * 1000).toISOString(),
          analystName: 'Sarah Chen (Tier-2 SOC)',
          actionType: 'indicator_search',
          hashes: {
            sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
          },
          evidence: {
            id: 'lkp_seed_eicar',
            indicator: {
              value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
              type: 'hash',
              normalized: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
            },
            analyst_name: 'Sarah Chen (Tier-2 SOC)',
            collected_at: new Date(now - 110 * 60 * 1000).toISOString(),
            providers: [
              {
                name: 'virustotal',
                displayName: 'VirusTotal v3',
                status: 'ok',
                latency_ms: 220,
                score: { malicious: 68, suspicious: 1, harmless: 0, undetected: 5 },
                headline: '68/74 engines detected as EICAR-Test-File',
                tags: ['eicar', 'test-file', 'dos-executable'],
                key_facts: { file_type: 'ASCII test string', names: ['eicar.com'] },
                raw: { simulated: true }
              },
              {
                name: 'hybrid_analysis',
                displayName: 'Hybrid Analysis (Falcon Sandbox)',
                status: 'ok',
                latency_ms: 310,
                score: { threat_score: 100, malicious: 1 },
                headline: 'Falcon Sandbox: 100/100 Threat Score (EICAR-Test-Signature)',
                tags: ['eicar', 'antivirus-test'],
                key_facts: { family: 'EICAR-Test-Signature' },
                raw: { simulated: true }
              }
            ],
            related: { domains: [], ips: ['89.238.73.97'], urls: [], hashes: [] },
            mitre_hints: [
              { technique_id: 'T1204.002', provider: 'hybrid-analysis', evidence: 'Simulated malware execution behavior test' }
            ],
            rule_score: {
              value: 83,
              band: 'high',
              coverage: '6/6',
              activeProviders: 6,
              totalQueried: 6,
              breakdown: { virustotal: 100, hybrid_analysis: 100, malwarebazaar: 100 }
            }
          }
        },
        analysis: {
          id: 'anl_seed_eicar',
          lookupId: 'lkp_seed_eicar',
          model: 'gemini-2.5-flash',
          createdAt: new Date(now - 110 * 60 * 1000).toISOString(),
          analystName: 'Sarah Chen (Tier-2 SOC)',
          verdict: {
            id: 'anl_seed_eicar',
            lookup_id: 'lkp_seed_eicar',
            indicator: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
            indicator_type: 'hash',
            analyst_name: 'Sarah Chen (Tier-2 SOC)',
            verdict: 'Malicious',
            confidence: 0.95,
            model: 'gemini-2.5-flash',
            created_at: new Date(now - 110 * 60 * 1000).toISOString(),
            headline: 'Standard Anti-Virus Benchmark Test Signature (EICAR)',
            summary: 'Universal detection across 68 AV engines. Classified as malicious by standard anti-malware definition benchmarking suites to validate endpoint scanner detection triggers without introducing actual payload danger.',
            threat_actors: ['None (Standard Industry Test)'],
            malware_family: 'EICAR-Test-File',
            campaign: 'AV / EDR Sensor Verification',
            targeted_sectors: ['Global Enterprise'],
            rule_vs_ai_comparison: {
              rule_score: 83,
              rule_band: 'high',
              ai_verdict: 'Malicious',
              agreement: true,
              divergence_reason: 'AV signatures trigger high rule score for validation test purposes.'
            },
            mitre_attack: [
              { technique_id: 'T1204.002', technique_name: 'User Execution: Malicious File', tactic: 'Execution', evidence: 'Simulated execution testing detection coverage' }
            ],
            iocs: [
              { type: 'sha256', value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', status: 'confirmed_malicious', source_feed: 'VirusTotal' }
            ],
            recommended_actions: [
              'Verify that all enterprise EDR agents correctly quarantined the test sample',
              'Record verification results in SOC Sensor Health log'
            ],
            limitations: ['Non-destructive test string designed for scanner validation']
          }
        }
      },
      {
        lookup: {
          id: 'lkp_seed_tor_ip',
          indicator: '185.220.101.5',
          type: 'ip',
          defanged: '185.220.101[.]5',
          createdAt: new Date(now - 220 * 60 * 1000).toISOString(),
          analystName: 'Marcus Vance (Incident Response)',
          actionType: 'indicator_search',
          hashes: {},
          evidence: {
            id: 'lkp_seed_tor_ip',
            indicator: {
              value: '185.220.101[.]5',
              type: 'ip',
              normalized: '185.220.101.5'
            },
            analyst_name: 'Marcus Vance (Incident Response)',
            collected_at: new Date(now - 220 * 60 * 1000).toISOString(),
            providers: [
              {
                name: 'abuseipdb',
                displayName: 'AbuseIPDB',
                status: 'ok',
                latency_ms: 140,
                score: { abuse_confidence: 100 },
                headline: 'Abuse Confidence: 100% · 1,420 reports · Tor Exit Node',
                tags: ['tor-exit-node', 'ssh-bruteforce', 'scanner'],
                key_facts: { is_tor: true, total_reports: 1420, country_code: 'DE' },
                raw: { simulated: true }
              },
              {
                name: 'virustotal',
                displayName: 'VirusTotal v3',
                status: 'ok',
                latency_ms: 190,
                score: { malicious: 14, suspicious: 4, harmless: 52 },
                headline: '14/86 vendors flagged IP as Malicious (Proxy / Anonymizer)',
                tags: ['tor', 'proxy', 'scanner'],
                key_facts: { asn: 'AS208294' },
                raw: { simulated: true }
              }
            ],
            related: { domains: [], ips: ['185.220.101.5'], urls: [], hashes: [] },
            mitre_hints: [
              { technique_id: 'T1090.003', provider: 'abuseipdb', evidence: 'Verified public Tor Exit Node routing anonymized traffic' },
              { technique_id: 'T1110.001', provider: 'abuseipdb', evidence: 'Automated SSH/RDP dictionary credential spraying' }
            ],
            rule_score: {
              value: 79,
              band: 'high',
              coverage: '5/5',
              activeProviders: 5,
              totalQueried: 5,
              breakdown: { abuseipdb: 100, virustotal: 60 }
            }
          }
        },
        analysis: {
          id: 'anl_seed_tor_ip',
          lookupId: 'lkp_seed_tor_ip',
          model: 'gemini-2.5-flash',
          createdAt: new Date(now - 220 * 60 * 1000).toISOString(),
          analystName: 'Marcus Vance (Incident Response)',
          verdict: {
            id: 'anl_seed_tor_ip',
            lookup_id: 'lkp_seed_tor_ip',
            indicator: '185.220.101.5',
            indicator_type: 'ip',
            analyst_name: 'Marcus Vance (Incident Response)',
            verdict: 'Suspicious',
            confidence: 0.88,
            model: 'gemini-2.5-flash',
            created_at: new Date(now - 220 * 60 * 1000).toISOString(),
            headline: 'Active Tor Exit Node Conducting Automated Credential Spraying',
            summary: 'AbuseIPDB rates 100% confidence with over 1,400 abuse reports documenting brute-force attempts against SSH and RDP endpoints. Confirmed active Tor Exit Node located in Germany (AS208294). Represents high operational risk for ingress authentication services.',
            threat_actors: ['Unattributed Anonymized Actors'],
            malware_family: 'Automated Scanner / Brute-Forcer',
            campaign: 'Opportunistic SSH & RDP Dictionary Attacks',
            targeted_sectors: ['Cloud Infrastructure', 'Remote Access Services'],
            rule_vs_ai_comparison: {
              rule_score: 79,
              rule_band: 'high',
              ai_verdict: 'Suspicious',
              agreement: true,
              divergence_reason: 'Categorized as Suspicious rather than inherently Malicious due to Tor network multi-tenant shared egress architecture.'
            },
            mitre_attack: [
              { technique_id: 'T1090.003', technique_name: 'Proxy: Multi-hop Proxy', tactic: 'Command and Control', evidence: 'Traffic routed through Tor anonymization circuits' },
              { technique_id: 'T1110.001', technique_name: 'Brute Force: Password Guessing', tactic: 'Credential Access', evidence: 'Repeated unauthorized authentication attempts against port 22' }
            ],
            iocs: [
              { type: 'ip', value: '185.220.101.5', status: 'suspicious', source_feed: 'AbuseIPDB & VirusTotal' }
            ],
            recommended_actions: [
              'Enforce inbound blocking of 185.220.101.5 on edge firewalls and load balancers',
              'Audit identity provider logs (Okta / Azure AD) for successful logins from this IP',
              'Subscribe perimeter edge to automated Tor exit node dynamic blocklists'
            ],
            limitations: ['Shared Tor exit node may intermittently route innocent web user requests']
          }
        }
      }
    ];

    for (const seed of seeds) {
      if (!this.lookups.has(seed.lookup.id)) {
        this.lookups.set(seed.lookup.id, seed.lookup);
      }
      if (!this.analyses.has(seed.analysis.id)) {
        this.analyses.set(seed.analysis.id, seed.analysis);
      }
    }
    this.persist();
  }

  /**
   * Purge lookups and analyses older than 24 hours from in-memory and disk store
   */
  purgeOldRecords(maxAgeMs = RETENTION_WINDOW_MS): number {
    const cutoff = Date.now() - maxAgeMs;
    let purgedLookups = 0;
    let purgedAnalyses = 0;

    for (const [id, lookup] of this.lookups.entries()) {
      const createdTime = new Date(lookup.createdAt).getTime();
      if (isNaN(createdTime) || createdTime < cutoff) {
        this.lookups.delete(id);
        purgedLookups++;
      }
    }

    for (const [id, analysis] of this.analyses.entries()) {
      const createdTime = new Date(analysis.createdAt).getTime();
      if (isNaN(createdTime) || createdTime < cutoff || !this.lookups.has(analysis.lookupId)) {
        this.analyses.delete(id);
        purgedAnalyses++;
      }
    }

    if (purgedLookups > 0 || purgedAnalyses > 0) {
      this.persist();
    }

    return purgedLookups;
  }

  private persist() {
    try {
      if (!fs.existsSync(this.dbPath)) {
        fs.mkdirSync(this.dbPath, { recursive: true });
      }
      fs.writeFileSync(
        path.join(this.dbPath, 'lookups.json'),
        JSON.stringify(Array.from(this.lookups.values()), null, 2)
      );
      fs.writeFileSync(
        path.join(this.dbPath, 'analyses.json'),
        JSON.stringify(Array.from(this.analyses.values()), null, 2)
      );
    } catch (err) {
      console.error('Error persisting data store:', err);
    }
  }

  saveLookup(lookup: StoredLookup): void {
    this.purgeOldRecords();
    this.lookups.set(lookup.id, lookup);
    this.persist();
  }

  getLookup(id: string): StoredLookup | undefined {
    return this.lookups.get(id);
  }

  getLookupByIndicator(normalized: string): StoredLookup | undefined {
    const match = this.findCachedLookup(normalized);
    return match ? match.lookup : undefined;
  }

  /**
   * Comprehensive 24-Hour Cache Search for Hash, Domain, or URL
   * - If an entry matches and was created within the last 24 hours, returns CacheMatchResult.
   * - If expired (> 24 hours), it purges the record and returns undefined, indicating
   *   fresh telemetry must be fetched from threat feeds.
   */
  findCachedLookup(indicator: string, type?: IndicatorType | string): CacheMatchResult | undefined {
    if (!indicator || typeof indicator !== 'string') return undefined;

    // Purge expired records first
    this.purgeOldRecords();

    const now = Date.now();
    const cleanRaw = indicator.trim().toLowerCase();
    const queryHash = normalizeHash(cleanRaw);
    const queryDomain = normalizeDomain(cleanRaw);
    const queryUrl = normalizeUrl(indicator);

    for (const lookup of this.lookups.values()) {
      const createdTime = new Date(lookup.createdAt).getTime();
      if (isNaN(createdTime)) continue;

      const ageMs = now - createdTime;
      // If older than 24 hours, it is expired per the retention policy
      if (ageMs >= RETENTION_WINDOW_MS) {
        continue;
      }

      const expiresInMs = Math.max(0, RETENTION_WINDOW_MS - ageMs);

      // 1. Direct exact indicator or defanged match
      if (
        lookup.indicator.toLowerCase() === cleanRaw ||
        lookup.defanged.toLowerCase() === cleanRaw ||
        lookup.evidence?.indicator?.value?.toLowerCase() === cleanRaw ||
        lookup.evidence?.indicator?.normalized?.toLowerCase() === cleanRaw
      ) {
        return {
          lookup,
          ageMs,
          expiresInMs,
          matchType: 'exact'
        };
      }

      // 2. Hash Cross-Match (MD5, SHA-1, SHA-256)
      if (queryHash) {
        const storedMd5 = lookup.hashes?.md5?.toLowerCase();
        const storedSha1 = lookup.hashes?.sha1?.toLowerCase();
        const storedSha256 = lookup.hashes?.sha256?.toLowerCase();
        const storedIndicatorHash = normalizeHash(lookup.indicator);
        const relatedHashes = (lookup.evidence?.related?.hashes || []).map((h) => h.toLowerCase());

        if (
          queryHash === storedMd5 ||
          queryHash === storedSha1 ||
          queryHash === storedSha256 ||
          queryHash === storedIndicatorHash ||
          relatedHashes.includes(queryHash)
        ) {
          return {
            lookup,
            ageMs,
            expiresInMs,
            matchType: 'hash_cross_match'
          };
        }
      }

      // 3. Domain Normalized Match
      if (queryDomain && (type === 'domain' || lookup.type === 'domain' || !type)) {
        const storedDomain = normalizeDomain(lookup.indicator);
        const storedDefangedDomain = normalizeDomain(lookup.defanged);
        const relatedDomains = (lookup.evidence?.related?.domains || [])
          .map((d) => normalizeDomain(d))
          .filter(Boolean);

        if (
          queryDomain === storedDomain ||
          queryDomain === storedDefangedDomain ||
          relatedDomains.includes(queryDomain)
        ) {
          return {
            lookup,
            ageMs,
            expiresInMs,
            matchType: 'domain_normalized'
          };
        }
      }

      // 4. URL Normalized Match
      if (queryUrl && (type === 'url' || lookup.type === 'url' || !type)) {
        const storedUrl = normalizeUrl(lookup.indicator);
        const storedDefangedUrl = normalizeUrl(lookup.defanged);
        const relatedUrls = (lookup.evidence?.related?.urls || [])
          .map((u) => normalizeUrl(u))
          .filter(Boolean);

        if (
          (storedUrl && queryUrl.toLowerCase() === storedUrl.toLowerCase()) ||
          (storedDefangedUrl && queryUrl.toLowerCase() === storedDefangedUrl.toLowerCase()) ||
          relatedUrls.some((u) => u && u.toLowerCase() === queryUrl.toLowerCase())
        ) {
          return {
            lookup,
            ageMs,
            expiresInMs,
            matchType: 'url_normalized'
          };
        }
      }
    }

    return undefined;
  }

  listRecentLookups(limit = 50): HistoryItemDTO[] {
    // Purge records older than 24 hours first
    this.purgeOldRecords();

    const sorted = Array.from(this.lookups.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );

    return sorted.slice(0, limit).map((l) => {
      // Find associated analysis if any
      let verdict: string | undefined;
      let analysisAnalyst: string | undefined;
      for (const a of this.analyses.values()) {
        if (a.lookupId === l.id) {
          verdict = a.verdict?.verdict;
          analysisAnalyst = a.analystName;
          break;
        }
      }

      const hashes = l.hashes || {
        sha256: l.type === 'hash' && l.indicator.length === 64 ? l.indicator : l.evidence?.related?.hashes?.find((h) => h.length === 64),
        sha1: l.type === 'hash' && l.indicator.length === 40 ? l.indicator : l.evidence?.related?.hashes?.find((h) => h.length === 40),
        md5: l.type === 'hash' && l.indicator.length === 32 ? l.indicator : l.evidence?.related?.hashes?.find((h) => h.length === 32)
      };

      return {
        id: l.id,
        indicator: l.indicator,
        defanged: l.defanged,
        type: l.type,
        createdAt: l.createdAt,
        ruleScore: l.evidence?.rule_score?.value ?? 0,
        verdict: verdict || (l.evidence?.rule_score?.value >= 70 ? 'Malicious' : l.evidence?.rule_score?.value >= 40 ? 'Suspicious' : 'Clean / Benign'),
        analystName: l.analystName || analysisAnalyst || l.evidence?.analyst_name || 'SOC Analyst',
        fileName: l.fileName,
        fileSize: l.fileSize,
        actionType: l.actionType || (l.fileName ? 'file_submission' : 'indicator_search'),
        hashes
      };
    });
  }

  saveAnalysis(analysis: StoredAnalysis): void {
    this.purgeOldRecords();
    this.analyses.set(analysis.id, analysis);
    this.persist();
  }

  getAnalysis(id: string): StoredAnalysis | undefined {
    return this.analyses.get(id);
  }

  getAnalysisByLookupId(lookupId: string): StoredAnalysis | undefined {
    for (const a of this.analyses.values()) {
      if (a.lookupId === lookupId) {
        return a;
      }
    }
    return undefined;
  }
}

export const db = new Database();
