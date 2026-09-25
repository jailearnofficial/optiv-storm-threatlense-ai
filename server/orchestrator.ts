/**
 * Orchestrator: Async Fan-Out to Threat Intelligence Providers
 * Spec Section 2, 4, 5
 */

import crypto from 'crypto';
import { IndicatorType, defang } from './detect.js';
import {
  EvidenceObject,
  ProviderAdapter,
  ProviderResult,
  MitreHint,
  FilePayload
} from './providers/types.js';
import {
  VirusTotalAdapter,
  HybridAnalysisAdapter,
  MalwareBazaarAdapter,
  AbuseIPDBAdapter,
  URLhausAdapter,
  UrlscanAdapter,
  AlienVaultOTXAdapter
} from './providers/adapters.js';
import { calculateRuleScore } from './scoring.js';
import { db } from './db.js';
import { findKnownSample } from './providers/mockFeeds.js';

export class Orchestrator {
  private adapters: ProviderAdapter[];

  constructor() {
    this.adapters = [
      new VirusTotalAdapter(),
      new HybridAnalysisAdapter(),
      new MalwareBazaarAdapter(),
      new AbuseIPDBAdapter(),
      new URLhausAdapter(),
      new UrlscanAdapter(),
      new AlienVaultOTXAdapter()
    ];
  }

  async runLookup(
    indicator: string,
    type: IndicatorType,
    bypassCache = false,
    onProgress?: (result: ProviderResult) => void,
    analystName?: string,
    filePayload?: FilePayload
  ): Promise<EvidenceObject> {
    // Check 24-hour strict retention cache per indicator unless bypassCache is requested
    // If an analyst searches for the same hash, domain, or URL within the 24-hour retention window,
    // fetch directly from cached data without parsing to threat feeds.
    // If it has expired (> 24 hours) or is not cached, parse to threat feeds.
    if (!bypassCache) {
      const match = db.findCachedLookup(indicator, type);
      if (match) {
        console.log(
          `[OPTIV 24h Cache HIT] Indicator "${indicator}" matched cached record (${match.matchType}, age: ${Math.round(match.ageMs / 1000)}s, remaining: ${Math.round(match.expiresInMs / 1000 / 60)}m). Returning cached data without querying threat feeds.`
        );

        // Deep copy evidence so we don't mutate stored database records
        const cachedEvidence: EvidenceObject = JSON.parse(JSON.stringify(match.lookup.evidence));
        cachedEvidence.id = match.lookup.id;
        cachedEvidence.cached = true;
        cachedEvidence.cached_at = match.lookup.createdAt;
        cachedEvidence.cache_age_ms = match.ageMs;
        cachedEvidence.retention_window_hours = 24;

        if (analystName) {
          cachedEvidence.analyst_name = analystName;
        }

        if (cachedEvidence.mitre_hints) {
          const seen = new Set<string>();
          cachedEvidence.mitre_hints = cachedEvidence.mitre_hints.filter((h) => {
            if (seen.has(h.technique_id)) return false;
            seen.add(h.technique_id);
            return true;
          });
        }

        if (onProgress) {
          for (const p of cachedEvidence.providers) {
            onProgress(p);
          }
        }

        return cachedEvidence;
      }
    }

    // Determine which adapters support this indicator type
    const activeAdapters = this.adapters.filter((a) => a.supports(type));

    // Parallel fan-out with per-provider timeout handled in adapters
    const promises = activeAdapters.map(async (adapter) => {
      try {
        const result = await adapter.lookup(indicator, type, filePayload);
        if (onProgress) onProgress(result);
        return result;
      } catch (err: any) {
        const fallback: ProviderResult = {
          name: adapter.name,
          displayName: adapter.displayName,
          status: 'error',
          latency_ms: 0,
          score: {},
          headline: `Internal error running ${adapter.displayName}`,
          tags: ['error'],
          key_facts: {},
          raw: { error: err.message }
        };
        if (onProgress) onProgress(fallback);
        return fallback;
      }
    });

    const results = await Promise.all(promises);

    // Compute rule-based score
    const ruleScore = calculateRuleScore(results, activeAdapters.length);

    // Extract related indicators and MITRE hints
    const related: {
      domains: string[];
      ips: string[];
      urls: string[];
      hashes: string[];
    } = {
      domains: [],
      ips: [],
      urls: [],
      hashes: []
    };

    const mitreHints: MitreHint[] = [];

    // Extract hints from known samples if any
    const sample = findKnownSample(indicator);
    if (sample) {
      if (sample.mitreHints) mitreHints.push(...sample.mitreHints);
      if (sample.related) {
        related.domains.push(...sample.related.domains);
        related.ips.push(...sample.related.ips);
        related.urls.push(...sample.related.urls);
        related.hashes.push(...sample.related.hashes);
      }
    }

    // Extract from live results
    for (const res of results) {
      if (res.status === 'ok') {
        if (res.name === 'hybrid_analysis') {
          if (res.ha_details?.mitre_attack && res.ha_details.mitre_attack.length > 0) {
            for (const m of res.ha_details.mitre_attack) {
              mitreHints.push({
                technique_id: m.technique_id,
                provider: 'hybrid-analysis',
                evidence: m.evidence || `Observed via Falcon Sandbox behavioral trace: ${m.technique_name || m.tactic}`
              });
            }
          } else if (res.key_facts?.family) {
            mitreHints.push({
              technique_id: 'T1059',
              provider: 'hybrid-analysis',
              evidence: `Identified malicious payload family: ${res.key_facts.family}`
            });
          }
        }
        if (res.name === 'urlscan') {
          if (res.key_facts?.server_ip) {
            related.ips.push(res.key_facts.server_ip);
          }
        }
        if (res.name === 'abuseipdb') {
          if (res.key_facts?.is_tor) {
            mitreHints.push({
              technique_id: 'T1090.003',
              provider: 'abuseipdb',
              evidence: 'Verified public Tor Exit Node routing anonymized traffic'
            });
          }
        }
      }
    }

    // Deduplicate related indicators and mitre hints
    related.domains = Array.from(new Set(related.domains));
    related.ips = Array.from(new Set(related.ips));
    related.urls = Array.from(new Set(related.urls));
    related.hashes = Array.from(new Set(related.hashes));

    const uniqueMitreHints: MitreHint[] = [];
    const seenHints = new Set<string>();
    for (const h of mitreHints) {
      if (!seenHints.has(h.technique_id)) {
        seenHints.add(h.technique_id);
        uniqueMitreHints.push(h);
      }
    }

    const evidenceId = 'lkp_' + Math.random().toString(36).substring(2, 10);
    const defangedValue = defang(indicator, type);

    const evidence: EvidenceObject = {
      id: evidenceId,
      indicator: {
        value: defangedValue,
        type,
        normalized: indicator
      },
      analyst_name: analystName,
      collected_at: new Date().toISOString(),
      providers: results,
      related,
      mitre_hints: uniqueMitreHints,
      rule_score: ruleScore
    };

    // Save to DB with full analyst attribution and file details
    db.saveLookup({
      id: evidenceId,
      indicator,
      type,
      defanged: defangedValue,
      createdAt: evidence.collected_at,
      evidence,
      analystName: analystName || 'SOC Analyst',
      actionType: filePayload ? 'file_submission' : 'indicator_search',
      fileName: filePayload?.originalname,
      fileSize: filePayload?.buffer.length,
      hashes: {
        sha256: type === 'hash' && indicator.length === 64 ? indicator : related.hashes?.find((h) => h.length === 64),
        sha1: type === 'hash' && indicator.length === 40 ? indicator : related.hashes?.find((h) => h.length === 40),
        md5: type === 'hash' && indicator.length === 32 ? indicator : related.hashes?.find((h) => h.length === 32)
      }
    });

    return evidence;
  }
}

export const orchestrator = new Orchestrator();
