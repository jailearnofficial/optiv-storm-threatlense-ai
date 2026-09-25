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

      // Purge any existing records loaded from disk that exceed 24 hours
      this.purgeOldRecords();
    } catch (err) {
      console.error('Error initializing data store:', err);
    }
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
        verdict,
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
