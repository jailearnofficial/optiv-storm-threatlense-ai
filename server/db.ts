/**
 * Persistent Storage for Lookups and Analyses
 * Section 5: lookups (id, indicator, type, created_at, evidence_json)
 * and analyses (id, lookup_id, verdict_json, model, created_at)
 */

import fs from 'fs';
import path from 'path';
import { EvidenceObject } from './providers/types.js';

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
    for (const lookup of this.lookups.values()) {
      if (lookup.indicator.toLowerCase() === normalized.toLowerCase()) {
        return lookup;
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
