/**
 * Persistent Storage for Lookups and Analyses
 * Section 5: lookups (id, indicator, type, created_at, evidence_json)
 * and analyses (id, lookup_id, verdict_json, model, created_at)
 */

import fs from 'fs';
import path from 'path';
import { EvidenceObject } from './providers/types.js';

export interface StoredLookup {
  id: string;
  indicator: string;
  type: string;
  defanged: string;
  createdAt: string;
  evidence: EvidenceObject;
  analystName?: string;
}

export interface StoredAnalysis {
  id: string;
  lookupId: string;
  verdict: any;
  model: string;
  createdAt: string;
  analystName?: string;
}

class Database {
  private dbPath: string;
  private lookups: Map<string, StoredLookup> = new Map();
  private analyses: Map<string, StoredAnalysis> = new Map();

  constructor() {
    this.dbPath = path.resolve(process.cwd(), 'data');
    this.init();
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
    } catch (err) {
      console.error('Error initializing data store:', err);
    }
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

  listRecentLookups(limit = 20): Array<{
    id: string;
    indicator: string;
    defanged: string;
    type: string;
    createdAt: string;
    ruleScore: number;
    verdict?: string;
  }> {
    const sorted = Array.from(this.lookups.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );

    return sorted.slice(0, limit).map((l) => {
      // Find associated analysis if any
      let verdict: string | undefined;
      for (const a of this.analyses.values()) {
        if (a.lookupId === l.id) {
          verdict = a.verdict?.verdict;
          break;
        }
      }
      return {
        id: l.id,
        indicator: l.indicator,
        defanged: l.defanged,
        type: l.type,
        createdAt: l.createdAt,
        ruleScore: l.evidence.rule_score.value,
        verdict
      };
    });
  }

  saveAnalysis(analysis: StoredAnalysis): void {
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
