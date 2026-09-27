/**
 * IOC Validation & Anti-Hallucination Filter
 * Section 6: Drops any IOC value that does not appear anywhere in provider data
 */

import { EvidenceObject } from '../providers/types.js';
import { defang } from '../detect.js';

export interface IOCItem {
  type: 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';
  value: string;
  context: string;
  source: string;
}

export function validateAndSanitizeIOCs(rawIOCs: any[], evidence: EvidenceObject): IOCItem[] {
  if (!Array.isArray(rawIOCs) || rawIOCs.length === 0) {
    return [];
  }

  // Create a searchable text corpus of all provider evidence
  const corpus = JSON.stringify(evidence).toLowerCase();
  const normalizedPrimary = evidence.indicator.normalized.toLowerCase();

  const validIOCs: IOCItem[] = [];
  const seenValues = new Set<string>();

  for (const item of rawIOCs) {
    if (!item || !item.value || typeof item.value !== 'string') continue;

    const val = item.value.trim();
    const valLower = val.toLowerCase();

    // Check if the value appears in the primary indicator or in the provider evidence corpus
    const appearsInCorpus =
      valLower === normalizedPrimary ||
      corpus.includes(valLower) ||
      evidence.related.domains.some((d) => d.toLowerCase() === valLower) ||
      evidence.related.ips.some((i) => i.toLowerCase() === valLower) ||
      evidence.related.urls.some((u) => u.toLowerCase() === valLower) ||
      evidence.related.hashes.some((h) => h.toLowerCase() === valLower);

    if (!appearsInCorpus) {
      // Discard hallucinated indicator not found in provider evidence
      continue;
    }

    const type = item.type || 'domain';
    const defangedValue = defang(val, type as any);

    if (seenValues.has(defangedValue.toLowerCase())) {
      continue;
    }
    seenValues.add(defangedValue.toLowerCase());

    validIOCs.push({
      type,
      value: defangedValue,
      context: item.context || 'Identified in threat intel telemetry',
      source: item.source || 'Threat Intelligence Engine'
    });
  }

  // Always ensure primary indicator is in the IOC list if malicious/suspicious
  const primaryDefanged = evidence.indicator.value;
  if (!seenValues.has(primaryDefanged.toLowerCase())) {
    validIOCs.unshift({
      type: evidence.indicator.type as any,
      value: primaryDefanged,
      context: 'Primary investigated target indicator',
      source: 'Analyst Query'
    });
  }

  return validIOCs;
}
