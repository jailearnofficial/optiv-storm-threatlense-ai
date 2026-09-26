/**
 * Rule-Based Scoring Engine
 * Spec Section 5: Deterministic 0-100 score computed after lookup before AI call
 */

import { ProviderResult, RuleScoreResult } from './providers/types.js';

export function calculateRuleScore(providers: ProviderResult[], totalQueriedCount: number): RuleScoreResult {
  // Provider base weights defined in Section 5
  // VirusTotal: 40
  // Hybrid Analysis: 20
  // MalwareBazaar / URLhaus: 20
  // AbuseIPDB: 10
  // AlienVault OTX / urlscan.io: 10
  const baseWeights: Record<string, number> = {
    virustotal: 40,
    hybrid_analysis: 20,
    malwarebazaar: 10,
    urlhaus: 10,
    abuseipdb: 10,
    urlscan: 5,
    alienvault_otx: 5,
  };

  const scores: Record<string, number> = {};
  let totalAvailableWeight = 0;
  let activeProvidersWithData = 0;

  for (const p of providers) {
    if (p.status !== 'ok' && p.status !== 'not_found') {
      continue;
    }

    const weight = baseWeights[p.name] || 0;
    let providerScore0to100 = 0;

    if (p.status === 'not_found') {
      // not_found is evidence of clean / never seen
      providerScore0to100 = 0;
      activeProvidersWithData++;
      totalAvailableWeight += weight;
      scores[p.name] = 0;
      continue;
    }

    // Provider is 'ok', calculate its 0-100 risk contribution
    activeProvidersWithData++;
    totalAvailableWeight += weight;

    switch (p.name) {
      case 'virustotal': {
        const mal = p.score.malicious || 0;
        const susp = p.score.suspicious || 0;
        const total = (mal + susp + (p.score.harmless || 0) + (p.score.undetected || 0)) || 70;
        // Detection ratio = (malicious + 0.5 * suspicious) / total * 100
        const ratio = ((mal + (0.5 * susp)) / total) * 100;
        providerScore0to100 = Math.min(100, Math.round(ratio * 1.5)); // Scale up if detected by engines
        break;
      }

      case 'hybrid_analysis': {
        const threatScore = p.score.threat_score ?? 0;
        const mal = p.score.malicious ? 100 : 0;
        providerScore0to100 = Math.max(threatScore, mal);
        break;
      }

      case 'malwarebazaar': {
        if (p.score.malicious || (p.key_facts?.signature && p.key_facts.signature !== 'None')) {
          providerScore0to100 = 100;
        } else {
          providerScore0to100 = 0;
        }
        break;
      }

      case 'urlhaus': {
        if (p.score.malicious || p.key_facts?.threat || p.key_facts?.status === 'online') {
          providerScore0to100 = 95;
        } else {
          providerScore0to100 = 0;
        }
        break;
      }

      case 'abuseipdb': {
        providerScore0to100 = p.score.abuse_confidence ?? 0;
        break;
      }

      case 'urlscan': {
        const score = p.score.threat_score ?? (p.score.malicious ? 85 : 0);
        providerScore0to100 = Math.min(100, score);
        break;
      }

      case 'alienvault_otx': {
        const pulses = p.score.pulse_count ?? 0;
        if (pulses >= 10) providerScore0to100 = 90;
        else if (pulses >= 3) providerScore0to100 = 65;
        else if (pulses >= 1) providerScore0to100 = 35;
        else providerScore0to100 = 0;
        break;
      }

      default:
        providerScore0to100 = 0;
    }

    scores[p.name] = Math.min(100, Math.max(0, providerScore0to100));
  }

  // Redistribute weights proportionally across the providers that returned data
  let finalScore = 0;
  if (totalAvailableWeight > 0) {
    let weightedSum = 0;
    for (const [name, score] of Object.entries(scores)) {
      const w = baseWeights[name] || 0;
      weightedSum += score * w;
    }
    finalScore = Math.round(weightedSum / totalAvailableWeight);
  }

  finalScore = Math.min(100, Math.max(0, finalScore));

  // Determine band: 0-19 clean, 20-49 low, 50-79 medium, 80-100 high
  let band: 'clean' | 'low' | 'medium' | 'high' = 'clean';
  if (finalScore >= 80) {
    band = 'high';
  } else if (finalScore >= 50) {
    band = 'medium';
  } else if (finalScore >= 20) {
    band = 'low';
  }

  return {
    value: finalScore,
    band,
    coverage: `${activeProvidersWithData}/${totalQueriedCount}`,
    activeProviders: activeProvidersWithData,
    totalQueried: totalQueriedCount,
    breakdown: scores
  };
}
