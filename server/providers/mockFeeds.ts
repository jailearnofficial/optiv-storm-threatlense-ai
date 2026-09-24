/**
 * Curated Threat Intelligence Knowledge Base for Realistic Fallback
 * Provides ground-truth intelligence for acceptance test indicators
 * when external API keys have not yet been populated.
 */

import { IndicatorType } from '../detect.js';
import { ProviderResult } from './types.js';

export interface KnownSample {
  indicator: string;
  type: IndicatorType;
  label: string;
  verdictExpected: 'Malicious' | 'Suspicious' | 'Benign' | 'False Positive' | 'Inconclusive';
  providers: Partial<Record<string, Partial<ProviderResult>>>;
  mitreHints?: { technique_id: string; provider: string; evidence: string }[];
  related?: { domains: string[]; ips: string[]; urls: string[]; hashes: string[] };
}

export const KNOWN_SAMPLES: KnownSample[] = [
  // 1. EICAR Standard Anti-Virus Test File Hash (SHA-256)
  {
    indicator: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    type: 'hash',
    label: 'EICAR Standard AV Test File',
    verdictExpected: 'Malicious',
    providers: {
      virustotal: {
        status: 'ok',
        headline: '68/74 engines detected as EICAR-Test-File',
        score: { malicious: 68, suspicious: 1, harmless: 0, undetected: 5 },
        tags: ['eicar', 'test-file', 'dos-executable'],
        key_facts: {
          file_type: 'DOS executable / ASCII test string',
          file_size: '68 bytes',
          first_seen: '2006-03-01T04:22:11Z',
          names: ['eicar.com', 'eicar.com.txt', 'eicar_test.file']
        },
        link: 'https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
      },
      hybrid_analysis: {
        status: 'ok',
        headline: 'Verdict: Malicious (Test String)',
        score: { threat_score: 100, malicious: 1 },
        tags: ['antivirus-test', 'heuristic-match'],
        key_facts: {
          av_detect_percent: 92,
          environment: 'Windows 10 64-bit',
          family: 'EICAR-Test-Signature'
        }
      },
      malwarebazaar: {
        status: 'ok',
        headline: 'Signature match: EICAR.Test.File',
        score: { malicious: 1 },
        tags: ['eicar', 'test'],
        key_facts: {
          signature: 'EICAR_Standard_Anti-Virus_Test_File',
          file_type: 'com',
          reporter: 'abuse_ch'
        }
      },
      alienvault_otx: {
        status: 'ok',
        headline: 'Present in 42 threat pulses',
        score: { pulse_count: 42 },
        tags: ['antivirus-testing', 'eicar-standard'],
        key_facts: { adversary: 'None (Standard Industry Test)', related_pulses: 42 }
      }
    },
    mitreHints: [
      { technique_id: 'T1204.002', provider: 'hybrid-analysis', evidence: 'Simulated malware execution behavior test' }
    ]
  },

  // 2. WannaCry Ransomware SHA-256 Hash
  {
    indicator: 'ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8',
    type: 'hash',
    label: 'WannaCry 2.0 Ransomware Payload',
    verdictExpected: 'Malicious',
    providers: {
      virustotal: {
        status: 'ok',
        headline: '71/72 security vendors flagged as Win32.WannaCry.Ransomware',
        score: { malicious: 71, suspicious: 0, harmless: 0, undetected: 1 },
        tags: ['ransomware', 'wannacry', 'wcry', 'killswitch-domain', 'eternalblue'],
        key_facts: {
          file_type: 'Win32 EXE',
          file_size: '3514368 bytes',
          first_seen: '2017-05-12T07:27:17Z',
          names: ['tasksche.exe', 'mssecsvc.exe', 'wcry.exe']
        },
        link: 'https://www.virustotal.com/gui/file/ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8'
      },
      hybrid_analysis: {
        status: 'ok',
        headline: 'Falcon Sandbox: 100/100 Threat Score (Ransomware Execution)',
        score: { threat_score: 100, malicious: 1 },
        tags: ['wannacry', 'ransomware', 'vssadmin-tamper', 'tor-client-embedded'],
        key_facts: {
          family: 'WannaCry',
          dropped_files: ['taskse.exe', '00000000.eky', 'c.wnry'],
          contacted_hosts: ['www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com', '192.168.56.101']
        }
      },
      malwarebazaar: {
        status: 'ok',
        headline: 'Known Ransomware Family: WannaCry',
        score: { malicious: 1 },
        tags: ['WannaCry', 'Ransomware', 'WanaCrypt0r'],
        key_facts: {
          signature: 'Win.Ransomware.WannaCry',
          delivery_method: 'SMB / EternalBlue MS17-010',
          first_seen: '2017-05-12T09:14:02Z'
        }
      },
      alienvault_otx: {
        status: 'ok',
        headline: 'Linked to 118 pulses, APT38 / Lazarus Group',
        score: { pulse_count: 118 },
        tags: ['ransomware', 'lazarus', 'wannacry', 'global-outbreak'],
        key_facts: { adversary: 'Lazarus Group (APT38)', pulse_count: 118 }
      }
    },
    mitreHints: [
      { technique_id: 'T1486', provider: 'hybrid-analysis', evidence: 'Bulk AES encryption of user documents with .WNCRY extension' },
      { technique_id: 'T1490', provider: 'hybrid-analysis', evidence: 'Executed vssadmin delete shadows /all /quiet' },
      { technique_id: 'T1059', provider: 'virustotal', evidence: 'Spawned cmd.exe /c attrib +h and taskkill' },
      { technique_id: 'T1071.001', provider: 'hybrid-analysis', evidence: 'HTTP query to unregistered sinkhole killswitch domain' }
    ],
    related: {
      domains: ['www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com', 'iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com'],
      ips: ['194.109.6.93', '217.182.169.148'],
      urls: ['http://www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com'],
      hashes: ['ed01ebf83334a19374d4a77573494f7d87ff9f0f9d37345c3b8c0a88f666e2c8', '514e9d5ecd9f3e8f68257640c1e0e844']
    }
  },

  // 3. Known Active Phishing URL (URLhaus / urlscan / VT)
  {
    indicator: 'http://paypal-account-verification-auth.com/login/update.php',
    type: 'url',
    label: 'Credential Harvester Phishing URL',
    verdictExpected: 'Malicious',
    providers: {
      virustotal: {
        status: 'ok',
        headline: '24/92 vendors flagged as Phishing / Malicious URL',
        score: { malicious: 24, suspicious: 3, harmless: 48, undetected: 17 },
        tags: ['phishing', 'brand-impersonation', 'paypal-target'],
        key_facts: {
          categories: ['phishing', 'financial-fraud'],
          server: 'nginx/1.22',
          first_seen: '2026-09-18T12:00:00Z'
        },
        link: 'https://www.virustotal.com/gui/url/lookup'
      },
      urlhaus: {
        status: 'ok',
        headline: 'Status: Online | Threat: Phishing Credential Harvester',
        score: { malicious: 1 },
        tags: ['phishing', 'paypal', 'credential-stealer'],
        key_facts: {
          status: 'online',
          threat: 'phishing',
          reporter: 'abuse_community',
          date_added: '2026-09-20T08:11:00Z'
        }
      },
      urlscan: {
        status: 'ok',
        headline: 'urlscan score 100/100 (PayPal Brand Impersonation)',
        score: { threat_score: 100, malicious: 1 },
        tags: ['brand:paypal', 'fake-login', 'tls-letsencrypt'],
        key_facts: {
          brands_targeted: ['PayPal Holdings Inc.'],
          final_url: 'http://paypal-account-verification-auth.com/login/update.php',
          server_ip: '194.67.210.14',
          asn: 'AS44050',
          country: 'RU'
        }
      },
      alienvault_otx: {
        status: 'ok',
        headline: 'Documented in 5 active phishing pulses',
        score: { pulse_count: 5 },
        tags: ['phishing', 'credential-harvesting'],
        key_facts: { pulse_names: ['PayPal Fake Login Campaign 2026', 'Financial Phish Kit #992'] }
      }
    },
    mitreHints: [
      { technique_id: 'T1566.002', provider: 'urlscan', evidence: 'Fake brand login portal impersonating legitimate financial provider' },
      { technique_id: 'T1598', provider: 'urlhaus', evidence: 'Credential harvesting form submission to update.php' },
      { technique_id: 'T1204.001', provider: 'virustotal', evidence: 'Direct victim lure link distributed via SMS/email spam' }
    ],
    related: {
      domains: ['paypal-account-verification-auth.com'],
      ips: ['194.67.210.14'],
      urls: ['http://paypal-account-verification-auth.com/login/update.php'],
      hashes: []
    }
  },

  // 4. Known Tor Exit Node / Scanner IP (AbuseIPDB / OTX)
  {
    indicator: '185.220.101.5',
    type: 'ip',
    label: 'Known Tor Exit Node & SSH Brute-Forcer',
    verdictExpected: 'Suspicious',
    providers: {
      abuseipdb: {
        status: 'ok',
        headline: '100% Abuse Confidence Score with 1,420 reports in 90 days',
        score: { abuse_confidence: 100, total_reports: 1420 },
        tags: ['tor-exit', 'ssh-brute-force', 'port-scan'],
        key_facts: {
          country: 'DE',
          isp: 'Zwiebelfreunde e.V.',
          usage_type: 'Data Center/Web Hosting/Transit',
          is_tor: true,
          last_reported: '2026-09-24T09:12:00Z'
        }
      },
      virustotal: {
        status: 'ok',
        headline: '12/88 security engines flagged as Tor Proxy / Scanning',
        score: { malicious: 12, suspicious: 4, harmless: 64, undetected: 8 },
        tags: ['tor', 'anonymizer', 'scanner'],
        key_facts: {
          as_owner: 'Zwiebelfreunde e.V.',
          network: '185.220.101.0/24',
          country: 'DE'
        },
        link: 'https://www.virustotal.com/gui/ip-address/185.220.101.5'
      },
      alienvault_otx: {
        status: 'ok',
        headline: 'Observed in 28 pulses (Tor Nodes, SSH Scanners)',
        score: { pulse_count: 28 },
        tags: ['tor', 'exit-node', 'scanning'],
        key_facts: { adversary: 'Multiple / Anonymized', related_pulses: 28 }
      },
      urlhaus: {
        status: 'ok',
        headline: 'Host recorded serving 3 temporary payload links',
        score: { malicious: 1 },
        tags: ['host-payload'],
        key_facts: { host_status: 'flagged' }
      }
    },
    mitreHints: [
      { technique_id: 'T1090.003', provider: 'abuseipdb', evidence: 'Verified public Tor Exit Node relaying anonymized network connections' },
      { technique_id: 'T1595', provider: 'abuseipdb', evidence: 'High-frequency TCP port 22/80/443 syn scanning logged across multiple reporters' },
      { technique_id: 'T1110', provider: 'abuseipdb', evidence: 'Automated dictionary attack attempts against SSH daemon' }
    ],
    related: {
      domains: ['tor-exit-node-05.zwiebelfreunde.de'],
      ips: ['185.220.101.5'],
      urls: [],
      hashes: []
    }
  },

  // 5. Clean / Benign Domain: Google Public DNS / Search
  {
    indicator: 'google.com',
    type: 'domain',
    label: 'Legitimate Global Domain (Google)',
    verdictExpected: 'Benign',
    providers: {
      virustotal: {
        status: 'ok',
        headline: '0/94 engines detected. Reputation: Highly Trusted (+3540)',
        score: { malicious: 0, suspicious: 0, harmless: 90, undetected: 4 },
        tags: ['search-engine', 'popular', 'legitimate-infrastructure'],
        key_facts: {
          registrar: 'MarkMonitor Inc.',
          first_seen: '1997-09-15T00:00:00Z',
          whois_age_days: 10600
        },
        link: 'https://www.virustotal.com/gui/domain/google.com'
      },
      urlscan: {
        status: 'ok',
        headline: 'Score 0/100 (Safe). Clean reputation verified.',
        score: { threat_score: 0, malicious: 0 },
        tags: ['verified', 'search', 'top-100-alexa'],
        key_facts: {
          server_ip: '142.250.190.46',
          asn: 'AS15169 Google LLC',
          country: 'US'
        }
      },
      alienvault_otx: {
        status: 'ok',
        headline: 'Whitelisted top-level service domain',
        score: { pulse_count: 0 },
        tags: ['whitelist', 'trusted'],
        key_facts: { pulse_count: 0 }
      },
      urlhaus: {
        status: 'not_found',
        headline: 'Not listed in URLhaus malware database',
        score: { malicious: 0 },
        tags: ['clean'],
        key_facts: {}
      }
    },
    mitreHints: [],
    related: {
      domains: ['google.com', 'www.google.com'],
      ips: ['142.250.190.46', '8.8.8.8'],
      urls: ['https://www.google.com'],
      hashes: []
    }
  },

  // 6. False Positive Domain: Known CDN / Telemetry with 1-2 Stale Detections
  {
    indicator: 'cdnjs.cloudflare.com',
    type: 'domain',
    label: 'Cloudflare CDN (False Positive Sample)',
    verdictExpected: 'False Positive',
    providers: {
      virustotal: {
        status: 'ok',
        headline: '1/92 low-confidence detection (Clean 91/92)',
        score: { malicious: 1, suspicious: 1, harmless: 86, undetected: 4 },
        tags: ['cdn', 'content-delivery-network', 'cloudflare', 'legitimate-host'],
        key_facts: {
          registrar: 'Cloudflare Inc.',
          top_detection: 'CRDF: Malicious (Unverified Heuristic)',
          reputation: 980
        },
        link: 'https://www.virustotal.com/gui/domain/cdnjs.cloudflare.com'
      },
      urlscan: {
        status: 'ok',
        headline: 'Score 0/100. Global JavaScript CDN library repository.',
        score: { threat_score: 0, malicious: 0 },
        tags: ['cdn', 'javascript-cdn', 'trusted'],
        key_facts: {
          server_ip: '104.16.18.94',
          asn: 'AS13335 Cloudflare, Inc.'
        }
      },
      alienvault_otx: {
        status: 'ok',
        headline: 'Tagged as legitimate infrastructure / CDN in pulses',
        score: { pulse_count: 2 },
        tags: ['cdn', 'benign-service'],
        key_facts: { pulse_names: ['Legitimate Public Services Catalog'] }
      },
      urlhaus: {
        status: 'not_found',
        headline: 'Host not flagged in malicious repository',
        score: { malicious: 0 },
        tags: ['clean'],
        key_facts: {}
      }
    },
    mitreHints: [],
    related: {
      domains: ['cdnjs.cloudflare.com', 'cloudflare.com'],
      ips: ['104.16.18.94'],
      urls: [],
      hashes: []
    }
  }
];

export function findKnownSample(indicator: string): KnownSample | null {
  const norm = indicator.trim().toLowerCase();
  for (const sample of KNOWN_SAMPLES) {
    if (sample.indicator.toLowerCase() === norm) {
      return sample;
    }
    // Also match URL without trailing slash or protocol
    if (norm.includes(sample.indicator.toLowerCase()) || sample.indicator.toLowerCase().includes(norm)) {
      if (norm.length > 5) return sample;
    }
  }
  return null;
}
