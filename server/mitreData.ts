/**
 * Bundled MITRE ATT&CK Enterprise Matrix Data
 * Supporting Enterprise ATT&CK v15 / Kill-chain order
 */

export interface MitreTechniqueDefinition {
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  description: string;
  mitigations: string[];
  detectionGuidance: string;
}

export const TACTIC_ORDER: { id: string; name: string }[] = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' }
];

export const MITRE_TECHNIQUES: Record<string, MitreTechniqueDefinition> = {
  // Reconnaissance
  'T1595': {
    techniqueId: 'T1595',
    techniqueName: 'Active Scanning',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.',
    mitigations: ['M1056', 'M1037'],
    detectionGuidance: 'Monitor network traffic for inbound scan patterns, abnormal port syn-floods, or rapid port sweeps.'
  },
  'T1598': {
    techniqueId: 'T1598',
    techniqueName: 'Phishing for Information',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries may send phishing messages to elicit sensitive information like credentials or architecture details.',
    mitigations: ['M1017', 'M1049'],
    detectionGuidance: 'Inspect email headers, SPF/DKIM validation failures, and suspicious link structures targeting credentials.'
  },

  // Initial Access
  'T1566.001': {
    techniqueId: 'T1566.001',
    techniqueName: 'Phishing: Spearphishing Attachment',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries send spearphishing emails with a malicious file attachment to gain execution.',
    mitigations: ['M1049', 'M1017', 'M1021'],
    detectionGuidance: 'Scan incoming email attachments using sandboxing and AV heuristics for macros or exploit payloads.'
  },
  'T1566.002': {
    techniqueId: 'T1566.002',
    techniqueName: 'Phishing: Spearphishing Link',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries send spearphishing messages containing a link to direct victims to malicious websites.',
    mitigations: ['M1017', 'M1021', 'M1031'],
    detectionGuidance: 'Alert on proxy hits to unclassified or newly registered domains; hunt for clicks in mail gateway logs.'
  },
  'T1189': {
    techniqueId: 'T1189',
    techniqueName: 'Drive-by Compromise',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries gain access into a system through a user visiting a website over the normal course of browsing.',
    mitigations: ['M1021', 'M1048', 'M1051'],
    detectionGuidance: 'Monitor web proxy logs for exploits, unauthorized browser extensions, and sudden spawned binary processes.'
  },
  'T1190': {
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries may attempt to exploit a weakness in an Internet-facing computer or program.',
    mitigations: ['M1051', 'M1050', 'M1041'],
    detectionGuidance: 'Correlate WAF alerts, anomalous HTTP request methods, and sudden child processes under web server daemons.'
  },

  // Execution
  'T1059': {
    techniqueId: 'T1059',
    techniqueName: 'Command and Scripting Interpreter',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'Adversaries abuse command interpreters such as PowerShell, cmd, bash, or python to execute malicious commands.',
    mitigations: ['M1038', 'M1047'],
    detectionGuidance: 'Enable Script Block Logging (EID 4104) and monitor unusual parent-child process relationships (e.g. Word -> cmd.exe).'
  },
  'T1059.001': {
    techniqueId: 'T1059.001',
    techniqueName: 'Command and Scripting: PowerShell',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'Adversaries use PowerShell commands and scripts for operations and defense evasion.',
    mitigations: ['M1038', 'M1042'],
    detectionGuidance: 'Monitor encoded command arguments (-enc, -encodedcommand), download cradles (IEX, WebClient), and AMSI bypasses.'
  },
  'T1204.001': {
    techniqueId: 'T1204.001',
    techniqueName: 'User Execution: Malicious Link',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'An adversary relies upon the user clicking a malicious link to initiate execution.',
    mitigations: ['M1017', 'M1021'],
    detectionGuidance: 'Correlate user email access logs with outbound firewall and proxy connection timestamps.'
  },
  'T1204.002': {
    techniqueId: 'T1204.002',
    techniqueName: 'User Execution: Malicious File',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'An adversary relies upon the user opening a malicious file (e.g. macro document, archive, ISO, or LNK).',
    mitigations: ['M1017', 'M1049'],
    detectionGuidance: 'Monitor process creation events where office applications spawn script engines, certutil, or powershell.'
  },

  // Defense Evasion
  'T1027': {
    techniqueId: 'T1027',
    techniqueName: 'Obfuscated Files or Information',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries encrypt, encode, or otherwise obfuscate contents on a system (e.g. XOR, Base64, packers) to hide artifacts.',
    mitigations: ['M1049', 'M1040'],
    detectionGuidance: 'Check for high file entropy, packed section headers (UPX, VMProtect), and suspicious Base64 execution.'
  },
  'T1055': {
    techniqueId: 'T1055',
    techniqueName: 'Process Injection',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries inject malicious code into processes to evade process-based defenses and elevate privileges.',
    mitigations: ['M1040', 'M1026'],
    detectionGuidance: 'Monitor API calls: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, and cross-process handle acquisitions.'
  },

  // Credential Access
  'T1110': {
    techniqueId: 'T1110',
    techniqueName: 'Brute Force',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    description: 'Adversaries use password guessing, dictionary attacks, or credential stuffing against authentication endpoints.',
    mitigations: ['M1036', 'M1032'],
    detectionGuidance: 'Detect high volumes of authentication failures (Event ID 4625) originating from single IPs or user accounts.'
  },

  // Command and Control
  'T1071.001': {
    techniqueId: 'T1071.001',
    techniqueName: 'Application Layer Protocol: Web Protocols',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries communicate using application layer protocols (HTTP/HTTPS) to avoid detection.',
    mitigations: ['M1031', 'M1037'],
    detectionGuidance: 'Analyze beacon intervals, abnormal User-Agent strings, and periodic HTTP POST requests without referrers.'
  },
  'T1568': {
    techniqueId: 'T1568',
    techniqueName: 'Dynamic Resolution',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries dynamically establish connections to command and control infrastructure using methods like DGA or fast flux.',
    mitigations: ['M1031'],
    detectionGuidance: 'Identify DNS query bursts for high-entropy domains with short TTLs and failing NXDOMAIN responses.'
  },
  'T1568.002': {
    techniqueId: 'T1568.002',
    techniqueName: 'Domain Generation Algorithms (DGA)',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries use algorithmically generated domains to establish resilient fallback C2 channels.',
    mitigations: ['M1031'],
    detectionGuidance: 'Calculate Shannon entropy on requested hostnames in internal DNS server query logs.'
  },
  'T1573': {
    techniqueId: 'T1573',
    techniqueName: 'Encrypted Channel',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries employ a known encryption algorithm or custom protocol to conceal command and control traffic.',
    mitigations: ['M1031', 'M1020'],
    detectionGuidance: 'Inspect SSL/TLS certificate validity, self-signed cert fingerprints (JA3/JA3S), and anomalous SNI values.'
  },
  'T1090.003': {
    techniqueId: 'T1090.003',
    techniqueName: 'Proxy: Multi-hop Proxy',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries route traffic through multiple chained proxies such as Tor or commercial VPNs to obfuscate origins.',
    mitigations: ['M1030', 'M1037'],
    detectionGuidance: 'Correlate destination IPs with known Tor exit nodes and anonymizer IP threat intelligence feeds.'
  },
  'T1105': {
    techniqueId: 'T1105',
    techniqueName: 'Ingress Tool Transfer',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries transfer tools or files from an external system into a compromised network.',
    mitigations: ['M1031', 'M1049'],
    detectionGuidance: 'Monitor curl, wget, certutil, bitsadmin, or powershell downloading binaries from external IP addresses.'
  },

  // Impact
  'T1486': {
    techniqueId: 'T1486',
    techniqueName: 'Data Encrypted for Impact',
    tacticId: 'TA0040',
    tacticName: 'Impact',
    description: 'Adversaries encrypt data on target systems to interrupt availability and extort ransom.',
    mitigations: ['M1053', 'M1041'],
    detectionGuidance: 'Alert on rapid file renaming with known ransomware extensions and deletion of volume shadow copies (vssadmin).'
  },
  'T1490': {
    techniqueId: 'T1490',
    techniqueName: 'Inhibit System Recovery',
    tacticId: 'TA0040',
    tacticName: 'Impact',
    description: 'Adversaries delete or disable recovery points (shadow copies, backup catalogs, recovery mode) to prevent remediation.',
    mitigations: ['M1053', 'M1022'],
    detectionGuidance: 'Detect execution of bcdedit /set {default} recoveryenabled No, wbadmin delete catalog, or vssadmin delete shadows.'
  }
};

export function lookupMitreTechnique(techniqueId: string): MitreTechniqueDefinition | null {
  // Normalize technique ID (e.g., T1071.001 or T1071)
  const id = techniqueId.trim().toUpperCase();
  if (MITRE_TECHNIQUES[id]) {
    return MITRE_TECHNIQUES[id];
  }

  // Check parent technique if subtechnique not found directly
  const baseId = id.split('.')[0];
  if (MITRE_TECHNIQUES[baseId]) {
    return MITRE_TECHNIQUES[baseId];
  }

  return null;
}
