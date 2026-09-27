# Architecture & System Design Specification

## Project: SOC Analysis – AI Unified Threat Triage Portal

---

## 1. Executive Overview

The **SOC Analysis – AI Unified Threat Triage Portal** is an enterprise-grade Security Operations Center (SOC) threat investigation platform. It provides Level-1/Level-2 security analysts and incident responders with a unified single pane of glass to ingest suspicious indicators of compromise (IOCs)—including file hashes, IPv4/IPv6 addresses, domain names, URLs, and uploaded suspicious binaries/scripts.

The system orchestrates multi-vendor threat intelligence queries concurrently across top-tier threat telemetry providers (VirusTotal, Hybrid Analysis Falcon Sandbox, AlienVault Open Threat Exchange, AbuseIPDB, URLhaus, MalwareBazaar, and urlscan.io), correlates observations using a deterministic heuristics engine, and executes server-side AI triage via **Google Gemini**.

The resulting output is an authoritative triage verdict complete with MITRE ATT&CK technique mappings, immediate containment and remediation playbooks, defanged secondary IOCs, topological interactive visualizations, STIX 2.1 compliance bundles, and downloadable executive PDF incident dossiers.

```
+-----------------------------------------------------------------------------------------+
|                                    CLIENT BROWSER (React SPA)                           |
|  - Real-time SSE Streaming Search   - Responsive SOC Theme (Dark/Light)                 |
|  - MITRE ATT&CK Interactive Matrix  - Deep-Dive Provider Inspectors (VT/HA/OTX)        |
|  - Recharts Threat Radar & Engine   - Dynamic Dossier Preview & PDF Print               |
+--------------------------------------------+--------------------------------------------+
                                             | HTTP / REST & Server-Sent Events (SSE)
                                             v
+-----------------------------------------------------------------------------------------+
|                                  EXPRESS FULL-STACK BACKEND                             |
|  - Security Middleware: Strict CSP, Anti-Clickjacking, No-Sniff, Referrer Policy       |
|  - Auto-Detection & Defanging Engine (RFC 1918 & Cloud Metadata SSRF Blocking)          |
|  - In-Memory + Disk Sync Cache Layer (Thread-Safe JSON Snapshots)                       |
+---------------------+-------------------------------+-----------------------------------+
                      |                               |
        (Parallel Orchestration)                      | (Unified Evidence Payload)
                      v                               v
+------------------------------------+   +------------------------------------------------+
|     MULTI-VENDOR INTEL ENGINES     |   |          GEMINI AI TRIAGE ENGINE               |
|  * VirusTotal v3 API               |   |  - Model: Gemini 2.5 Flash                     |
|  * Hybrid Analysis Falcon Sandbox  |   |  - Strict Structured Schema Output             |
|  * AlienVault OTX Threat Pulses    |   |  - MITRE ATT&CK Matrix Mapping                 |
|  * AbuseIPDB v2 Reputation         |   |  - Defanged Secondary IOC Extraction           |
|  * URLhaus Threat Database         |   |  - Actionable SOC Containment Recommendations  |
|  * MalwareBazaar File DB           |   +------------------------------------------------+
|  * urlscan.io Visual & DOM Scan    |
+------------------------------------+
                      |
                      v
+-----------------------------------------------------------------------------------------+
|                              REPORTING & EXPORT INTEROPERABILITY                        |
|  - Sanitized Print-Ready HTML/PDF Executive Dossier with Multi-Vendor Consensus         |
|  - Defanged IOCs CSV Export (Hardened against CWE-1236 Formula Injection)               |
|  - OASIS STIX 2.1 JSON Threat Intelligence Bundle (Campaigns, Malware, Threat Actors)   |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Core Architectural Pillars

### 2.1. Strict Server-Side Key Isolation
No API keys or secret credentials ever enter the client-side bundle or environment. All external telemetry API requests and Gemini invocations occur exclusively on the Express Node.js backend. The frontend communicates through proxy endpoints (`/api/*`).

### 2.2. Deterministic Fallback & Zero Single-Point-of-Failure
When external provider API keys are missing or provider quotas are exhausted, the orchestrator gracefully falls back to curated threat intelligence knowledge bases for classic and contemporary malware families (WannaCry, Emotet, Cobalt Strike, Lazarus Group). Real live endpoints (MalwareBazaar, URLhaus, public urlscan.io) continue querying live data concurrently.

### 2.3. Asynchronous Streaming Intelligence
The platform provides instant UI responsiveness through Server-Sent Events (`/api/lookup/stream`). As each provider completes its lookup (varying from 150ms to 2.5s), results stream to the browser in real time, giving analysts immediate telemetry before the full consensus is synthesized.

---

## 3. Indicator Ingestion & Normalization Engine

Located at `server/detect.ts`:

### 3.1. Indicator Type Detection
Supports four core indicator types:
- **`hash`**: SHA-256 (64 hex characters), SHA-1 (40 hex characters), MD5 (32 hex characters).
- **`ip`**: IPv4 and IPv6 addresses.
- **`url`**: Standard HTTP/HTTPS/FTP URLs.
- **`domain`**: Fully Qualified Domain Names (FQDN).

### 3.2. Automatic Refanging & Defanging
- **Refanging**: Incoming indicators submitted in defanged formats (e.g., `hxxps[://]bad[.]com`, `192[.]168[.]1[.]1`, `example(dot)com`) are automatically normalized before querying APIs.
- **Defanging**: All outgoing indicators, summaries, and generated reports defang domains (`.` &rarr; `[.]`), IPs, and protocols (`http` &rarr; `hxxp`) to prevent accidental analyst clicks or automated mail-filter misattribution.

### 3.3. Server-Side Request Forgery (SSRF) Guard
To prevent threat actors or attackers from querying internal infrastructure through the analyzer:
- Restricts indicator URLs strictly to `http:`, `https:`, and `ftp:`. Rejects dangerous schemes (`file:`, `gopher:`, `javascript:`, `data:`).
- Validates target hostnames against loopback addresses (`127.0.0.1`, `localhost`), link-local metadata endpoints (`169.254.169.254`), and private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

---

## 4. Threat Intelligence Provider Adapters

Located at `server/providers/`:

| Provider | Telemetry Focus | Supported Types | Key Capabilities |
| :--- | :--- | :--- | :--- |
| **VirusTotal v3** | Multi-scanner engine detection | Hash, IP, Domain, URL | 70+ AV scanner votes, behavioral tags, names, VT Graph topological visualization |
| **Hybrid Analysis** | Falcon Sandbox dynamic analysis | Hash, Domain | Threat score (0–100), sandbox environment, AV detection %, MITRE ATT&CK indicators |
| **AlienVault OTX** | Global crowdsourced threat pulses | Hash, IP, Domain, URL | Community threat pulses, threat actor attribution, targeted geographies, advisory links |
| **AbuseIPDB** | Crowd-reported IP abuse & spam | IP | Abuse confidence score (0–100%), total reports, ISP, usage type, country |
| **URLhaus** | Active malware distribution URLs | URL, Domain, Hash | Malware payloads, payload tags, URL status (online/offline) |
| **MalwareBazaar** | Malware sample repository | Hash | Sample signatures, file type, delivery tags, ClamAV detections, reporter |
| **urlscan.io** | Automated browser DOM analysis | URL, Domain, IP | Screenshot previews, HTTP transaction breakdown, DOM verdicts, malicious score |

### Parallel Execution Pattern
```typescript
const providerPromises = activeProviders.map(async (provider) => {
  try {
    const result = await Promise.race([
      provider.lookup(indicator, type),
      timeout(10000)
    ]);
    onProgress?.(result);
    return result;
  } catch (error) {
    return createUnavailableProviderResult(provider.name, error);
  }
});

const results = await Promise.allSettled(providerPromises);
```

---

## 5. Scoring & Heuristic Engine

Located at `server/scoring.ts`:

The deterministic rule score evaluates provider evidence before passing to the AI layer:
- **Baseline Score**: 0 to 100 integer.
- **Weights**:
  - VirusTotal malicious engine count: $\min(45, \text{engines} \times 3)$
  - Hybrid Analysis threat score: $\min(30, \text{HA Score} \times 0.3)$
  - AbuseIPDB confidence score: $\min(25, \text{Confidence} \times 0.25)$
  - URLhaus confirmed active payload: $+25$
  - AlienVault OTX active pulses: $\min(20, \text{pulses} \times 4)$
- **Confidence Calibration**: Computed from the number of responding providers, agreement ratio, and signal strength.

---

## 6. Server-Side AI Threat Triage Engine

Located at `server/ai/gemini.ts`:

- **Model**: Google Gemini (`gemini-2.5-flash`) via the `@google/genai` SDK.
- **Role**: Level 3 Senior SOC Incident Analyst.
- **Inputs**: Defanged indicator, indicator type, rule score, and consolidated multi-provider evidence payload.
- **Output Schema**: Strict JSON Schema enforcement guarantees uniform parsing:
  - `verdict`: `"Malicious"` | `"Suspicious"` | `"Benign"` | `"Inconclusive"`
  - `confidence_score`: 0–100 integer
  - `malware_family`: String or null
  - `threat_actors`: Array of attributed adversary groups
  - `executive_summary`: High-level summary for CISOs / leadership
  - `technical_summary`: Deep technical breakdown for SOC analysts
  - `mitre_attack`: Array of `{ technique_id, technique_name, tactic, evidence }`
  - `recommended_actions`: Array of `{ priority, action, rationale }`
  - `iocs`: Array of defanged secondary IOCs `{ type, value, context, source }`

---

## 7. Report Generation & Threat Interoperability

Located at `server/report/generator.ts`:

### 7.1. Executive Incident Dossier (Print / PDF)
- Designed with high-density, vector-clean typography (Inter, SF Pro, Consolas).
- Includes:
  1. Header with custom Analyst Identity, Reference ID, Classification, and Timestamp.
  2. Multi-Vendor Consensus Grid (VirusTotal, Falcon Sandbox, AlienVault OTX).
  3. Executive & Technical AI Summaries.
  4. Top-Engine Telemetry Matrix & SVG Topological Graphs.
  5. AlienVault OTX Community Pulses & ATT&CK Mappings.
  6. Defanged IOC Extraction Table.
  7. SOC Playbook & Action Checklist with priority color coding.

### 7.2. Hardened CSV IOC Export
- Enforces protection against **CWE-1236 (CSV Formula Injection)**:
  ```typescript
  const sanitizeCell = (val: string): string => {
    let str = String(val || '');
    if (/^[=+\-@\t\r]/.test(str)) {
      str = `'${str}`; // Prepend single quote to neutralize spreadsheet formulas
    }
    return `"${str.replace(/"/g, '""')}"`;
  };
  ```

### 7.3. OASIS STIX 2.1 Threat Intelligence Bundle
- Exportable at `/api/iocs/:id?format=stix`.
- Constructs valid STIX 2.1 entities:
  - `indicator` (with Pattern: `[file:hashes.'SHA-256' = '...']` or `[ipv4-addr:value = '...']`)
  - `malware` (mapped family attribution)
  - `threat-actor` (attributed groups like Lazarus, APT28)
  - `campaign` (derived from AlienVault OTX community pulses)
  - `attack-pattern` (MITRE ATT&CK techniques)
  - `relationship` objects linking indicators to malware and attack patterns.

---

## 8. Security & Hardening Architecture

| Threat Vector | Mechanism & Defense |
| :--- | :--- |
| **API Secret Leaks** | Loaded strictly via `process.env` in `server/config.ts`. No `VITE_` exposed keys. Health checks only return boolean flags. |
| **SSRF / Cloud Metadata** | Blocks RFC 1918 private subnets, localhost, and `169.254.169.254` AWS/GCP metadata endpoints. |
| **CSV Formula Injection** | Prepends `'` to cells starting with `=`, `+`, `-`, `@`, `\t`, or `\r`. |
| **Cross-Site Scripting (XSS)** | Mandatory HTML entity escaping (`escapeHtml()`) across all template literals. |
| **Reverse Tab-Nabbing** | All outbound hyperlinks enforce `rel="noopener noreferrer"` and `safeUrl()` protocol checks (`http:`/`https:` only). |
| **Clickjacking** | Custom `Content-Security-Policy: frame-ancestors 'self' https://*.google.com https://*.run.app https://*.googleusercontent.com;` |
| **MIME Sniffing** | `X-Content-Type-Options: nosniff`. |
| **Path Traversal** | Alphanumeric validation regex (`/^[a-zA-Z0-9_-]{1,64}$/`) on all URL route parameters. |
| **Server Fingerprinting** | Disabled `X-Powered-By: Express`. |

---

## 9. Frontend Architecture & Component Hierarchy

- **Framework**: React 19 SPA with TypeScript and Vite.
- **Styling**: Tailwind CSS v4 + custom CSS dark/light theme variables.
- **Visuals & Charts**: Recharts (Radar charts for multi-engine confidence, Bar/Pie charts for telemetry breakdown).
- **Icons**: Lucide React.

```
src/
├── App.tsx                     # Main application layout, state orchestrator, SSE receiver
├── components/
│   ├── Header.tsx              # Brand banner, analyst badge, system health indicator, theme switch
│   ├── SearchConsole.tsx       # Auto-detecting input box, file upload dropzone, sample indicator quick-buttons
│   ├── SummaryStrip.tsx        # High-level statistics ticker (Score, Consensus, Latency, Active Providers)
│   ├── VerdictBanner.tsx       # Primary AI verdict header, confidence meter, executive summary
│   ├── ChartsPanel.tsx         # Recharts multi-source radar and vendor detection bar breakdown
│   ├── MitreAttackMatrix.tsx   # Categorized MITRE ATT&CK tactics, techniques, and evidence pill matrix
│   ├── ProviderCard.tsx        # Card representations of each threat intel provider's telemetry
│   ├── ProviderDetailModal.tsx # Raw JSON & telemetry inspector for individual provider responses
│   ├── VirusTotalDeepDive.tsx  # Interactive SVG graph and scanner engine breakdown modal
│   ├── HybridAnalysisDeepDive.tsx # Falcon sandbox behavioral indicators and process tree modal
│   ├── AlienVaultOTXDeepDive.tsx  # Community threat pulses, adversary attribution, and advisory modal
│   ├── IocTable.tsx            # Defanged extracted IOCs table with one-click copy & CSV/STIX export
│   ├── HistoryDrawer.tsx       # Slide-out drawer with chronological past lookups & quick reload
│   ├── ReportModal.tsx         # Full-screen incident dossier preview with live print/PDF trigger
│   └── HeroBackground.tsx      # Subtle animated grid and cyber radar background
└── types/                      # Comprehensive TypeScript definitions for lookups, providers, verdicts
```

---

## 10. REST API Specification

### Endpoints Reference

#### `POST /api/lookup`
Synchronous unified lookup.
- **Body**: `{ indicator: string, type?: IndicatorType, analyst_name?: string }`
- **Response**: `{ lookup_id: string, evidence: ConsolidatedEvidence, ... }`

#### `GET /api/lookup/stream`
Server-Sent Events (SSE) streaming lookup.
- **Query Params**: `indicator`, `type`, `analyst_name`
- **Events**: `provider_update`, `complete`, `error`

#### `POST /api/submit`
File upload and URL submission analysis.
- **Payload**: `multipart/form-data` with `file` or JSON `{ url: string }`
- **Response**: Computes SHA-256, MD5, SHA-1, size, MIME type and initiates provider triage.

#### `GET /api/lookup/:id`
Retrieves stored lookup evidence and telemetry by lookup ID.

#### `POST /api/analyze`
Triggers or retrieves Gemini AI triage verdict for a completed lookup.
- **Body**: `{ lookup_id: string, refresh?: boolean, analyst_name?: string }`
- **Response**: `AIAnalysisVerdict` object.

#### `GET /api/report/:analysis_id.pdf`
Renders print-ready, high-resolution HTML incident dossier formatted for browser print-to-PDF.

#### `GET /api/iocs/:analysis_id`
Exports defanged IOCs.
- **Query Params**: `format=csv` (default) or `format=stix`.

#### `GET /api/history`
Returns chronological lookup investigation history.

#### `GET /api/health`
System operational status and provider connectivity health check.

---

## 11. Data Persistence & Cache Strategy

Located at `server/db.ts`:

- **Dual-Storage Engine**: Combines high-speed in-memory Map indexing with durable asynchronous disk persistence in `data/db.json`.
- **Atomic Operations**: Writes use atomic serialization to prevent corruption during concurrent lookup operations.
- **Session Cache Duration**: Indicators are cached with timestamps to prevent redundant external API quota consumption while supporting an analyst-forced `refresh` trigger.

---

## 12. Verification & Build Verification

The project compiles cleanly using standard toolchains:
```bash
# Verify TypeScript typing & linting
npm run lint

# Build production bundle
npm run build

# Launch dev full-stack server
npm run dev
```
All linting checks pass with 0 errors across server and client codebases.
