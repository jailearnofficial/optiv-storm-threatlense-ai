# OPTIV S.T.O.R.M · ThreatLense AI

**Next-Generation Unified SOC Threat Triage & Incident Investigation Console**

OPTIV S.T.O.R.M ThreatLense AI aggregates and correlates live threat telemetry across 7 independent security intelligence feeds in parallel, analyzes findings using Google Gemini AI, maps adversarial tradecraft directly to the **MITRE ATT&CK Enterprise Matrix**, and generates exportable forensic reports, STIX 2.1 bundles, and defanged IOC catalogs.

---

## ⚡ Key Capabilities

- **7-Way Parallel Threat Intelligence Fan-Out**:
  - **VirusTotal**: Multi-engine detection distribution, behavioral analysis, and topological entity graph explorer.
  - **AbuseIPDB**: IP reputation confidence score, ISP/ASN routing context, and abuse report count.
  - **AlienVault OTX**: Threat pulse correlation, targeted geographies, and APT attribution.
  - **URLhaus**: Malware payload distribution tags, online status, and URL signatures.
  - **urlscan.io**: Web page screenshot capture, DOM behavioral analysis, and HTTP transaction inspection.
  - **ThreatFox**: C2 infrastructure indicators, malware family tags, and confidence levels.
  - **Hybrid Analysis (Falcon Sandbox)**: Dynamic malware detonation, process tree lineage, and behavioral MITRE ATT&CK tags.
- **ThreatLense AI Synthesis**:
  - Synthesizes findings using Gemini AI (`gemini-3.8-flash`) into executive summaries, verdict classifications (`Malicious`, `Suspicious`, `Benign`, `Inconclusive`), confidence ratings, and priority mitigation steps.
- **MITRE ATT&CK Matrix Alignment**:
  - Correlates techniques (e.g., T1071, T1059, T1105) with behavioral evidence and automated remediation playbooks.
- **Enterprise Forensic Reporting**:
  - Print-ready and downloadable PDF / HTML reports branded for incident response workflows.
  - One-click export of verified defanged IOCs in **STIX 2.1 JSON** and **CSV** (with RFC-compliant sanitization against formula injection).
- **Secure File Detonation & Routing Architecture**:
  - **Dynamic Detonation Modal**: When an analyst drops or uploads a suspicious binary or script, ThreatLense AI prompts with a detonation target chooser:
    1. **External Threat Intelligence Network**: Computes cryptographic digests (MD5, SHA-1, SHA-256) in memory and queries VirusTotal, Falcon Sandbox, and MalwareBazaar without releasing confidential binaries.
    2. **In-House Isolated Air-Gapped Sandbox**: Directs samples to private guest VMs (Windows 10 Pro 22H2, Windows 11 Enterprise with Office 365, or Ubuntu 22.04 LTS). Traces process hollowing, memory injections, registry persistence, and network beacons while guaranteeing zero third-party cloud leakage.
    3. **Dual-Track Hybrid Detonation**: Forks execution simultaneously into both external threat feeds and the in-house sandbox for complete cross-validation.

---

## 🛡️ Security Architecture

- **Zero Client-Side API Keys**: All provider requests and Gemini API calls are securely proxied through backend server routes (`/api/*`).
- **Firebase Authentication Token Verification**:
  - All `/api/*` investigation endpoints (except `/api/health`) require a valid Firebase ID token (`Bearer <token>` or `X-Firebase-Token` header) verified using Google's RS256 x509 public certificates.
  - Prevents unauthorized API usage, scraping, and abuse of backend intelligence feeds.
- **Strict Origin-Restricted CORS**:
  - No wildcard origins (`*`).
  - Cross-Origin Resource Sharing is strictly constrained to authorized domains:
    - `https://optiv-storm-threatlense-ai.vercel.app` (Official production portal)
    - `https://*.optiv.com` (Optiv corporate domains)
    - `http://localhost:*` & `http://127.0.0.1:*` (Local development)
  - Enforces `Vary: Origin`, `Access-Control-Allow-Credentials: true`, and strict allowed headers (`Content-Type`, `Authorization`, `X-Requested-With`, `Accept`, `X-Firebase-Token`).
- **Hardened Content Security Policy (CSP)**:
  - Enforces strict frame embedding restrictions:
    ```http
    Content-Security-Policy: frame-ancestors 'self' https://aistudio.google.com https://optiv-storm-threatlense-ai.vercel.app https://*.optiv.com;
    ```
- **Clickjacking & Header Hardening**: Enforces `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-XSS-Protection: 1; mode=block`, and strict `Permissions-Policy`.
- **Active 24-Hour Forensic Retention**:
  - Strict 24-hour investigative history window (`/api/history`) with automatic timestamp expiration and manual force-purge (`POST /api/history/purge`).
- **Defanged by Default**: All indicators (domains, IPs, URLs) are defanged (`hxxp://`, `example[.]com`) across UI views and exports to prevent accidental navigation or clickjacking.
- **Formula Injection Defense (CWE-1236)**: CSV exports automatically neutralize formula characters (`=`, `+`, `-`, `@`).
- **Strict Input Validation & SSRF Guard**: Indicator detection and validation prevent SSRF or malformed parameter attacks against RFC 1918 private subnets and cloud metadata endpoints.

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** >= 18.x
- **npm** >= 9.x (or `pnpm` / `bun`)

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/your-org/optiv-storm-threatlense-ai.git
cd optiv-storm-threatlense-ai
npm install
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` with your API credentials:

```ini
# Required for ThreatLense AI Synthesis
GEMINI_API_KEY="your-gemini-api-key"

# Optional: Threat Intelligence Feeds
# If omitted or empty, realistic fallback intelligence is automatically provided
VT_API_KEY=""
HA_API_KEY=""
ABUSECH_AUTH_KEY=""
ABUSEIPDB_API_KEY=""
URLSCAN_API_KEY=""
OTX_API_KEY=""

PORT=3000
```

### 3. Launch Development Server

```bash
npm run dev
```

Visit `http://localhost:3000` in your browser.

### 4. Build for Production

```bash
npm run build
npm start
```

---

## ☁️ Deploying to Vercel

The repository is pre-configured with `vercel.json` and a serverless API adapter (`api/index.ts`):

1. **Push your repository to GitHub**.
2. Go to [vercel.com](https://vercel.com) and click **"Add New Project"** -> **Import Git Repository**.
3. In **Environment Variables**, add:
   - `GEMINI_API_KEY`: Your Google Gemini API Key.
   - *(Optional)* Add any provider keys: `VT_API_KEY`, `HA_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY`, `OTX_API_KEY`, `ABUSECH_AUTH_KEY`. (If omitted, automatic intelligent fallback feeds are served).
4. Click **Deploy**. Vercel will automatically build the React Vite frontend and route all `/api/*` endpoints to the serverless function.

---

## 📂 Project Structure

```
├── server/                     # Backend proxy, intelligence engines & report generation
│   ├── ai/                     # Gemini AI triage prompt orchestration & validation
│   ├── providers/              # 7-way parallel threat intelligence integrations
│   ├── report/                 # Forensic HTML/PDF, STIX 2.1 & CSV generator
│   ├── db.ts                   # In-memory query cache & lookup store
│   ├── detect.ts               # Regex indicator detection & defanging utilities
│   ├── orchestrator.ts         # Parallel promise fanout & rule-based scoring engine
│   └── scoring.ts              # Weighted multi-source risk assessment algorithms
├── src/                        # Frontend React 19 application
│   ├── components/             # Telemetry cards, VT Graph Explorer, Header, Report modals
│   ├── App.tsx                 # Main SOC triage interface
│   ├── index.css               # Tailwind CSS theme
│   └── main.tsx                # Client entry point
├── server.ts                   # Express server entry point mounting Vite middlewares
├── .env.example                # Template environment variables
├── package.json                # Project dependencies and run scripts
└── vite.config.ts              # Vite + React build configuration
```

---

## 📜 License

Licensed under the [MIT License](LICENSE).
