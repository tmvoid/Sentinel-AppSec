<p align="center">
  <img src="public/logo.png" alt="Sentinel AppSec Logo" width="130" style="border-radius: 50%; box-shadow: 0 0 30px rgba(6, 182, 212, 0.4);" />
</p>

<h1 align="center">Sentinel AppSec</h1>

<p align="center">
  <strong>Universal Empirical Vulnerability, Exploit Proof & Automated Hardening Platform</strong>
</p>

<p align="center">
  <em>Zero synthetic hallucinations. Zero generic checklists. Every finding backed by verifiable cryptographic proof, raw HTTP telemetry, and line-level SAST evidence.</em>
</p>

<p align="center">
  <a href="https://tmvoid.github.io/Sentinel-AppSec/"><img src="https://img.shields.io/badge/Static_UI_Showcase-GitHub_Pages-0284c7?style=for-the-badge&logo=githubpages&logoColor=white" alt="Static UI Showcase" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-20+-22c55e?style=for-the-badge&logo=node.js&logoColor=white" alt="Node Version" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-7.0-3178c6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" /></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/React-19-61dafb?style=for-the-badge&logo=react&logoColor=black" alt="React 19" /></a>
  <a href="https://tailwindcss.com/"><img src="https://img.shields.io/badge/Tailwind_CSS-v4-38bdf8?style=for-the-badge&logo=tailwindcss&logoColor=white" alt="Tailwind CSS v4" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge" alt="License" /></a>
</p>

<p align="center">
  Architected and engineered by <strong><a href="https://www.linkedin.com/in/tanmaysbhardwaj/">Tanmay Bhardwaj</a></strong> (<strong><a href="https://github.com/tmvoid">@tmvoid</a></strong>)
</p>

---

## 🛡️ Overview

**Sentinel AppSec** is a modern, deterministic application security audit and exploitability verification platform. Built specifically for developers, DevSecOps practitioners, and security auditors, Sentinel bridges the gap between superficial static scanners and active penetration testing.

Unlike traditional compliance scanners that generate noisy alerts based on string matching or speculative checks, Sentinel operates on a strict **empirical verification model**: every vulnerability reported includes a reproducible command (`curl`), raw response headers, cryptographic cracking evidence, extracted script strings, or exact source code lines.

> [!IMPORTANT]
> ### 🔒 Local-First Privacy Architecture & Static Preview Notice
> * **Why GitHub Pages is a Static UI Showcase (Demo Mode)**: The deployed [**GitHub Pages site (`tmvoid.github.io/Sentinel-AppSec`)**](https://tmvoid.github.io/Sentinel-AppSec/) is a purely static frontend build intended as a **visual display showcase** to demonstrate how the platform looks and operates. Because static hosting runs inside a web browser sandbox without a live Node.js socket server, it **does not produce authentic live network audit results** on external domains.
> * **Why Authentic Audits Run on Your Own Device (Privacy by Design)**: Security auditing inherently involves sensitive infrastructure URLs, proprietary source code, internal endpoints, and active JWT session tokens. Because **we value strict data privacy**, Sentinel AppSec is architected to be installed and executed locally on your own machine (`npm run engine`).
> * **100% On-Device Reports**: When you run Sentinel locally, every raw-socket probe is executed directly from your device's operating system network stack, and **every audit report and PDF you generate stays exclusively on your device**—never transmitted to, logged by, or stored on any external server.

### 🌟 Why Sentinel AppSec?

* **Strict On-Device Privacy**: Zero cloud logging. Every scan, source file, token, and exported PDF report stays strictly on your personal machine.
* **Deterministic Verification**: No speculative heuristics or unverified risk scoring.
* **100% Private Local Audit Daemon**: Run audits directly through your workstation's raw network sockets with zero external cloud dependencies.
* **Cross-Platform by Design**: Fully compatible across **Linux (Fedora, Ubuntu, Arch, Debian)**, **macOS**, and **Windows (PowerShell, CMD, WSL)**.
* **Dual-Architecture Runtime**: Operates seamlessly as a self-contained local fullstack server (`http://localhost:3000`), or pairs the static UI showcase with your local daemon via W3C Private Network Access.
* **Automated Remediation Studio**: Generates drop-in server and framework hardening snippets (Express, Nginx, Next.js, Vercel) and provides Before-vs-After delta comparison.
* **Executive PDF Generation**: Exports client-ready, tamper-evident security audit reports locally in your browser.

---

## ⚡ The 7 Deterministic Verification Engines

Sentinel runs your target through seven purpose-built auditing engines:

```
                                  ┌─────────────────────────────┐
                                  │    Sentinel Target Scope    │
                                  │   (URL / Repo / JWT / Files)│
                                  └──────────────┬──────────────┘
                                                 │
         ┌───────────────────┬───────────────────┼───────────────────┬───────────────────┐
         │                   │                   │                   │                   │
         ▼                   ▼                   ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ 01. HTTP & CORS │ │ 02. Route Probe │ │ 03. JS Harvester│ │ 04. JWT Cracker │ │ 05. Protocol    │
│ Headers, TLS,   │ │ SPA 404 Filter, │ │ Hidden Endpoints│ │ HS256 Dictionary│ │ GraphQL Schema, │
│ Clickjacking,   │ │ /.env, /.git,   │ │ Leaked Secrets, │ │ alg:none, forged│ │ HTTP Verbs,     │
│ Origin Mirror   │ │ .js.map files   │ │ Client Sourcemap│ │ Admin Signature │ │ Open Redirects  │
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
                                                 │
                                                 ├───────────────────────────────┐
                                                 ▼                               ▼
                                  ┌─────────────────────────────┐ ┌─────────────────────────────┐
                                  │ 06. OSV.dev Supply-Chain    │ │ 07. Deterministic Code SAST │
                                  │ Live Upstream CVE / GHSA    │ │ Regex Sinks, Dangerous Keys,│
                                  │ Manifest Dependency Audit   │ │ SQLi & DOM XSS Line Mapping │
                                  └─────────────────────────────┘ └─────────────────────────────┘
```

| Engine | Verification Focus | Exploitability & Proof Provided |
| :--- | :--- | :--- |
| **01. HTTP, CORS & Clickjacking** | CSP, HSTS, X-Frame-Options, MIME sniffing, wildcard CORS | Exact response headers, reproduction `curl -sI`, framing PoC simulation |
| **02. Dotfile & Sourcemap Prober** | `/.env`, `/.git/config`, `app.bundle.js.map` | Adaptive SPA 404 signature comparison, exposed secret payload dumps |
| **03. JS Bundle & Route Harvester** | Client JavaScript bundle inspection | Harvests hidden `/api/*` and `/admin/*` endpoints and embedded tokens |
| **04. JWT Cryptographic Cracker** | Algorithm confusion (`alg: none`), weak HMAC keys | High-speed dictionary cracking + forged Admin JWT cryptographic PoC |
| **05. Protocol & Verb Auditor** | GraphQL `__schema` dump, HTTP TRACE/OPTIONS, Open Redirect | Verifies introspection locks, verb tampering, and unvalidated 3xx redirects |
| **06. OSV.dev Supply-Chain CVE** | `package.json` manifest dependencies | Direct API batch querying of Open Source Vulnerabilities (OSV) database |
| **07. Deterministic Code SAST** | AWS keys, Stripe tokens, SQLi template interpolation, DOM XSS | Line-numbered code citations with before/after secure replacement snippets |

---

## 🚀 Getting Started

Sentinel AppSec is built to work out of the box on **Windows**, **Linux (Fedora, Ubuntu, Debian, Arch)**, and **macOS**.

### Method A: 100% Private Local Engine (Recommended)

This method runs both the web UI and the Node.js audit daemon on your personal computer. It requires **zero external cloud accounts**, keeps all code and tokens strictly on your machine, and provides unrestricted raw socket access to audit any local or external target:

```bash
# 1. Clone the repository
git clone https://github.com/tmvoid/Sentinel-AppSec.git
cd Sentinel-AppSec

# 2. Install dependencies (Works across Windows, Linux, Fedora & macOS)
npm install
# Or use the clean cross-platform setup script:
npm run setup

# 3. Start the Sentinel engine
npm run engine
```

Open your browser to:
```
http://localhost:3000
```

> **Tip**: You can also run `npm run dev` to start Vite with Hot Module Replacement alongside the Express backend.

---

### Method B: Static Web Console + Local Daemon (Hybrid)

If you are using the hosted web version at [**tmvoid.github.io/Sentinel-AppSec**](https://tmvoid.github.io/Sentinel-AppSec/):

1. Start your local daemon on your machine:
   ```bash
   npm run engine
   ```
2. In the web console, click **Engine & Free Cloud Deploy** in the navigation bar.
3. Select the preset: **Local Node.js Dev Engine (`http://localhost:3000`)**.
4. Sentinel leverages W3C Private Network Access (`Access-Control-Allow-Private-Network: true`) to pipe audit requests directly through your workstation's raw socket engine!

---

## 🛠️ Available Scripts

| Command | Action | Platform Support |
| :--- | :--- | :--- |
| `npm run engine` | Boots the fullstack Sentinel server & audit daemon on `http://localhost:3000` | Windows, Linux, macOS |
| `npm run dev` | Runs the fullstack development server with Vite HMR | Windows, Linux, macOS |
| `npm run setup` | Clean, peer-dependency safe installation (`npm install --legacy-peer-deps`) | Windows, Linux, macOS |
| `npm run build` | Compiles the production frontend bundle into `dist/` | Windows, Linux, macOS |
| `npm run start` | Starts the production server hosting `dist/` and `/api/*` | Windows, Linux, macOS |
| `npm run lint` | Runs TypeScript type verification (`tsc --noEmit`) | Windows, Linux, macOS |
| `npm run clean` | Cross-platform cleanup of `dist/` and `server.js` using Node.js | Windows, Linux, macOS |

---

## 📊 Project Structure

```
├── .github/
│   └── workflows/
│       └── deploy.yml            # Automated GitHub Actions CI/CD to GitHub Pages
├── public/
│   └── logo.png                  # Canonical Sentinel shield insignia
├── src/
│   ├── components/
│   │   ├── BackendConnectionModal.tsx # Engine selector & latency monitor
│   │   ├── EvidenceDrawer.tsx         # Slide-over raw proof & exploit viewer
│   │   ├── HardeningStudio.tsx        # Remediation & config generator
│   │   ├── ReportExportModal.tsx      # Multi-format PDF report generator
│   │   ├── SpotlightCard.tsx          # Micro-interaction container components
│   │   └── ThemeToggle.tsx            # Obsidian Dark / Alabaster Light toggle
│   ├── types/
│   │   └── audit.ts              # TypeScript domain schemas and interfaces
│   ├── utils/
│   │   ├── assets.ts             # Base-aware asset resolution
│   │   ├── clientAuditEngine.ts  # In-browser deterministic fallback scanner
│   │   └── pdfExport.ts          # Clean vector PDF audit report generator
│   ├── App.tsx                   # Main console orchestration layout
│   └── main.tsx                  # Application bootstrap
├── .env.example                  # Environment variable reference template
├── .npmrc                        # Cross-platform peer dependency resolution rule
├── Dockerfile                    # Containerization recipe for cloud hosts
├── LICENSE                       # Apache 2.0 open-source license
├── package.json                  # Dependencies, scripts, and engine entrypoints
├── render.yaml                   # Infrastructure-as-Code blueprint for Render
├── server.ts                     # Fullstack Node.js server with raw socket audit engines
├── tsconfig.json                 # TypeScript compiler configuration
└── vite.config.ts                # Vite build and Tailwind CSS v4 setup
```

---

## 🔒 Security & Privacy Posture

* **Zero Telemetry Collection**: Sentinel AppSec contains zero third-party analytics, user tracking beacons, or telemetry logging.
* **Safe Local Storage**: Audit history, theme preferences, and custom backend URLs are stored solely in your browser's private `localStorage`.
* **Private Network Isolation**: When connecting from the public web console to your local daemon, all requests are scoped strictly to the `/api/*` prefix with strict origin checks.

---

## 👨‍💻 Author & Attribution

**Sentinel AppSec** is engineered and maintained by:

* **Tanmay Bhardwaj**
  * LinkedIn: [linkedin.com/in/tanmaysbhardwaj](https://www.linkedin.com/in/tanmaysbhardwaj/)
  * GitHub: [@tmvoid](https://github.com/tmvoid)

---

## 📄 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for complete details.
