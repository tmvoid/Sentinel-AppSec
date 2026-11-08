# Production Free Hosting & Fullstack Deployment Plan for Sentinel AppSec

A comprehensive production deployment architecture and step-by-step implementation plan to host Sentinel AppSec completely free ($0/month) with 100% authentic, unrestricted security audits, automated GitHub Actions CI/CD on git push, and an in-app live backend connection manager.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> The primary requirement is generating **100% genuine, real-world audit results** with zero synthetic fallback data. Browser-only static hosts (like GitHub Pages) are constrained by web browser CORS and Mixed-Content sandboxes, which block direct inspection of third-party HTTP headers. To guarantee genuine audits without paying for servers, we provide an all-in-one free fullstack deployment on **Render** (or **Koyeb**) alongside an in-app **Backend Connection Manager** that lets the GitHub Pages frontend connect to any live Node.js engine.

- **Confirmed Decision (Hosting Architecture)**: **All-in-One Fullstack on Render Free Tier ($0/mo)** as the primary live web service, paired with an automated GitHub Actions deployment workflow.
- **Confirmed Decision (Decoupled Flexibility)**: Maintain the existing GitHub Pages deployment as an alternate client distribution, enhanced with a live **Backend Connection Manager** in the header so the static site can query the free Render backend or a local `localhost:3000` instance.
- **Confirmed Decision (CI/CD)**: Automated GitHub Actions workflow on `git push` to `main`, plus one-click Render Blueprint specification (`render.yaml`).

---

## 1. Overview & Core Concept

### What It Delivers
* **100% Genuine Network Audits**: Full OS socket access via Node.js (`server.ts`) capable of inspecting arbitrary targets (`youtube.com`, university portals, enterprise APIs) without browser CORS, preflight, or mixed-content interference.
* **Completely Free ($0/mo)**: Leverages Render's Free Web Service tier (750 free instance hours per month, custom domains, free automatic TLS certificates, zero credit card required).
* **Automated CI/CD**: Automatic builds and deployments triggered immediately whenever code is pushed to the GitHub repository.
* **In-App Backend Connection Manager**: A top-tier UI component displaying real-time engine connectivity, latency ping, and an endpoint selector allowing users on static mirrors (like GitHub Pages) to connect to their live backend.

### Target Audience & Persona
* **Application Security Engineers & Penetration Testers**: Running black-box audits against deployed web services and internal APIs.
* **Developers & Students**: Performing pre-deployment checks, auditing npm dependency trees via OSV.dev, and verifying JWT token hygiene.
* **Tanmay Bhardwaj Portfolio & Demonstration**: A showcase of deterministic DevSecOps tooling accessible globally without paywalls.

---

## 2. User Experience & Visual Design

### A. Navigation & Engine Status Indicator (Top Bar Contract)
Following the strict 3-zone header layout (`[Brand wordmark] — [Nav links] — [Engine Status & Action]`):
* **Zone 1 (Brand)**: `Sentinel AppSec` wordmark with subtle author attribution and logo asset.
* **Zone 2 (Navigation Links)**: `Audit Console`, `Verification Ledger`, `Audit History`, `Methodology`.
* **Zone 3 (Engine Status & Actions)**:
  * An interactive **Engine Status Pill** showing connection mode:
    * `🟢 Live Node Engine (Direct Sockets)` when connected to a fullstack server (AI Studio or Render).
    * `🟡 Remote Backend Connected (Ping: 42ms)` when a static client (GitHub Pages) is paired with a live backend.
    * `⚪ Browser Sandbox Mode (Limited CORS)` with an instant "Connect Live Engine" prompt.
  * Clicking the status pill opens the **Engine Settings Drawer**.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [🛡️ Sentinel AppSec]       Audit Console · Ledger · History · Methodology    [🟢 Node Engine] │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### B. In-App Backend Connection Modal / Drawer
When the user clicks the status indicator or runs an audit in browser sandbox mode:
* **Current Engine State**: Shows active API base URL, round-trip latency ping test, and capability checklist (Raw Headers, Cross-Origin Sockets, Bundle Probing, OSV Supply Chain, JWT Cracking).
* **Connection Options**:
  1. **Automatic / Same-Origin**: Automatically uses the current origin (`/api/audit/run`) when hosted fullstack.
  2. **Custom Cloud Backend**: Allows entering the free Render service URL (e.g., `https://sentinel-appsec.onrender.com`).
  3. **Local Dev Engine**: One-click preset to connect to `http://localhost:3000`.
* **Latency & Health Verification**: An interactive "Test Connection" button that issues a lightweight health check to `/api/health` and verifies socket readiness with exact millisecond latency.
* **Persistent Preferences**: Saves the preferred backend URL in `localStorage` so users never have to re-enter it.

### C. Visual Identity & Theme
* **Canvas**: Deep Obsidian Slate (`#0B0F17`) in dark mode; crisp clean off-white (`#F8FAFC`) in light mode.
* **Card Depth**: Single-elevation flat containers with 1px hairline borders (`border-slate-800 dark:border-slate-800/80`).
* **Accents**: Cyber Cyan (`#06B6D4` / `#0891B2`) for primary actions; Emerald (`#10B981`) for verified passes; Amber (`#F59E0B`) for warnings; Crimson (`#EF4444`) for high/critical findings.
* **Typography**: `Plus Jakarta Sans` for clean, professional display titles; `DM Sans` for body copy; `JetBrains Mono` with `tabular-nums` for all telemetry, timings, and code evidence.

---

## 3. Free Hosting Platforms: Evaluation & Architecture

### Free Hosting Comparison Matrix

| Platform | Free Tier Specifications | Server-Side Node.js? | Unrestricted HTTP Audits? | Setup Effort | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Render Web Service** | 750 free hrs/month, free SSL, custom domain, auto Git deploy | **Yes (Full Node.js)** | **Yes (100% Genuine)** | **Minimal (Zero config)** | **Recommended Primary** |
| **Koyeb Free Tier** | Free nano instance, 512MB RAM, global edge, auto Git deploy | **Yes (Full Node.js)** | **Yes (100% Genuine)** | Low | Excellent Backup |
| **GitHub Pages** | Unlimited static hosting, CDN distribution | No (Static JS only) | No (Restricted by CORS) | Existing | Client Static Mirror |
| **Vercel Hobby** | 100GB bandwidth, serverless functions | Yes (Serverless) | Partial (10s execution timeout) | Medium | Good for lightweight |

### Primary Free Recommendation: Render Free Web Service
1. **Zero Cost**: Render's free Web Service tier provides continuous hosting for Node.js web applications at $0.
2. **Native Fullstack Support**: Render runs `node server.ts` directly, mounting both the Vite frontend and Express backend on port 3000.
3. **No CORS Workarounds**: Because frontend and backend live on the same domain (`https://sentinel-appsec.onrender.com`), all `/api/audit/run` calls are same-origin and instant.
4. **Automated Continuous Deployment**: Render connects directly to the GitHub repository (`tmvoid/Sentinel-AppSec`). Every `git push` to `main` automatically triggers a fresh build and zero-downtime deployment.

---

## 4. Technical Architecture & Implementation Steps

### A. System Architecture Diagram

```
[ Developer / Git Push ]
          │
          ├───► GitHub Repository (tmvoid/Sentinel-AppSec)
          │             │
          │             ├───► GitHub Actions (Automated CI & Pages Build)
          │             │             │
          │             │             └───► GitHub Pages (Static Mirror)
          │             │                         │ (Queries via CORS)
          │             │                         ▼
          │             └───► Render Web Service (Automated CD)
          │                           │
          │                           ├─── Express Server (server.ts)
          │                           ├─── Direct OS Sockets (Raw HTTP / TLS)
          │                           └─── Built Frontend (dist/)
          │
[ Target Domain (e.g., youtube.com) ] ◄─── Raw TCP / HTTP Inspection
```

### B. Step-by-Step Implementation Workflows

#### 1. Add Render Deployment Configuration (`render.yaml`)
Create an automated Infrastructure-as-Code blueprint in the root directory:
* **Service Type**: `web`
* **Environment**: `node`
* **Plan**: `free`
* **Build Command**: `npm install && npm run build`
* **Start Command**: `node server.ts`
* **Environment Variables**: `NODE_ENV=production`, `PORT=3000`

#### 2. Enable Cross-Origin CORS on `server.ts`
Ensure `server.ts` includes an explicit CORS middleware allowing requests from `https://tmvoid.github.io` and `http://localhost:*`:
* Enables the static GitHub Pages deployment to seamlessly use the free Render backend without origin rejection.
* Supports preflight `OPTIONS` requests and JSON payloads.

#### 3. Implement In-App Backend Connection Manager
* Create `src/components/BackendConnectionModal.tsx`:
  * Current endpoint status pill in the navbar.
  * Real-time latency measurement via `GET /api/health`.
  * Input field to override or specify backend URL with localStorage persistence.
  * Capability badges showing which engine features are active.
* Update `src/App.tsx` and `src/utils/clientAuditEngine.ts`:
  * Audit requests first check the configured backend URL (falling back to `/api/audit/run` or client engine).
  * Seamless notification if the user needs to connect a live engine for third-party domain inspection.

#### 4. Configure Automated GitHub Actions Workflow (`.github/workflows/deploy.yml`)
* Automate the GitHub Pages build and deployment on every push to `main`.
* Add automated lint and build verification steps before deploying.

---

## 5. Verification & Deployment Checklist

- [ ] **Render Blueprint**: `render.yaml` created and verified for one-click deployment.
- [ ] **Server CORS**: `server.ts` configured with permissive CORS headers for the GitHub Pages domain.
- [ ] **Health Endpoint**: `GET /api/health` responding with server status, uptime, and engine capabilities.
- [ ] **Backend Connection UI**: Connection manager modal integrated into `src/App.tsx` with live latency test.
- [ ] **Clean Compilation**: Co-execute `compile_applet` and `lint_applet` to ensure zero TypeScript/lint errors.
- [ ] **Step-by-Step Guide**: Provide exact, copy-paste instructions for linking Render to GitHub in under 2 minutes.
