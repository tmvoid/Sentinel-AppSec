/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  Code2,
  FileCode2,
  FileDown,
  FilePlus2,
  FileText,
  Flame,
  FolderGit2,
  GitCompare,
  Globe,
  KeyRound,
  Loader2,
  Network,
  PackageCheck,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
  Wifi,
  WifiOff,
  Wrench,
  X,
} from 'lucide-react';
import {
  BackendConnectionModal,
  type BackendConnectionState,
} from './components/BackendConnectionModal.tsx';
import { EvidenceDrawer } from './components/EvidenceDrawer.tsx';
import { HardeningStudio } from './components/HardeningStudio.tsx';
import MicroSlats from './components/MicroSlats.jsx';
import { ReportExportModal } from './components/ReportExportModal.tsx';
import { BlurRevealHeading, SpotlightCard } from './components/SpotlightCard.tsx';
import { ThemeToggle, type ThemeMode } from './components/ThemeToggle.tsx';
import { SENTINEL_LOGO_SRC } from './utils/assets.ts';
import { runClientSideAudit } from './utils/clientAuditEngine.ts';
import type {
  AuditModuleId,
  AuditReport,
  AuditTargetConfig,
  RemediationDelta,
  SeverityLevel,
  UploadedCodeFile,
  VerifiedFinding,
} from './types/audit.ts';

const STORAGE_KEY = 'sentinel_appsec_real_audits_v3';
const LEGACY_STORAGE_KEY = 'sentinel_audit_history_v1';
const THEME_STORAGE_KEY = 'sentinel_theme_mode';
const BACKEND_URL_STORAGE_KEY = 'sentinel_custom_backend_url';

const SEVERITY_LABEL_STYLES: Record<SeverityLevel, string> = {
  critical: 'text-[#EF4444] font-semibold',
  high: 'text-[#F97316] font-semibold',
  medium: 'text-[#F59E0B] font-semibold',
  low: 'text-[#38BDF8] font-semibold',
};

const MODULE_NAMES: Record<AuditModuleId, string> = {
  http: 'HTTP, CORS & Transport',
  exposure: 'Route & Sourcemap Prober',
  dependencies: 'OSV.dev Dependency CVE',
  sast: 'Source Code SAST & Secrets',
  bundle: 'JS Bundle & API Harvester',
  jwt: 'JWT Weak-Secret Auditor',
  protocol: 'GraphQL, Verbs & Redirects',
};

function computeRemediationDelta(
  before: AuditReport,
  after: AuditReport
): RemediationDelta {
  const getKey = (f: VerifiedFinding) => `${f.module}::${f.cwe}::${f.title}`;
  const beforeMap = new Map(before.findings.map((f) => [getKey(f), f]));
  const afterMap = new Map(after.findings.map((f) => [getKey(f), f]));

  const resolvedFindings: VerifiedFinding[] = [];
  for (const [k, f] of beforeMap.entries()) {
    if (!afterMap.has(k)) {
      resolvedFindings.push(f);
    }
  }

  const remainingFindings: VerifiedFinding[] = [];
  const newFindings: VerifiedFinding[] = [];
  for (const [k, f] of afterMap.entries()) {
    if (beforeMap.has(k)) {
      remainingFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }

  return {
    baselineReportId: before.id,
    baselineProjectName: before.projectName,
    baselineTimestamp: before.timestamp,
    resolvedFindings,
    remainingFindings,
    newFindings,
    passedDelta: after.passedChecks.length - before.passedChecks.length,
  };
}

export default function App() {
  // Polarity Theme State ('dark' Obsidian | 'bright' Alabaster)
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      return saved === 'bright' ? 'bright' : 'dark';
    } catch {
      return 'dark';
    }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // ignore storage errors
    }
  }, [theme]);

  // Clean, Empty Initial State — Zero Pre-Filled Data or Pre-Loaded Reports
  const [config, setConfig] = useState<AuditTargetConfig>({
    projectName: '',
    targetUrl: '',
    githubRepoUrl: '',
    jwtToken: '',
    uploadedFiles: [],
    modules: {
      httpHeaders: true,
      routeProbing: true,
      dependencyCve: true,
      sourceSast: true,
      jsBundleAudit: true,
      jwtAudit: true,
      protocolProbing: true,
    },
  });

  // Add Custom Source File Inline Form State
  const [isAddingFile, setIsAddingFile] = useState(false);
  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');
  const [selectedFileIndex, setSelectedFileIndex] = useState<number | null>(
    null
  );

  // Audit Execution & Results State (Starts null until user executes an audit)
  const [isRunning, setIsRunning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeReport, setActiveReport] = useState<AuditReport | null>(null);
  const [remediationDelta, setRemediationDelta] =
    useState<RemediationDelta | null>(null);

  const [auditHistory, setAuditHistory] = useState<AuditReport[]>(() => {
    try {
      localStorage.removeItem(LEGACY_STORAGE_KEY);
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved ? (JSON.parse(saved) as AuditReport[]) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    try {
      localStorage.removeItem(LEGACY_STORAGE_KEY);
    } catch {
      // ignore
    }
    console.info('Sentinel AppSec — Engineered by Tanmay Bhardwaj (https://www.linkedin.com/in/tanmaysbhardwaj/ · https://github.com/tmvoid)');
  }, []);

  // Ledger Filtering & UI State
  const [activeLedgerTab, setActiveLedgerTab] = useState<
    'findings' | 'passed' | 'hardening' | 'telemetry'
  >('findings');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'all'>(
    'all'
  );
  const [moduleFilter, setModuleFilter] = useState<AuditModuleId | 'all'>(
    'all'
  );
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] =
    useState<VerifiedFinding | null>(null);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [isBackendModalOpen, setIsBackendModalOpen] = useState(false);
  const [headerLogoError, setHeaderLogoError] = useState(false);
  const [heroLogoError, setHeroLogoError] = useState(false);

  const [backendConnection, setBackendConnection] =
    useState<BackendConnectionState>(() => {
      let savedUrl = '';
      try {
        savedUrl = (localStorage.getItem(BACKEND_URL_STORAGE_KEY) || '').trim();
      } catch {
        // ignore
      }
      return {
        mode: savedUrl ? 'remote-node' : 'same-origin-node',
        customBackendUrl: savedUrl,
        latencyMs: null,
        lastCheckedAt: null,
        isChecking: false,
        error: null,
      };
    });

  const pingBackendConnection = useCallback(
    async (overrideUrl?: string) => {
      const targetBase =
        overrideUrl !== undefined
          ? overrideUrl.trim().replace(/\/+$/, '')
          : backendConnection.customBackendUrl.trim().replace(/\/+$/, '');

      setBackendConnection((prev) => ({
        ...prev,
        isChecking: true,
        error: null,
      }));

      const healthEndpoint = targetBase
        ? `${targetBase}/api/health`
        : '/api/health';
      const startPing = Date.now();
      try {
        const res = await fetch(healthEndpoint, {
          method: 'GET',
          headers: { Accept: 'application/json' },
        });
        const contentType = res.headers.get('content-type') || '';
        if (res.ok && contentType.includes('application/json')) {
          const data = (await res.json()) as { status?: string };
          if (data.status === 'ok') {
            const elapsed = Math.max(1, Date.now() - startPing);
            setBackendConnection({
              mode: targetBase ? 'remote-node' : 'same-origin-node',
              customBackendUrl: targetBase,
              latencyMs: elapsed,
              lastCheckedAt: new Date().toISOString(),
              isChecking: false,
              error: null,
            });
            return;
          }
        }
        throw new Error('Endpoint did not return valid Sentinel Node health JSON');
      } catch {
        setBackendConnection({
          mode: 'browser-sandbox',
          customBackendUrl: targetBase,
          latencyMs: null,
          lastCheckedAt: new Date().toISOString(),
          isChecking: false,
          error: targetBase
            ? `Could not reach Node backend at ${targetBase}. Verify the server is running and accessible.`
            : null,
        });
      }
    },
    [backendConnection.customBackendUrl]
  );

  const handleSaveCustomBackendUrl = useCallback(
    async (newUrl: string) => {
      const cleaned = newUrl.trim().replace(/\/+$/, '');
      try {
        if (cleaned) {
          localStorage.setItem(BACKEND_URL_STORAGE_KEY, cleaned);
        } else {
          localStorage.removeItem(BACKEND_URL_STORAGE_KEY);
        }
      } catch {
        // ignore storage errors
      }
      await pingBackendConnection(cleaned);
    },
    [pingBackendConnection]
  );

  useEffect(() => {
    void pingBackendConnection();
  }, [pingBackendConnection]);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const saveReportToHistory = useCallback((report: AuditReport) => {
    setAuditHistory((prev) => {
      const updated = [
        report,
        ...prev.filter((r) => r.id !== report.id),
      ].slice(0, 12);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // ignore storage quota errors
      }
      return updated;
    });
  }, []);

  const executeAudit = useCallback(
    async (
      targetConfig: AuditTargetConfig,
      baselineForDelta?: AuditReport | null
    ) => {
      if (
        !targetConfig.targetUrl.trim() &&
        !targetConfig.githubRepoUrl.trim() &&
        !(targetConfig.jwtToken && targetConfig.jwtToken.trim()) &&
        targetConfig.uploadedFiles.length === 0
      ) {
        setErrorMessage(
          'Please enter a Live Deployed URL, a Public GitHub Repository URL, a JWT token, or upload/paste project files to audit.'
        );
        return;
      }

      setIsRunning(true);
      setErrorMessage(null);
      try {
        const inferredName =
          targetConfig.projectName.trim() ||
          targetConfig.targetUrl.trim() ||
          targetConfig.githubRepoUrl.trim() ||
          'Target Application Audit';

        let report: AuditReport | null = null;
        const customBase = backendConnection.customBackendUrl
          .trim()
          .replace(/\/+$/, '');
        const auditEndpoint = customBase
          ? `${customBase}/api/audit/run`
          : '/api/audit/run';

        try {
          const pingStart = Date.now();
          const res = await fetch(auditEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              ...targetConfig,
              projectName: inferredName,
            }),
          });
          const contentType = res.headers.get('content-type') || '';
          if (res.ok && contentType.includes('application/json')) {
            report = (await res.json()) as AuditReport;
            setBackendConnection((prev) => ({
              ...prev,
              mode: customBase ? 'remote-node' : 'same-origin-node',
              latencyMs: prev.latencyMs ?? Math.max(1, Date.now() - pingStart),
              error: null,
            }));
          }
        } catch {
          // Backend API unreachable or running on static hosting like GitHub Pages
        }

        // If backend is not available (e.g., deployed statically on GitHub Pages), run in-browser verification
        if (!report) {
          setBackendConnection((prev) => ({
            ...prev,
            mode: 'browser-sandbox',
          }));
          report = await runClientSideAudit(targetConfig, inferredName);
        }
        if (baselineForDelta) {
          setRemediationDelta(
            computeRemediationDelta(baselineForDelta, report)
          );
        } else {
          setRemediationDelta(null);
        }
        setActiveReport(report);
        saveReportToHistory(report);
        if (report.findings.length === 0 && report.passedChecks.length > 0) {
          setActiveLedgerTab('passed');
        } else {
          setActiveLedgerTab('findings');
        }
      } catch (err) {
        setErrorMessage(
          err instanceof Error
            ? err.message
            : 'Unable to complete verification run.'
        );
      } finally {
        setIsRunning(false);
      }
    },
    [backendConnection.customBackendUrl, saveReportToHistory]
  );

  const handleResetWorkspace = () => {
    setConfig({
      projectName: '',
      targetUrl: '',
      githubRepoUrl: '',
      jwtToken: '',
      uploadedFiles: [],
      modules: {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: true,
        sourceSast: true,
        jsBundleAudit: true,
        jwtAudit: true,
        protocolProbing: true,
      },
    });
    setActiveReport(null);
    setRemediationDelta(null);
    setSelectedFileIndex(null);
    setErrorMessage(null);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    const loadedFiles: UploadedCodeFile[] = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const text = await file.text();
      loadedFiles.push({ name: file.name, content: text });
    }

    setConfig((prev) => ({
      ...prev,
      uploadedFiles: [
        ...prev.uploadedFiles.filter(
          (existing) => !loadedFiles.some((nf) => nf.name === existing.name)
        ),
        ...loadedFiles,
      ],
    }));
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleAddInlineFile = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFileName.trim() || !newFileContent.trim()) return;
    const cleanName = newFileName.trim();
    setConfig((prev) => ({
      ...prev,
      uploadedFiles: [
        ...prev.uploadedFiles.filter((f) => f.name !== cleanName),
        { name: cleanName, content: newFileContent },
      ],
    }));
    setNewFileName('');
    setNewFileContent('');
    setIsAddingFile(false);
  };

  const handleRemoveFile = (name: string) => {
    setConfig((prev) => ({
      ...prev,
      uploadedFiles: prev.uploadedFiles.filter((f) => f.name !== name),
    }));
    setSelectedFileIndex(null);
  };

  const filteredFindings = useMemo(() => {
    if (!activeReport) return [];
    return activeReport.findings.filter((f) => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) {
        return false;
      }
      if (moduleFilter !== 'all' && f.module !== moduleFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          f.title.toLowerCase().includes(q) ||
          f.affectedTarget.toLowerCase().includes(q) ||
          f.cwe.toLowerCase().includes(q) ||
          f.owasp.toLowerCase().includes(q) ||
          f.summary.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [activeReport, severityFilter, moduleFilter, searchQuery]);

  const filteredPassedChecks = useMemo(() => {
    if (!activeReport) return [];
    return activeReport.passedChecks.filter((p) => {
      if (moduleFilter !== 'all' && p.module !== moduleFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          p.title.toLowerCase().includes(q) ||
          p.target.toLowerCase().includes(q) ||
          p.proofSummary.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [activeReport, moduleFilter, searchQuery]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    if (!activeReport) return counts;
    for (const f of activeReport.findings) {
      counts[f.severity]++;
    }
    return counts;
  }, [activeReport]);

  const hasTargetInput =
    Boolean(config.targetUrl.trim()) ||
    Boolean(config.githubRepoUrl.trim()) ||
    Boolean(config.jwtToken && config.jwtToken.trim()) ||
    config.uploadedFiles.length > 0;

  const isBright = theme === 'bright';

  return (
    <div
      className={`min-h-screen relative transition-colors duration-300 ${
        isBright
          ? 'theme-bright bg-[#EEF2F7] text-[#0F172A]'
          : 'bg-[#04070E] text-[#F8FAFC]'
      }`}
    >
      {/* =====================================================================
          REACTBITS MICROSLATS INTERACTIVE WEBGL BACKGROUND
          Dynamically adapts between Obsidian Dark and Alabaster Bright Daylight
         ===================================================================== */}
      <div
        className={`fixed inset-0 z-0 transition-opacity duration-300 ${
          isBright ? 'opacity-55' : 'opacity-65'
        }`}
      >
        <MicroSlats
          preset="tide"
          color={isBright ? '#93C5FD' : '#0078D4'}
          glintColor={isBright ? '#0078D4' : '#7DD3FC'}
          backgroundColor={isBright ? '#EEF2F7' : '#04070E'}
          slatWidth={11}
          slatHeight={26}
          gap={3}
          glint={isBright ? 0.45 : 0.55}
          contrast={isBright ? 1.05 : 1.2}
          interactive={true}
          cursorStrength={0.9}
        />
      </div>
      {/* Measured Radial Atmospheric Scrim for Crisp Glassmorphic Depth & WCAG Legibility */}
      <div
        className="pointer-events-none fixed inset-0 z-0 transition-all duration-300"
        style={{
          background: isBright
            ? 'radial-gradient(ellipse 95% 80% at 50% 35%, rgba(248, 250, 252, 0.42) 0%, rgba(238, 242, 247, 0.84) 100%)'
            : 'radial-gradient(ellipse 95% 80% at 50% 35%, rgba(4, 7, 14, 0.35) 0%, rgba(4, 7, 14, 0.78) 100%)',
        }}
      />

      {/* =====================================================================
          STRICT 3-ZONE TOP BAR CONTRACT (GLASSMORPHIC HEADER)
          [Brand Wordmark] — [4 Concise Nav Links] — [Theme Switcher + Primary CTA]
         ===================================================================== */}
      <header
        className={`sticky top-0 z-30 border-b backdrop-blur-2xl transition-colors duration-300 ${
          isBright
            ? 'border-slate-900/10 bg-white/75'
            : 'border-white/[0.10] bg-[#060B16]/65'
        }`}
      >
        <div className="mx-auto flex max-w-[1360px] items-center justify-between gap-6 px-6 py-3.5">
          {/* Zone 1: Single Brand Lockup */}
          <a
            href="#workspace"
            className="flex items-center gap-2.5 font-display text-sm font-bold tracking-tight text-white whitespace-nowrap shrink-0"
          >
            <div className="relative flex h-8 w-8 items-center justify-center rounded-full overflow-hidden ring-1 ring-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.3)] bg-[#070B14] shrink-0">
              <img
                src={SENTINEL_LOGO_SRC}
                alt="Sentinel AppSec Logo"
                className="h-full w-full object-cover"
              />
            </div>
            <span>Sentinel AppSec</span>
          </a>

          {/* Zone 2: 4 Single-Line Navigation Links */}
          <nav className="hidden md:flex items-center gap-8 text-xs font-medium text-[#CBD5E1]">
            <a
              href="#workspace"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Audit Console
            </a>
            <a
              href="#verification-ledger"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Verification Ledger
            </a>
            <a
              href="#recent-audits"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Audit History
            </a>
            <a
              href="#methodology"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Methodology
            </a>
          </nav>

          {/* Zone 3: Premium Polarity Toggler + 1 Primary Action */}
          <div className="flex items-center gap-3 shrink-0">
            <ThemeToggle theme={theme} onChange={setTheme} />
            <button
              onClick={() => setIsExportModalOpen(true)}
              disabled={!activeReport}
              className={`flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all whitespace-nowrap shrink-0 shadow-sm ${
                isBright
                  ? 'bg-[#0078D4] text-white hover:bg-[#0067B8] disabled:bg-slate-900/10 disabled:text-slate-400'
                  : 'bg-white text-[#04070E] hover:bg-[#E2E8F0] disabled:bg-white/[0.1] disabled:text-white/40'
              }`}
            >
              <FileDown className="h-3.5 w-3.5" />
              <span>Export Report & PDF</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Container (1440px Desktop Baseline) */}
      <main className="relative z-10 mx-auto max-w-[1360px] px-6 py-10 space-y-12">
        {/* ===================================================================
            HERO & UNIVERSAL APPSEC ENGINE HEADER
           =================================================================== */}
        <section
          id="workspace"
          className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 pb-2"
        >
          <div className="flex items-start gap-5 max-w-3xl">
            <div className="relative hidden sm:flex h-16 w-16 items-center justify-center rounded-full p-0.5 shrink-0 mt-0.5 ring-2 ring-cyan-500/40 shadow-[0_0_24px_rgba(6,182,212,0.35)] bg-[#070B14] overflow-hidden">
              <img
                src={SENTINEL_LOGO_SRC}
                alt="Sentinel AppSec Security Crest"
                className="h-full w-full object-cover rounded-full"
              />
            </div>
            <div className="space-y-2.5">
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[#CBD5E1]">
                <span className="text-[#38BDF8] font-semibold">
                  APPLICATION SECURITY
                </span>
                <span className="text-white/30" aria-hidden="true">
                  /
                </span>
                <span>EXPLOITABILITY & HARDENING VERIFICATION</span>
                <span className="text-white/30" aria-hidden="true">
                  /
                </span>
                <span>7 DETERMINISTIC ENGINES</span>
              </div>
              <BlurRevealHeading
                text="Empirical Vulnerability, Exploit Proof & Hardening Auditor"
                className="text-2xl sm:text-3xl lg:text-[36px] font-bold leading-[1.15]"
              />
              <p className="text-sm text-[#CBD5E1] leading-relaxed max-w-2xl">
                Universal web application security verification suite. Every
                finding is backed by empirical proof—spanning HTTP/CORS/TLS
                headers, SPA-filtered dotfiles, client JS bundle secret & hidden API
                harvesting, JWT weak-secret cracking, GraphQL & Open-Redirect
                probing, OSV.dev CVEs, and exact SAST lines.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 self-start lg:self-end shrink-0">
            <button
              type="button"
              onClick={() => setIsBackendModalOpen(true)}
              className={`glass-panel flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                backendConnection.mode === 'browser-sandbox'
                  ? 'border-amber-500/40 text-amber-300 hover:border-amber-400'
                  : 'border-emerald-500/35 text-emerald-300 hover:border-emerald-400'
              }`}
              title="Configure live Node.js backend connection or view free fullstack deployment guide"
            >
              {backendConnection.mode === 'browser-sandbox' ? (
                <WifiOff className="h-3.5 w-3.5 text-amber-400" />
              ) : (
                <Wifi className="h-3.5 w-3.5 text-emerald-400" />
              )}
              <span>
                {backendConnection.mode === 'same-origin-node'
                  ? 'Node Engine Active'
                  : backendConnection.mode === 'remote-node'
                  ? 'Remote Node Connected'
                  : 'Browser Sandbox · Connect Backend'}
              </span>
              {backendConnection.latencyMs !== null &&
                backendConnection.mode !== 'browser-sandbox' && (
                  <>
                    <span className="text-white/30" aria-hidden="true">
                      ·
                    </span>
                    <span className="font-mono tabular-nums text-[#E2E8F0]">
                      {backendConnection.latencyMs}ms
                    </span>
                  </>
                )}
            </button>

            {(hasTargetInput || activeReport) && (
              <button
                type="button"
                onClick={handleResetWorkspace}
                className="glass-panel flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium text-[#E2E8F0] hover:border-white/[0.25] hover:text-white transition-colors whitespace-nowrap shrink-0"
              >
                <RotateCcw className="h-3.5 w-3.5 text-[#38BDF8]" />
                <span>Reset Workspace</span>
              </button>
            )}
          </div>
        </section>

        {/* ===================================================================
            TRANSLUCENT GLASSMORPHIC WORKSPACE (TARGET CONTROLLER + TELEMETRY)
           =================================================================== */}
        <section className="glass-workspace grid grid-cols-1 lg:grid-cols-12 rounded-2xl divide-y lg:divide-y-0 lg:divide-x divide-white/[0.10] overflow-hidden">
          {/* Left Panel: Target & Scope Controller (7 Cols) */}
          <div className="lg:col-span-7 p-6 sm:p-8 flex flex-col justify-between space-y-6">
            <div className="space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.09] pb-5">
                <div>
                  <h2 className="font-display text-base font-semibold text-white">
                    Target Configuration
                  </h2>
                  <p className="text-xs text-[#CBD5E1] mt-0.5">
                    Provide a deployed URL, GitHub repository, JWT session
                    token, or source & manifest files.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {activeReport && (
                    <button
                      type="button"
                      onClick={() => executeAudit(config, activeReport)}
                      disabled={isRunning || !hasTargetInput}
                      className="glass-subpanel flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold text-[#38BDF8] hover:border-[#38BDF8]/50 hover:text-white disabled:opacity-40 transition-all whitespace-nowrap shrink-0"
                      title="Re-run verification and compare resolved vs. remaining vulnerabilities"
                    >
                      <RefreshCw
                        className={`h-3.5 w-3.5 ${
                          isRunning ? 'animate-spin' : ''
                        }`}
                      />
                      <span>Re-Verify & Compare Delta</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => executeAudit(config, null)}
                    disabled={isRunning || !hasTargetInput}
                    className="flex items-center gap-2 rounded-lg bg-[#0078D4] px-4 py-2 text-xs font-semibold text-white shadow-[0_8px_24px_-4px_rgba(0,120,212,0.55)] hover:bg-[#1084E0] disabled:bg-white/[0.08] disabled:text-white/35 disabled:shadow-none transition-all whitespace-nowrap shrink-0"
                  >
                    {isRunning ? (
                      <>
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        <span>Verifying Target...</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-3 w-3 fill-current" />
                        <span>Run Security Audit</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Project Name & GitHub Repo Inputs */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-[#E2E8F0] mb-1.5">
                    Project Identifier
                  </label>
                  <input
                    type="text"
                    value={config.projectName}
                    onChange={(e) =>
                      setConfig({ ...config, projectName: e.target.value })
                    }
                    placeholder="e.g., Production API Gateway"
                    className="glass-input w-full rounded-lg px-3.5 py-2 text-sm text-white placeholder-[#64748B]"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-[#E2E8F0] mb-1.5">
                    Public GitHub Repository
                  </label>
                  <div className="relative">
                    <FolderGit2 className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[#94A3B8]" />
                    <input
                      type="text"
                      value={config.githubRepoUrl}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          githubRepoUrl: e.target.value,
                        })
                      }
                      placeholder="https://github.com/tmvoid/repo"
                      className="glass-input w-full rounded-lg pl-9 pr-3.5 py-2 text-sm font-mono text-white placeholder-[#64748B]"
                    />
                  </div>
                </div>
              </div>

              {/* Live Target URL & Optional JWT Session Token Input */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-[#E2E8F0] mb-1.5">
                    Deployed Application or API Endpoint URL
                  </label>
                  <div className="relative">
                    <Globe className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[#94A3B8]" />
                    <input
                      type="text"
                      value={config.targetUrl}
                      onChange={(e) =>
                        setConfig({ ...config, targetUrl: e.target.value })
                      }
                      placeholder="https://your-project.vercel.app"
                      className="glass-input w-full rounded-lg pl-9 pr-3.5 py-2 text-sm font-mono text-white placeholder-[#64748B]"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-[#E2E8F0] mb-1.5">
                    JWT / Bearer Token (Optional or Auto-Captured)
                  </label>
                  <div className="relative">
                    <KeyRound className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[#94A3B8]" />
                    <input
                      type="text"
                      value={config.jwtToken || ''}
                      onChange={(e) =>
                        setConfig({ ...config, jwtToken: e.target.value })
                      }
                      placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                      className="glass-input w-full rounded-lg pl-9 pr-3.5 py-2 text-sm font-mono text-white placeholder-[#64748B]"
                    />
                  </div>
                </div>
              </div>

              {/* Source Code & package.json Manifest Staging */}
              <div className="space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-medium text-[#E2E8F0]">
                    Source Code &{' '}
                    <code className="text-[#38BDF8]">package.json</code>{' '}
                    Manifests ({config.uploadedFiles.length})
                  </span>
                  <div className="flex items-center gap-2">
                    <input
                      ref={fileInputRef}
                      type="file"
                      multiple
                      accept=".json,.ts,.tsx,.js,.jsx,.py,.env,.html,.yml,.yaml"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="glass-subpanel flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-[#E2E8F0] hover:border-white/[0.22] hover:text-white transition-colors whitespace-nowrap shrink-0"
                    >
                      <Upload className="h-3.5 w-3.5 text-[#38BDF8]" />
                      <span>Upload Files</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setIsAddingFile((prev) => !prev)}
                      className="glass-subpanel flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-[#E2E8F0] hover:border-white/[0.22] hover:text-white transition-colors whitespace-nowrap shrink-0"
                    >
                      <FilePlus2 className="h-3.5 w-3.5 text-[#38BDF8]" />
                      <span>Paste Snippet / Manifest</span>
                    </button>
                  </div>
                </div>

                {/* Inline Paste Code / Manifest Form */}
                {isAddingFile && (
                  <form
                    onSubmit={handleAddInlineFile}
                    className="glass-subpanel rounded-lg p-3.5 space-y-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <input
                        type="text"
                        value={newFileName}
                        onChange={(e) => setNewFileName(e.target.value)}
                        placeholder="File path (e.g., package.json or src/auth.ts)"
                        className="glass-input flex-1 rounded px-3 py-1.5 text-xs font-mono text-white placeholder-[#64748B]"
                      />
                      <button
                        type="submit"
                        className="rounded bg-white px-3 py-1.5 text-xs font-semibold text-[#04070E] hover:bg-[#E2E8F0] whitespace-nowrap shrink-0"
                      >
                        Stage File
                      </button>
                    </div>
                    <textarea
                      rows={4}
                      value={newFileContent}
                      onChange={(e) => setNewFileContent(e.target.value)}
                      placeholder="Paste package.json or source file content..."
                      className="glass-input w-full rounded p-2.5 text-xs font-mono text-white placeholder-[#64748B]"
                    />
                  </form>
                )}

                {/* Staged Files List */}
                {config.uploadedFiles.length === 0 ? (
                  <div className="glass-subpanel rounded-lg border-dashed px-4 py-2.5 text-xs text-[#94A3B8]">
                    No local files staged. Upload a{' '}
                    <code className="text-[#E2E8F0]">package.json</code> or
                    source files, or enter a URL / GitHub repository / JWT
                    above.
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="flex flex-wrap gap-2">
                      {config.uploadedFiles.map((file, idx) => (
                        <div
                          key={file.name}
                          className={`glass-subpanel flex items-center gap-2 rounded-md px-2.5 py-1 text-xs font-mono transition-colors ${
                            selectedFileIndex === idx
                              ? 'border-[#38BDF8] bg-[#0078D4]/25 text-white'
                              : 'text-[#CBD5E1]'
                          }`}
                        >
                          <button
                            type="button"
                            onClick={() =>
                              setSelectedFileIndex(
                                selectedFileIndex === idx ? null : idx
                              )
                            }
                            className="flex items-center gap-1.5 text-left hover:text-white"
                          >
                            <FileText className="h-3.5 w-3.5 text-[#38BDF8] shrink-0" />
                            <span>{file.name}</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => handleRemoveFile(file.name)}
                            className="text-[#94A3B8] hover:text-[#EF4444] transition-colors"
                            aria-label={`Remove ${file.name}`}
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        </div>
                      ))}
                    </div>

                    {selectedFileIndex !== null &&
                      config.uploadedFiles[selectedFileIndex] && (
                        <div className="glass-subpanel rounded-lg p-3">
                          <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8] mb-2">
                            <span>
                              {config.uploadedFiles[selectedFileIndex].name}
                            </span>
                            <button
                              type="button"
                              onClick={() => setSelectedFileIndex(null)}
                              className="text-[#38BDF8] hover:underline"
                            >
                              Close Preview
                            </button>
                          </div>
                          <pre className="max-h-40 overflow-y-auto font-mono text-[11px] leading-relaxed text-[#E2E8F0]">
                            <code>
                              {config.uploadedFiles[selectedFileIndex].content}
                            </code>
                          </pre>
                        </div>
                      )}
                  </div>
                )}
              </div>
            </div>

            {/* 7 Authentic Verification & Exploitability Engine Toggles */}
            <div className="pt-5 border-t border-white/[0.09]">
              <div className="text-xs font-medium text-[#CBD5E1] mb-2.5">
                Active Verification & Exploitability Engines (7 Modules)
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {[
                  {
                    key: 'httpHeaders' as const,
                    label: '01. HTTP, CORS & Clickjacking',
                    desc: 'Headers, Origin reflection & iframe PoC',
                  },
                  {
                    key: 'routeProbing' as const,
                    label: '02. Dotfile & Map Prober',
                    desc: 'SPA 404 filter + /.env & .js.map probe',
                  },
                  {
                    key: 'jsBundleAudit' as const,
                    label: '03. JS Bundle & API Harvester',
                    desc: 'Extracts hidden /api/* routes & leaked keys',
                  },
                  {
                    key: 'jwtAudit' as const,
                    label: '04. JWT Weak-Secret Cracker',
                    desc: 'Tests alg:none + HMAC secret dictionary',
                  },
                  {
                    key: 'protocolProbing' as const,
                    label: '05. GraphQL, Verbs & Redirects',
                    desc: '__schema dump, TRACE & Open Redirects',
                  },
                  {
                    key: 'dependencyCve' as const,
                    label: '06. OSV.dev Supply-Chain CVE',
                    desc: 'Live upstream npm CVE/GHSA query',
                  },
                  {
                    key: 'sourceSast' as const,
                    label: '07. Source Code SAST Engine',
                    desc: 'Exact file & line sink/secret scanner',
                  },
                ].map((mod) => {
                  const active = config.modules[mod.key];
                  return (
                    <button
                      key={mod.key}
                      type="button"
                      onClick={() =>
                        setConfig((prev) => ({
                          ...prev,
                          modules: {
                            ...prev.modules,
                            [mod.key]: !prev.modules[mod.key],
                          },
                        }))
                      }
                      className={`glass-subpanel flex items-start justify-between gap-2 rounded-lg p-2.5 text-left transition-all ${
                        active
                          ? 'border-white/[0.18] bg-white/[0.04]'
                          : 'opacity-50 hover:opacity-80'
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-white truncate">
                          {mod.label}
                        </div>
                        <div className="text-[11px] text-[#94A3B8] mt-0.5 truncate">
                          {mod.desc}
                        </div>
                      </div>
                      <span
                        className={`font-mono text-[10px] font-semibold shrink-0 ${
                          active ? 'text-[#38BDF8]' : 'text-[#64748B]'
                        }`}
                      >
                        {active ? 'ON' : 'OFF'}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Panel: Live Audit Telemetry & Posture Breakdown (5 Cols) */}
          <div className="lg:col-span-5 p-6 sm:p-8 bg-black/20 flex flex-col justify-between">
            {errorMessage ? (
              <div className="flex flex-col justify-between h-full space-y-4">
                <div className="space-y-2">
                  <div className="text-xs font-mono text-[#EF4444]">
                    VERIFICATION ERROR
                  </div>
                  <h3 className="font-display text-lg font-semibold text-white">
                    Target Audit Could Not Complete
                  </h3>
                  <p className="text-sm text-[#CBD5E1] leading-relaxed">
                    {errorMessage}
                  </p>
                </div>
                <button
                  onClick={() => setErrorMessage(null)}
                  className="glass-subpanel inline-flex items-center gap-2 self-start rounded-md px-3.5 py-1.5 text-xs font-medium text-white hover:border-white/[0.25]"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  <span>Dismiss</span>
                </button>
              </div>
            ) : activeReport ? (
              <div className="space-y-5">
                <div className="flex items-start justify-between gap-4 border-b border-white/[0.09] pb-4">
                  <div>
                    <div className="flex items-center gap-2 text-xs font-mono text-[#38BDF8]">
                      <span>TELEMETRY SNAPSHOT</span>
                      <span aria-hidden="true">·</span>
                      <span className="tabular-nums">
                        {activeReport.durationMs} ms
                      </span>
                    </div>
                    <h2 className="font-display text-lg font-bold text-white mt-0.5 break-all">
                      {activeReport.projectName}
                    </h2>
                  </div>
                  <div className="text-right font-mono shrink-0">
                    {activeReport.findings.length === 0 ? (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#10B981]">
                        <ShieldCheck className="h-4 w-4" />
                        <span>VERIFIED CLEAN</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#EF4444]">
                        <ShieldAlert className="h-4 w-4" />
                        <span className="tabular-nums">
                          {activeReport.findings.length} ISSUE(S)
                        </span>
                      </span>
                    )}
                  </div>
                </div>

                {/* Contiguous Severity Grid (Tabular Numerals) */}
                <div className="glass-subpanel grid grid-cols-4 divide-x divide-white/[0.08] rounded-xl font-mono tabular-nums">
                  <div className="p-3">
                    <div className="text-[11px] text-[#94A3B8]">Critical</div>
                    <div className="text-2xl font-bold text-[#EF4444] mt-0.5">
                      {severityCounts.critical}
                    </div>
                  </div>
                  <div className="p-3">
                    <div className="text-[11px] text-[#94A3B8]">High</div>
                    <div className="text-2xl font-bold text-[#F97316] mt-0.5">
                      {severityCounts.high}
                    </div>
                  </div>
                  <div className="p-3">
                    <div className="text-[11px] text-[#94A3B8]">Medium</div>
                    <div className="text-2xl font-bold text-[#F59E0B] mt-0.5">
                      {severityCounts.medium}
                    </div>
                  </div>
                  <div className="p-3">
                    <div className="text-[11px] text-[#94A3B8]">Low</div>
                    <div className="text-2xl font-bold text-[#38BDF8] mt-0.5">
                      {severityCounts.low}
                    </div>
                  </div>
                </div>

                {/* 7-Engine Execution Ledger */}
                <div className="space-y-2 font-mono text-xs">
                  <div className="text-xs font-sans font-medium text-[#CBD5E1]">
                    7-Engine Verification Telemetry
                  </div>
                  <div className="glass-subpanel divide-y divide-white/[0.07] rounded-xl">
                    <div className="flex items-center justify-between px-3.5 py-2">
                      <span className="text-[#E2E8F0]">
                        01. HTTP / CORS / Clickjacking
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.http
                          ? `HTTP ${activeReport.rawTelemetry.http.status} (${activeReport.rawTelemetry.http.responseTimeMs} ms)`
                          : 'Skipped'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2">
                      <span className="text-[#E2E8F0]">
                        02. Dotfile & Sourcemap Prober
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.probes
                          ? `${activeReport.rawTelemetry.probes.testedRoutes.length} probed · SPA Filter ${
                              activeReport.rawTelemetry.probes.isSpaCatchAll
                                ? 'On'
                                : 'Std'
                            }`
                          : 'Skipped'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2">
                      <span className="text-[#E2E8F0]">
                        03. JS Bundle & API Harvester
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.bundles
                          ? `${activeReport.rawTelemetry.bundles.scriptsAnalyzed} scripts · ${activeReport.rawTelemetry.bundles.discoveredEndpoints.length} routes`
                          : 'Skipped'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2">
                      <span className="text-[#E2E8F0]">
                        04. JWT Cryptographic Auditor
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.jwt
                          ? `${activeReport.rawTelemetry.jwt.tokensInspected} token(s) inspected`
                          : '0 tokens'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2">
                      <span className="text-[#E2E8F0]">
                        05. GraphQL, Verbs & Redirects
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.protocol
                          ? `${activeReport.rawTelemetry.protocol.allowedMethods.length} verbs · GQL ${
                              activeReport.rawTelemetry.protocol
                                .graphqlIntrospectionOpen
                                ? 'OPEN'
                                : 'Locked'
                            }`
                          : 'Skipped'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2">
                      <span className="text-[#E2E8F0]">
                        06. OSV.dev Supply-Chain CVE
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.dependencies
                          ? `${activeReport.rawTelemetry.dependencies.totalPackages} pkgs (${activeReport.rawTelemetry.dependencies.osvQueryTimeMs} ms)`
                          : 'No package.json'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2">
                      <span className="text-[#E2E8F0]">
                        07. Deterministic Code SAST
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.sast
                          ? `${activeReport.rawTelemetry.sast.totalFiles} files · ${activeReport.rawTelemetry.sast.totalLines} LOC`
                          : 'No code files'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Passed Checks vs Issues Footer */}
                <div className="flex items-center justify-between pt-2 border-t border-white/[0.09] text-xs">
                  <div className="text-[#CBD5E1] font-mono tabular-nums">
                    Passed:{' '}
                    <span className="text-[#10B981] font-semibold">
                      {activeReport.passedChecks.length}
                    </span>{' '}
                    · Issues:{' '}
                    <span className="text-white font-semibold">
                      {activeReport.findings.length}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setActiveLedgerTab('hardening')}
                      className="inline-flex items-center gap-1 text-xs font-medium text-[#10B981] hover:underline whitespace-nowrap shrink-0"
                    >
                      <Wrench className="h-3.5 w-3.5" />
                      <span>Hardening Configs</span>
                    </button>
                    <button
                      onClick={() => setIsExportModalOpen(true)}
                      className="inline-flex items-center gap-1 text-xs font-medium text-[#38BDF8] hover:underline whitespace-nowrap shrink-0"
                    >
                      <span>Export PDF</span>
                      <ArrowUpRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              /* Clean Glassmorphic Standby State Before First Audit Run */
              <div className="flex h-full flex-col justify-between py-2 space-y-6">
                <div className="space-y-1.5 border-b border-white/[0.09] pb-4">
                  <div className="text-xs font-mono text-[#38BDF8]">
                    TELEMETRY STANDBY
                  </div>
                  <h3 className="font-display text-base font-semibold text-white">
                    Awaiting Target Specification
                  </h3>
                  <p className="text-xs text-[#CBD5E1] leading-relaxed">
                    No pre-loaded or synthetic reports are shown. Configure a
                    target on the left and run an audit to populate live
                    verification metrics.
                  </p>
                </div>

                {isRunning ? (
                  <div className="glass-subpanel rounded-xl p-6 space-y-2">
                    <div className="inline-flex items-center gap-2 text-xs font-mono font-semibold text-[#38BDF8]">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>EXECUTING 7-ENGINE VERIFICATION PIPELINE...</span>
                    </div>
                    <p className="text-xs text-[#CBD5E1]">
                      Inspecting HTTP/CORS/TLS, probing SPA-filtered dotfiles,
                      harvesting JS bundles & hidden APIs, auditing JWT secrets,
                      probing GraphQL & redirects, and querying OSV.dev.
                    </p>
                  </div>
                ) : (
                  <div className="glass-subpanel divide-y divide-white/[0.07] rounded-xl font-mono text-xs">
                    <div className="flex items-center justify-between px-4 py-2.5">
                      <span className="text-[#E2E8F0]">
                        01. HTTP, CORS & Clickjacking PoC
                      </span>
                      <span className="text-[#38BDF8]">Ready</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-2.5">
                      <span className="text-[#E2E8F0]">
                        02. Route & Sourcemap Prober
                      </span>
                      <span className="text-[#38BDF8]">SPA Filter Armed</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-2.5">
                      <span className="text-[#E2E8F0]">
                        03. JS Bundle & Hidden API Harvester
                      </span>
                      <span className="text-[#38BDF8]">Ready</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-2.5">
                      <span className="text-[#E2E8F0]">
                        04. JWT Cryptographic Cracker
                      </span>
                      <span className="text-[#38BDF8]">HMAC-SHA256 Armed</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-2.5">
                      <span className="text-[#E2E8F0]">
                        05. GraphQL, Verbs & Open Redirect
                      </span>
                      <span className="text-[#38BDF8]">Ready</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-2.5">
                      <span className="text-[#E2E8F0]">
                        06. OSV.dev + 07. Source SAST
                      </span>
                      <span className="text-[#38BDF8]">Connected</span>
                    </div>
                  </div>
                )}

                <div className="text-[11px] font-mono text-[#94A3B8]">
                  100% Empirical Proof Requirement · Zero False-Positive Guarantee
                </div>
              </div>
            )}
          </div>
        </section>

        {/* ===================================================================
            BEFORE-AND-AFTER REMEDIATION DELTA RE-VERIFIER BANNER
           =================================================================== */}
        {remediationDelta && (
          <section className="glass-panel rounded-2xl border border-[#38BDF8]/40 p-6 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs font-mono text-[#38BDF8]">
                  <GitCompare className="h-4 w-4" />
                  <span>BEFORE & AFTER REMEDIATION VERIFICATION DELTA</span>
                </div>
                <h3 className="font-display text-base font-bold text-white">
                  Remediation Re-Verification Comparison Complete
                </h3>
                <p className="text-xs text-[#CBD5E1]">
                  Comparing baseline snapshot{' '}
                  <span className="text-white font-medium">
                    {remediationDelta.baselineProjectName}
                  </span>{' '}
                  (
                  {new Date(
                    remediationDelta.baselineTimestamp
                  ).toLocaleTimeString()}
                  ) against active verification run.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setRemediationDelta(null)}
                className="glass-subpanel rounded-md p-1.5 text-[#94A3B8] hover:text-white"
                aria-label="Close remediation delta"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="glass-subpanel grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-white/[0.08] rounded-xl font-mono tabular-nums">
              <div className="p-3.5">
                <div className="text-[11px] text-[#94A3B8]">
                  Resolved Vulnerabilities
                </div>
                <div className="text-2xl font-bold text-[#10B981] mt-1">
                  -{remediationDelta.resolvedFindings.length}
                </div>
              </div>
              <div className="p-3.5">
                <div className="text-[11px] text-[#94A3B8]">
                  Remaining Issues
                </div>
                <div className="text-2xl font-bold text-[#F59E0B] mt-1">
                  {remediationDelta.remainingFindings.length}
                </div>
              </div>
              <div className="p-3.5">
                <div className="text-[11px] text-[#94A3B8]">
                  Newly Introduced
                </div>
                <div className="text-2xl font-bold text-[#EF4444] mt-1">
                  +{remediationDelta.newFindings.length}
                </div>
              </div>
              <div className="p-3.5">
                <div className="text-[11px] text-[#94A3B8]">
                  Passed Controls Delta
                </div>
                <div className="text-2xl font-bold text-[#38BDF8] mt-1">
                  {remediationDelta.passedDelta >= 0
                    ? `+${remediationDelta.passedDelta}`
                    : remediationDelta.passedDelta}
                </div>
              </div>
            </div>

            {remediationDelta.resolvedFindings.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-semibold text-[#10B981]">
                  Verified Fixed & Eliminated Vulnerabilities:
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {remediationDelta.resolvedFindings.map((rf) => (
                    <div
                      key={rf.id}
                      className="glass-subpanel flex items-center justify-between gap-2 rounded-lg px-3.5 py-2 text-xs"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <CheckCircle2 className="h-4 w-4 text-[#10B981] shrink-0" />
                        <span className="text-white font-medium truncate">
                          {rf.title}
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-[#10B981] shrink-0">
                        FIXED ({rf.cwe})
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        )}

        {/* ===================================================================
            INTERACTIVE VERIFICATION LEDGER (GLASSMORPHIC)
           =================================================================== */}
        <section id="verification-ledger" className="space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            {/* Primary View Tabs (Functional Segmented Control) */}
            <div className="glass-panel flex flex-wrap items-center gap-1 rounded-xl p-1 self-start">
              <button
                onClick={() => setActiveLedgerTab('findings')}
                className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 tabular-nums ${
                  activeLedgerTab === 'findings'
                    ? 'bg-[#0078D4] text-white'
                    : 'text-[#CBD5E1] hover:text-white'
                }`}
              >
                Verified Vulnerabilities ({activeReport?.findings.length ?? 0})
              </button>
              <button
                onClick={() => setActiveLedgerTab('passed')}
                className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 tabular-nums ${
                  activeLedgerTab === 'passed'
                    ? 'bg-[#0078D4] text-white'
                    : 'text-[#CBD5E1] hover:text-white'
                }`}
              >
                Passed Controls ({activeReport?.passedChecks.length ?? 0})
              </button>
              <button
                onClick={() => setActiveLedgerTab('hardening')}
                className={`flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                  activeLedgerTab === 'hardening'
                    ? 'bg-[#0078D4] text-white'
                    : 'text-[#CBD5E1] hover:text-white'
                }`}
              >
                <Wrench className="h-3.5 w-3.5" />
                <span>Hardening Config Studio</span>
              </button>
              <button
                onClick={() => setActiveLedgerTab('telemetry')}
                className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                  activeLedgerTab === 'telemetry'
                    ? 'bg-[#0078D4] text-white'
                    : 'text-[#CBD5E1] hover:text-white'
                }`}
              >
                Raw Telemetry & Surface Map
              </button>
            </div>

            {/* Search & Interactive Filters */}
            {activeReport &&
              activeLedgerTab !== 'telemetry' &&
              activeLedgerTab !== 'hardening' && (
                <div className="flex flex-wrap items-center gap-2">
                  {activeLedgerTab === 'findings' && (
                    <div className="glass-panel flex items-center gap-1 rounded-lg p-1">
                      {(
                        ['all', 'critical', 'high', 'medium', 'low'] as const
                      ).map((sev) => (
                        <button
                          key={sev}
                          onClick={() => setSeverityFilter(sev)}
                          className={`rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors whitespace-nowrap shrink-0 ${
                            severityFilter === sev
                              ? 'bg-white/[0.15] text-white'
                              : 'text-[#CBD5E1] hover:text-white'
                          }`}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  )}

                  <div className="glass-panel flex flex-wrap items-center gap-1 rounded-lg p-1">
                    {(
                      [
                        'all',
                        'http',
                        'exposure',
                        'bundle',
                        'jwt',
                        'protocol',
                        'dependencies',
                        'sast',
                      ] as const
                    ).map((mod) => (
                      <button
                        key={mod}
                        onClick={() => setModuleFilter(mod)}
                        className={`rounded px-2 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                          moduleFilter === mod
                            ? 'bg-white/[0.15] text-white'
                            : 'text-[#CBD5E1] hover:text-white'
                        }`}
                      >
                        {mod === 'all'
                          ? 'All'
                          : mod === 'http'
                          ? 'HTTP'
                          : mod === 'exposure'
                          ? 'Probes'
                          : mod === 'bundle'
                          ? 'JS Bundle'
                          : mod === 'jwt'
                          ? 'JWT'
                          : mod === 'protocol'
                          ? 'GraphQL/Verbs'
                          : mod === 'dependencies'
                          ? 'OSV CVE'
                          : 'SAST'}
                      </button>
                    ))}
                  </div>

                  <div className="relative">
                    <Search className="pointer-events-none absolute left-3 top-2 h-3.5 w-3.5 text-[#94A3B8]" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Filter by CWE, file, header..."
                      className="glass-input w-48 sm:w-56 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-[#64748B]"
                    />
                  </div>
                </div>
              )}
          </div>

          {/* ZERO-STATE WHEN NO AUDIT HAS BEEN RUN YET */}
          {!activeReport && !isRunning ? (
            <div className="glass-panel rounded-2xl px-6 py-14 text-center space-y-2">
              <div className="text-xs font-mono text-[#38BDF8]">
                LEDGER STANDBY
              </div>
              <h3 className="font-display text-base font-semibold text-white">
                No Audit Executed Yet
              </h3>
              <p className="text-xs text-[#CBD5E1] max-w-md mx-auto leading-relaxed">
                Enter a live URL, GitHub repository, JWT token, or source files
                above and click{' '}
                <span className="text-white font-medium">
                  Run Security Audit
                </span>{' '}
                to populate empirical findings, exploitability proofs, and
                auto-generated hardening configs.
              </p>
            </div>
          ) : (
            <>
              {/* TAB 1: VERIFIED VULNERABILITIES TABLE */}
              {activeLedgerTab === 'findings' && (
                <div className="glass-panel overflow-hidden rounded-2xl">
                  {isRunning ? (
                    <div className="p-6 space-y-3">
                      {[1, 2, 3].map((n) => (
                        <div
                          key={n}
                          className="h-11 w-full animate-pulse rounded-lg bg-white/[0.06]"
                        />
                      ))}
                    </div>
                  ) : filteredFindings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center px-6 py-14 text-center space-y-3">
                      <ShieldCheck className="h-8 w-8 text-[#10B981]" />
                      <div className="space-y-1">
                        <h3 className="font-display text-base font-semibold text-white">
                          {activeReport && activeReport.findings.length === 0
                            ? 'Zero Exploitable Vulnerabilities Verified'
                            : 'No Findings Match Current Filter'}
                        </h3>
                        <p className="text-xs text-[#CBD5E1] max-w-md">
                          {activeReport && activeReport.findings.length === 0
                            ? 'All enabled security checks passed verification. Sentinel AppSec never generates synthetic or bogus findings.'
                            : 'Clear the active filter criteria to view all verified findings.'}
                        </p>
                      </div>
                      {activeReport && activeReport.findings.length === 0 && (
                        <button
                          onClick={() => setActiveLedgerTab('passed')}
                          className="glass-subpanel rounded-lg px-3.5 py-1.5 text-xs font-medium text-white hover:border-white/[0.25]"
                        >
                          View {activeReport.passedChecks.length} Passed
                          Security Controls
                        </button>
                      )}
                    </div>
                  ) : (
                    <div className="divide-y divide-white/[0.07]">
                      {filteredFindings.map((finding) => (
                        <div
                          key={finding.id}
                          onClick={() => setSelectedFinding(finding)}
                          className="group flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-6 py-4 hover:bg-white/[0.04] cursor-pointer transition-colors"
                        >
                          <div className="space-y-1 min-w-0">
                            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                              <span
                                className={`uppercase ${SEVERITY_LABEL_STYLES[finding.severity]}`}
                              >
                                {finding.severity}
                              </span>
                              <span
                                className="text-white/25"
                                aria-hidden="true"
                              >
                                ·
                              </span>
                              <span className="text-[#CBD5E1]">
                                {finding.cwe}
                              </span>
                              <span
                                className="text-white/25"
                                aria-hidden="true"
                              >
                                ·
                              </span>
                              <span className="text-[#CBD5E1]">
                                {finding.owasp}
                              </span>
                              <span
                                className="text-white/25"
                                aria-hidden="true"
                              >
                                ·
                              </span>
                              <span className="text-[#38BDF8]">
                                {MODULE_NAMES[finding.module]}
                              </span>
                              {finding.exploitProof && (
                                <>
                                  <span
                                    className="text-white/25"
                                    aria-hidden="true"
                                  >
                                    ·
                                  </span>
                                  <span className="inline-flex items-center gap-1 text-[#EF4444] font-semibold">
                                    <Flame className="h-3 w-3" />
                                    <span>Interactive Exploit PoC</span>
                                  </span>
                                </>
                              )}
                            </div>

                            <div className="font-display text-sm font-semibold text-white group-hover:text-[#38BDF8] transition-colors">
                              {finding.title}
                            </div>

                            <div className="text-xs text-[#CBD5E1] line-clamp-1">
                              {finding.summary}
                            </div>
                          </div>

                          <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0">
                            <div className="text-left sm:text-right font-mono">
                              <div className="text-xs text-[#E2E8F0] truncate max-w-[240px]">
                                {finding.affectedTarget}
                              </div>
                              <div className="text-[11px] text-[#94A3B8]">
                                Proof: {finding.evidence.type}
                              </div>
                            </div>
                            <div className="flex items-center gap-1 text-xs font-medium text-[#38BDF8] whitespace-nowrap shrink-0">
                              <span>
                                {finding.exploitProof
                                  ? 'Launch PoC & Fix'
                                  : 'Inspect Proof'}
                              </span>
                              <ChevronRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: PASSED SECURITY CONTROLS LEDGER */}
              {activeLedgerTab === 'passed' && (
                <div className="glass-panel overflow-hidden rounded-2xl">
                  {filteredPassedChecks.length === 0 ? (
                    <div className="p-10 text-center text-xs text-[#CBD5E1]">
                      No passed checks match the current filter criteria.
                    </div>
                  ) : (
                    <div className="divide-y divide-white/[0.07]">
                      {filteredPassedChecks.map((check) => (
                        <div
                          key={check.id}
                          className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-6 py-3.5 hover:bg-white/[0.03] transition-colors"
                        >
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-2 text-xs font-mono">
                              <span className="text-[#10B981] font-semibold">
                                PASS
                              </span>
                              <span
                                className="text-white/25"
                                aria-hidden="true"
                              >
                                ·
                              </span>
                              <span className="text-[#CBD5E1]">
                                {MODULE_NAMES[check.module]}
                              </span>
                              <span
                                className="text-white/25"
                                aria-hidden="true"
                              >
                                ·
                              </span>
                              <span className="text-[#38BDF8]">
                                {check.target}
                              </span>
                            </div>
                            <div className="text-sm font-medium text-white">
                              {check.title}
                            </div>
                          </div>
                          <div className="font-mono text-xs text-[#CBD5E1] sm:text-right max-w-md break-all">
                            {check.proofSummary}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: AUTO-GENERATED HARDENING CONFIG STUDIO */}
              {activeLedgerTab === 'hardening' && activeReport && (
                <HardeningStudio report={activeReport} />
              )}

              {/* TAB 4: RAW TELEMETRY, SURFACE MAP, JWT & OSV MATRIX */}
              {activeLedgerTab === 'telemetry' && activeReport && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* 1. Raw HTTP Response Headers */}
                  <SpotlightCard className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display text-sm font-semibold text-white">
                        Captured HTTP Response Headers
                      </h3>
                      {activeReport.rawTelemetry.http && (
                        <span className="font-mono text-xs text-[#38BDF8] tabular-nums">
                          HTTP {activeReport.rawTelemetry.http.status} ·{' '}
                          {activeReport.rawTelemetry.http.responseTimeMs} ms
                        </span>
                      )}
                    </div>
                    {activeReport.rawTelemetry.http ? (
                      <pre className="glass-subpanel max-h-72 overflow-auto rounded-lg p-4 font-mono text-xs leading-relaxed text-[#E2E8F0]">
                        <code>
                          {Object.entries(
                            activeReport.rawTelemetry.http.headers
                          )
                            .map(([k, v]) => `${k}: ${v}`)
                            .join('\n')}
                        </code>
                      </pre>
                    ) : (
                      <p className="text-xs text-[#CBD5E1]">
                        No live URL was audited in this run.
                      </p>
                    )}
                  </SpotlightCard>

                  {/* 2. Sensitive Route Prober Matrix */}
                  <SpotlightCard className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display text-sm font-semibold text-white">
                        Sensitive Route Probe & SPA Filter Log
                      </h3>
                      {activeReport.rawTelemetry.probes && (
                        <span className="font-mono text-xs text-[#CBD5E1]">
                          Baseline 404: HTTP{' '}
                          {activeReport.rawTelemetry.probes.baselineStatus}
                        </span>
                      )}
                    </div>
                    {activeReport.rawTelemetry.probes ? (
                      <div className="glass-subpanel divide-y divide-white/[0.06] rounded-lg font-mono text-xs max-h-72 overflow-y-auto">
                        {activeReport.rawTelemetry.probes.testedRoutes.map(
                          (rt) => (
                            <div
                              key={rt.path}
                              className="flex items-center justify-between gap-3 px-3.5 py-2.5"
                            >
                              <div>
                                <div className="text-white">{rt.path}</div>
                                <div className="text-[11px] text-[#CBD5E1]">
                                  {rt.note}
                                </div>
                              </div>
                              <div className="text-right tabular-nums shrink-0">
                                <div
                                  className={
                                    rt.exposedSignatureVerified
                                      ? 'text-[#EF4444] font-semibold'
                                      : 'text-[#10B981]'
                                  }
                                >
                                  HTTP {rt.status}
                                </div>
                                <div className="text-[11px] text-[#94A3B8]">
                                  {rt.contentLength} B
                                </div>
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    ) : (
                      <p className="text-xs text-[#CBD5E1]">
                        Route probing was not executed in this run.
                      </p>
                    )}
                  </SpotlightCard>

                  {/* 3. Discovered Client JS Bundles & Hidden API Surface Map */}
                  <SpotlightCard className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display text-sm font-semibold text-white">
                        Discovered API Surface Map & JS Bundles
                      </h3>
                      {activeReport.rawTelemetry.bundles && (
                        <span className="font-mono text-xs text-[#38BDF8] tabular-nums">
                          {
                            activeReport.rawTelemetry.bundles
                              .discoveredEndpoints.length
                          }{' '}
                          routes ·{' '}
                          {activeReport.rawTelemetry.bundles.scriptsAnalyzed}{' '}
                          bundles ({activeReport.rawTelemetry.bundles.totalBytes}{' '}
                          B)
                        </span>
                      )}
                    </div>
                    {activeReport.rawTelemetry.bundles ? (
                      <div className="space-y-3 font-mono text-xs">
                        {activeReport.rawTelemetry.bundles.discoveredEndpoints
                          .length > 0 ? (
                          <div className="glass-subpanel rounded-lg p-3 space-y-1.5">
                            <div className="text-[11px] text-[#94A3B8]">
                              Extracted Backend / Internal API Routes:
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                              {activeReport.rawTelemetry.bundles.discoveredEndpoints.map(
                                (ep) => (
                                  <span
                                    key={ep}
                                    className="rounded bg-black/50 px-2 py-0.5 text-[#38BDF8] border border-white/[0.08]"
                                  >
                                    {ep}
                                  </span>
                                )
                              )}
                            </div>
                          </div>
                        ) : (
                          <div className="text-xs text-[#CBD5E1]">
                            No hidden /api/* or /admin/* routes extracted from
                            client scripts.
                          </div>
                        )}

                        {activeReport.rawTelemetry.bundles.bundleNames.length >
                          0 && (
                          <div className="glass-subpanel divide-y divide-white/[0.06] rounded-lg max-h-48 overflow-y-auto">
                            {activeReport.rawTelemetry.bundles.bundleNames.map(
                              (bundleUrl) => (
                                <div
                                  key={bundleUrl}
                                  className="flex items-center justify-between px-3 py-2"
                                >
                                  <span className="text-[#E2E8F0] truncate max-w-md">
                                    {bundleUrl}
                                  </span>
                                  <span className="text-[#10B981] shrink-0">
                                    Inspected
                                  </span>
                                </div>
                              )
                            )}
                          </div>
                        )}
                      </div>
                    ) : (
                      <p className="text-xs text-[#CBD5E1]">
                        JS Bundle harvesting was not executed in this run.
                      </p>
                    )}
                  </SpotlightCard>

                  {/* 4. JWT Cryptographic Audit & GraphQL / Verb Telemetry */}
                  <SpotlightCard className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display text-sm font-semibold text-white">
                        JWT Cryptographic & Protocol Probe Telemetry
                      </h3>
                      {activeReport.rawTelemetry.jwt && (
                        <span className="font-mono text-xs text-[#38BDF8] tabular-nums">
                          {activeReport.rawTelemetry.jwt.tokensInspected} JWT(s)
                          analyzed
                        </span>
                      )}
                    </div>
                    <div className="space-y-3 font-mono text-xs">
                      {activeReport.rawTelemetry.jwt &&
                      activeReport.rawTelemetry.jwt.decodedTokens.length > 0 ? (
                        activeReport.rawTelemetry.jwt.decodedTokens.map(
                          (tok, idx) => (
                            <div
                              key={idx}
                              className="glass-subpanel rounded-lg p-3 space-y-1.5"
                            >
                              <div className="flex items-center justify-between">
                                <span className="text-white font-semibold">
                                  Source: {tok.source} (alg:{' '}
                                  {String(tok.header.alg ?? 'unknown')})
                                </span>
                                <span
                                  className={
                                    tok.weakSecretMatched
                                      ? 'text-[#EF4444] font-bold'
                                      : 'text-[#10B981]'
                                  }
                                >
                                  {tok.weakSecretMatched
                                    ? `CRACKED ("${tok.weakSecretMatched}")`
                                    : 'Secret Uncracked'}
                                </span>
                              </div>
                              <pre className="overflow-x-auto rounded bg-black/40 p-2 text-[11px] text-[#CBD5E1]">
                                <code>
                                  {JSON.stringify(tok.payload, null, 2)}
                                </code>
                              </pre>
                            </div>
                          )
                        )
                      ) : (
                        <div className="glass-subpanel rounded-lg p-3 text-[#94A3B8]">
                          No JWT tokens captured from Set-Cookie or manual input.
                        </div>
                      )}

                      {activeReport.rawTelemetry.protocol && (
                        <div className="glass-subpanel rounded-lg p-3 space-y-1">
                          <div className="text-[#E2E8F0]">
                            Allowed HTTP Verbs:{' '}
                            <span className="text-[#38BDF8]">
                              {activeReport.rawTelemetry.protocol.allowedMethods.join(
                                ', '
                              ) || 'Standard'}
                            </span>
                          </div>
                          <div className="text-[#CBD5E1]">
                            HTTP TRACE Enabled:{' '}
                            <span
                              className={
                                activeReport.rawTelemetry.protocol.traceEnabled
                                  ? 'text-[#EF4444]'
                                  : 'text-[#10B981]'
                              }
                            >
                              {activeReport.rawTelemetry.protocol.traceEnabled
                                ? 'YES (Vulnerable)'
                                : 'No (Blocked)'}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </SpotlightCard>

                  {/* 5. OSV.dev Dependency Scan Table */}
                  <SpotlightCard className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display text-sm font-semibold text-white">
                        OSV.dev Dependency Vulnerability Matrix
                      </h3>
                      {activeReport.rawTelemetry.dependencies && (
                        <span className="font-mono text-xs text-[#CBD5E1] tabular-nums">
                          {activeReport.rawTelemetry.dependencies.totalPackages}{' '}
                          packages queried
                        </span>
                      )}
                    </div>
                    {activeReport.rawTelemetry.dependencies ? (
                      <div className="glass-subpanel divide-y divide-white/[0.06] rounded-lg font-mono text-xs max-h-64 overflow-y-auto">
                        {activeReport.rawTelemetry.dependencies.packages.map(
                          (pkg) => (
                            <div
                              key={`${pkg.name}@${pkg.version}`}
                              className="flex items-center justify-between px-3.5 py-2"
                            >
                              <span className="text-[#E2E8F0]">
                                {pkg.name}@{pkg.version}
                              </span>
                              <span
                                className={
                                  pkg.vulnCount > 0
                                    ? 'text-[#EF4444] font-semibold tabular-nums'
                                    : 'text-[#10B981] tabular-nums'
                                }
                              >
                                {pkg.vulnCount > 0
                                  ? `${pkg.vulnCount} CVE/GHSA (${pkg.advisories.slice(0, 2).join(', ')})`
                                  : '0 CVEs (Clean)'}
                              </span>
                            </div>
                          )
                        )}
                      </div>
                    ) : (
                      <p className="text-xs text-[#CBD5E1]">
                        No package.json file was provided in this audit run.
                      </p>
                    )}
                  </SpotlightCard>

                  {/* 6. Scanned Source Files Manifest */}
                  <SpotlightCard className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display text-sm font-semibold text-white">
                        SAST Analyzed Source File Manifest
                      </h3>
                      {activeReport.rawTelemetry.sast && (
                        <span className="font-mono text-xs text-[#CBD5E1] tabular-nums">
                          {activeReport.rawTelemetry.sast.totalLines} total
                          lines
                        </span>
                      )}
                    </div>
                    {activeReport.rawTelemetry.sast ? (
                      <div className="glass-subpanel divide-y divide-white/[0.06] rounded-lg font-mono text-xs max-h-64 overflow-y-auto">
                        {activeReport.rawTelemetry.sast.files.map((file) => (
                          <div
                            key={file.name}
                            className="flex items-center justify-between px-3.5 py-2"
                          >
                            <span className="text-[#E2E8F0] truncate max-w-xs">
                              {file.name}
                            </span>
                            <span
                              className={
                                file.findingsCount > 0
                                  ? 'text-[#F59E0B] tabular-nums'
                                  : 'text-[#10B981] tabular-nums'
                              }
                            >
                              {file.lines} lines · {file.findingsCount}{' '}
                              match(es)
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-[#CBD5E1]">
                        No source code files were scanned in this audit run.
                      </p>
                    )}
                  </SpotlightCard>
                </div>
              )}
            </>
          )}
        </section>

        {/* ===================================================================
            RECENT CHAPTER AUDITS WITH DELTA COMPARISON (GLASSMORPHIC CARDS)
           =================================================================== */}
        <section id="recent-audits" className="space-y-4 pt-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-base font-semibold text-white">
                Executed Audit History & Delta Comparison
              </h2>
              <p className="text-xs text-[#CBD5E1]">
                Select any historical run or compare a baseline run against your
                active report to verify vulnerability remediation.
              </p>
            </div>
            {auditHistory.length > 0 && (
              <button
                onClick={() => {
                  setAuditHistory([]);
                  localStorage.removeItem(STORAGE_KEY);
                }}
                className="text-xs text-[#CBD5E1] hover:text-white transition-colors"
              >
                Clear History
              </button>
            )}
          </div>

          {auditHistory.length === 0 ? (
            <div className="glass-panel rounded-2xl px-5 py-6 text-xs text-[#94A3B8]">
              No audit runs recorded yet.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {auditHistory.slice(0, 6).map((item) => {
                const isCurrent = activeReport?.id === item.id;
                return (
                  <SpotlightCard
                    key={item.id}
                    onClick={() => setActiveReport(item)}
                    className={`p-4 space-y-2 ${
                      isCurrent ? 'border-[#38BDF8]/60 bg-[#0F1B33]/70' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                      <span>
                        {new Date(item.timestamp).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </span>
                      <span className="tabular-nums">{item.durationMs} ms</span>
                    </div>
                    <div className="font-display text-sm font-semibold text-white truncate">
                      {item.projectName}
                    </div>
                    <div className="flex items-center justify-between gap-2 pt-1">
                      <div className="flex items-center gap-2 text-xs font-mono tabular-nums">
                        <span
                          className={
                            item.findings.length === 0
                              ? 'text-[#10B981]'
                              : 'text-[#EF4444]'
                          }
                        >
                          {item.findings.length} Findings
                        </span>
                        <span className="text-white/25" aria-hidden="true">
                          ·
                        </span>
                        <span className="text-[#10B981]">
                          {item.passedChecks.length} Passed
                        </span>
                      </div>

                      {activeReport && !isCurrent && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setRemediationDelta(
                              computeRemediationDelta(item, activeReport)
                            );
                          }}
                          className="glass-subpanel flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-mono text-[#38BDF8] hover:text-white"
                        >
                          <GitCompare className="h-3 w-3" />
                          <span>Diff vs Active</span>
                        </button>
                      )}
                    </div>
                  </SpotlightCard>
                );
              })}
            </div>
          )}
        </section>

        {/* ===================================================================
            AUTHENTIC 7-ENGINE ZERO-HALLUCINATION METHODOLOGY SECTION
           =================================================================== */}
        <section
          id="methodology"
          className="space-y-5 border-t border-white/[0.10] pt-8"
        >
          <div className="max-w-2xl space-y-1">
            <h2 className="font-display text-base font-semibold text-white">
              7-Engine Zero-Hallucination Verification & Exploitability
              Architecture
            </h2>
            <p className="text-xs text-[#CBD5E1] leading-relaxed">
              Every module relies on live protocol inspection, cryptographic
              verification, and upstream CVE advisory databases rather than
              speculative or unverified heuristics.
            </p>
          </div>

          <div className="glass-workspace grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-white/[0.09] rounded-2xl overflow-hidden">
            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINES 01 & 02</span>
                <Globe className="h-4 w-4 text-[#38BDF8]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                HTTP, CORS, Clickjacking & SPA Route Probing
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Captures live headers, tests untrusted Origin reflection, builds
                a live Clickjacking iframe PoC when framing locks are missing,
                and filters SPA catch-all 404s before flagging /.env or
                .js.map.
              </p>
            </div>

            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINES 03 & 04</span>
                <KeyRound className="h-4 w-4 text-[#10B981]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                JS Bundle Harvester & JWT Secret Cracker
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Fetches live client JavaScript bundles to extract leaked secrets
                and hidden /api/* or /admin/* routes, and tests JWT tokens
                against HMAC-SHA256 weak secrets to forge an Admin PoC token.
              </p>
            </div>

            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINES 05 & 06</span>
                <Network className="h-4 w-4 text-[#38BDF8]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                GraphQL, Verb Tampering, Redirects & OSV.dev
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Probes unauthenticated GraphQL __schema introspection, HTTP
                OPTIONS/TRACE verb tampering, unvalidated Open Redirects, and
                queries api.osv.dev for live npm CVE/GHSA advisories.
              </p>
            </div>

            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINE 07 + STUDIO</span>
                <FileCode2 className="h-4 w-4 text-[#38BDF8]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                Line-Number SAST & Auto-Hardening Studio
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Scans source files line-by-line for dangerous sinks and
                auto-synthesizes drop-in hardening configs for Vercel, Next.js,
                Express, and Nginx with Before-vs-After delta re-verification.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Quiet Glassmorphic Footer */}
      <footer
        className={`relative z-10 mt-12 border-t backdrop-blur-xl px-6 py-6 transition-colors duration-300 ${
          isBright
            ? 'border-slate-900/10 bg-white/70'
            : 'border-white/[0.09] bg-[#04070E]/70'
        }`}
      >
        <div className="mx-auto flex max-w-[1360px] flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#94A3B8]">
          <div className="flex items-center gap-2.5">
            <div className="h-5 w-5 rounded-full overflow-hidden ring-1 ring-cyan-500/30 shrink-0 bg-[#070B14]">
              <img
                src={SENTINEL_LOGO_SRC}
                alt="Sentinel AppSec Logo"
                className="h-full w-full object-cover"
              />
            </div>
            <span className="text-white font-medium">Sentinel AppSec</span>
            <span aria-hidden="true">·</span>
            <span>Universal Application Security & Verification Platform</span>
          </div>
          <div className="flex items-center gap-5">
            <a
              href="#workspace"
              className="hover:text-white transition-colors"
            >
              Audit Console
            </a>
            <button
              type="button"
              onClick={() => setIsBackendModalOpen(true)}
              className="hover:text-white transition-colors flex items-center gap-1"
            >
              <Server className="h-3 w-3 text-[#38BDF8]" />
              <span>Engine & Free Cloud Deploy</span>
            </button>
            <button
              onClick={() => setIsExportModalOpen(true)}
              disabled={!activeReport}
              className="hover:text-white disabled:opacity-40 transition-colors"
            >
              Export PDF Report
            </button>
          </div>
        </div>

        {/* Standalone Ultra-Subtle Signature Row */}
        <div className="mx-auto mt-3 flex max-w-[1360px] justify-end items-center gap-1.5 font-mono text-[10px] tracking-tight text-[#64748B]/60">
          <a
            href="https://www.linkedin.com/in/tanmaysbhardwaj/"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-[#94A3B8] transition-colors"
          >
            tanmay bhardwaj
          </a>
          <span aria-hidden="true" className="select-none opacity-60">·</span>
          <a
            href="https://github.com/tmvoid"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-[#94A3B8] transition-colors"
          >
            github.com/tmvoid
          </a>
        </div>
      </footer>

      {/* Slide-Over Exact Evidence, Interactive Exploit PoC & Remediation Drawer */}
      <EvidenceDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {/* Official Security Audit Report Export Modal */}
      <ReportExportModal
        report={activeReport}
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
      />

      {/* Live Backend Connection & Free Fullstack Cloud Deployment Manager */}
      <BackendConnectionModal
        isOpen={isBackendModalOpen}
        onClose={() => setIsBackendModalOpen(false)}
        connectionState={backendConnection}
        onSaveCustomUrl={handleSaveCustomBackendUrl}
        onPingConnection={pingBackendConnection}
      />
    </div>
  );
}
