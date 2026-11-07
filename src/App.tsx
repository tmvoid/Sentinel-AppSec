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
  FileDown,
  FilePlus2,
  FileText,
  FolderGit2,
  Globe,
  Loader2,
  PackageCheck,
  Play,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import { EvidenceDrawer } from './components/EvidenceDrawer.tsx';
import MicroSlats from './components/MicroSlats.jsx';
import { ReportExportModal } from './components/ReportExportModal.tsx';
import { BlurRevealHeading, SpotlightCard } from './components/SpotlightCard.tsx';
import type {
  AuditModuleId,
  AuditReport,
  AuditTargetConfig,
  SeverityLevel,
  UploadedCodeFile,
  VerifiedFinding,
} from './types/audit.ts';

const STORAGE_KEY = 'mlsa_kiit_real_audits_v2';
const LEGACY_STORAGE_KEY = 'mlsa_kiit_sentinel_audit_history_v1';

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
};

export default function App() {
  // Clean, Empty Initial State — Zero Pre-Filled Data or Pre-Loaded Reports
  const [config, setConfig] = useState<AuditTargetConfig>({
    projectName: '',
    targetUrl: '',
    githubRepoUrl: '',
    uploadedFiles: [],
    modules: {
      httpHeaders: true,
      routeProbing: true,
      dependencyCve: true,
      sourceSast: true,
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
  }, []);

  // Ledger Filtering & UI State
  const [activeLedgerTab, setActiveLedgerTab] = useState<
    'findings' | 'passed' | 'telemetry'
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
  const [headerLogoError, setHeaderLogoError] = useState(false);
  const [heroLogoError, setHeroLogoError] = useState(false);

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
    async (targetConfig: AuditTargetConfig) => {
      if (
        !targetConfig.targetUrl.trim() &&
        !targetConfig.githubRepoUrl.trim() &&
        targetConfig.uploadedFiles.length === 0
      ) {
        setErrorMessage(
          'Please enter a Live Deployed URL, a Public GitHub Repository URL, or upload/paste project files to audit.'
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
          'MLSA KIIT Project Audit';

        const res = await fetch('/api/audit/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ...targetConfig,
            projectName: inferredName,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || `Audit failed with HTTP ${res.status}`);
        }
        const report = data as AuditReport;
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
    [saveReportToHistory]
  );

  const handleResetWorkspace = () => {
    setConfig({
      projectName: '',
      targetUrl: '',
      githubRepoUrl: '',
      uploadedFiles: [],
      modules: {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: true,
        sourceSast: true,
      },
    });
    setActiveReport(null);
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
    config.uploadedFiles.length > 0;

  return (
    <div className="min-h-screen bg-[#04070E] text-[#F8FAFC] relative">
      {/* =====================================================================
          REACTBITS MICROSLATS INTERACTIVE WEBGL BACKGROUND
          Tuned to MLSA Azure (#0078D4), Ambassador Cyan Glints (#7DD3FC) & Deep Obsidian
         ===================================================================== */}
      <div className="fixed inset-0 z-0 opacity-65">
        <MicroSlats
          preset="tide"
          color="#0078D4"
          glintColor="#7DD3FC"
          backgroundColor="#04070E"
          slatWidth={11}
          slatHeight={26}
          gap={3}
          glint={0.55}
          contrast={1.2}
          interactive={true}
          cursorStrength={0.9}
        />
      </div>
      {/* Measured Radial Atmospheric Scrim for Crisp Glassmorphic Depth & WCAG Legibility */}
      <div
        className="pointer-events-none fixed inset-0 z-0"
        style={{
          background:
            'radial-gradient(ellipse 95% 80% at 50% 35%, rgba(4, 7, 14, 0.35) 0%, rgba(4, 7, 14, 0.78) 100%)',
        }}
      />

      {/* =====================================================================
          STRICT 3-ZONE TOP BAR CONTRACT (GLASSMORPHIC HEADER)
          [Brand Wordmark] — [4 Concise Nav Links] — [1 Primary Action Button]
         ===================================================================== */}
      <header className="sticky top-0 z-30 border-b border-white/[0.10] bg-[#060B16]/65 backdrop-blur-2xl">
        <div className="mx-auto flex max-w-[1360px] items-center justify-between gap-8 px-6 py-3.5">
          {/* Zone 1: Single Brand Lockup */}
          <a
            href="#workspace"
            className="flex items-center gap-3 font-display text-sm font-bold tracking-tight text-white whitespace-nowrap shrink-0"
          >
            {!headerLogoError ? (
              <img
                src="/assets/aistudio/image_950b45df.png"
                alt="MLSA KIIT Emblem"
                referrerPolicy="no-referrer"
                onError={() => setHeaderLogoError(true)}
                className="h-7 w-7 object-contain shrink-0"
              />
            ) : (
              <Shield className="h-5 w-5 text-[#38BDF8] shrink-0" />
            )}
            <span>MLSA KIIT Sentinel</span>
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

          {/* Zone 3: 1 Primary Action */}
          <div className="flex items-center shrink-0">
            <button
              onClick={() => setIsExportModalOpen(true)}
              disabled={!activeReport}
              className="flex items-center gap-1.5 rounded-lg bg-white px-3.5 py-1.5 text-xs font-semibold text-[#04070E] hover:bg-[#E2E8F0] disabled:bg-white/[0.1] disabled:text-white/40 transition-all whitespace-nowrap shrink-0 shadow-sm"
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
            HERO & OFFICIAL MLSA KIIT CHAPTER HEADER
           =================================================================== */}
        <section
          id="workspace"
          className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 pb-2"
        >
          <div className="flex items-start gap-5 max-w-3xl">
            {!heroLogoError ? (
              <div className="glass-panel hidden sm:flex h-16 w-16 items-center justify-center rounded-2xl p-2 shrink-0 mt-0.5">
                <img
                  src="/assets/aistudio/image_950b45df.png"
                  alt="Microsoft Learn Student Ambassador Shield"
                  referrerPolicy="no-referrer"
                  onError={() => setHeroLogoError(true)}
                  className="h-full w-full object-contain"
                />
              </div>
            ) : null}
            <div className="space-y-2.5">
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[#CBD5E1]">
                <span className="text-[#38BDF8] font-semibold">
                  MLSA KIIT CHAPTER
                </span>
                <span className="text-white/30" aria-hidden="true">
                  /
                </span>
                <span>APPLICATION SECURITY VERIFICATION</span>
                <span className="text-white/30" aria-hidden="true">
                  /
                </span>
                <span>ZERO-HALLUCINATION ENGINE</span>
              </div>
              <BlurRevealHeading
                text="Empirical Vulnerability & Security Posture Auditor"
                className="text-2xl sm:text-3xl lg:text-[36px] font-bold leading-[1.15]"
              />
              <p className="text-sm text-[#CBD5E1] leading-relaxed max-w-2xl">
                Built for Microsoft Learn Student Ambassadors at KIIT. Every
                finding is strictly deterministic—verified against live HTTP
                headers, SPA-filtered route signatures, upstream OSV.dev CVE
                records, or exact source code lines.
              </p>
            </div>
          </div>

          {(hasTargetInput || activeReport) && (
            <div className="flex items-center gap-3 self-start lg:self-end shrink-0">
              <button
                type="button"
                onClick={handleResetWorkspace}
                className="glass-panel flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium text-[#E2E8F0] hover:border-white/[0.25] hover:text-white transition-colors whitespace-nowrap shrink-0"
              >
                <RotateCcw className="h-3.5 w-3.5 text-[#38BDF8]" />
                <span>Reset Workspace</span>
              </button>
            </div>
          )}
        </section>

        {/* ===================================================================
            TRANSLUCENT GLASSMORPHIC WORKSPACE (TARGET CONTROLLER + TELEMETRY)
           =================================================================== */}
        <section className="glass-workspace grid grid-cols-1 lg:grid-cols-12 rounded-2xl divide-y lg:divide-y-0 lg:divide-x divide-white/[0.10] overflow-hidden">
          {/* Left Panel: Target & Scope Controller (7 Cols) */}
          <div className="lg:col-span-7 p-6 sm:p-8 flex flex-col justify-between space-y-6">
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.09] pb-5">
                <div>
                  <h2 className="font-display text-base font-semibold text-white">
                    Target Configuration
                  </h2>
                  <p className="text-xs text-[#CBD5E1] mt-0.5">
                    Provide a deployed endpoint URL, a public GitHub repository,
                    or source & manifest files.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => executeAudit(config)}
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
                    placeholder="e.g., KIIT Chapter Portal"
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
                      placeholder="https://github.com/owner/repo"
                      className="glass-input w-full rounded-lg pl-9 pr-3.5 py-2 text-sm font-mono text-white placeholder-[#64748B]"
                    />
                  </div>
                </div>
              </div>

              {/* Live Target URL Input */}
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
                  <div className="glass-subpanel rounded-lg border-dashed px-4 py-3 text-xs text-[#94A3B8]">
                    No local files staged. Upload a{' '}
                    <code className="text-[#E2E8F0]">package.json</code> or
                    source files, or enter a URL / GitHub repository above.
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

            {/* 4 Audit Engine Toggles */}
            <div className="pt-5 border-t border-white/[0.09]">
              <div className="text-xs font-medium text-[#CBD5E1] mb-2.5">
                Verification Modules
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {[
                  {
                    key: 'httpHeaders' as const,
                    label: 'HTTP Headers, CORS & TLS',
                    desc: 'Live header capture & Origin reflection probe',
                  },
                  {
                    key: 'routeProbing' as const,
                    label: 'Sensitive Route & Sourcemap Prober',
                    desc: 'Baseline 404 SPA filter + signature check',
                  },
                  {
                    key: 'dependencyCve' as const,
                    label: 'Dependency CVE Audit (OSV.dev)',
                    desc: 'Upstream npm advisory verification',
                  },
                  {
                    key: 'sourceSast' as const,
                    label: 'Source Code SAST & Secrets',
                    desc: 'Exact file & line matching for keys & sinks',
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
                      className={`glass-subpanel flex items-start justify-between gap-3 rounded-lg p-3 text-left transition-all ${
                        active
                          ? 'border-white/[0.18] bg-white/[0.04]'
                          : 'opacity-50 hover:opacity-80'
                      }`}
                    >
                      <div>
                        <div className="text-xs font-semibold text-white">
                          {mod.label}
                        </div>
                        <div className="text-[11px] text-[#94A3B8] mt-0.5">
                          {mod.desc}
                        </div>
                      </div>
                      <span
                        className={`font-mono text-[11px] font-semibold shrink-0 ${
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
              <div className="space-y-6">
                <div className="flex items-start justify-between gap-4 border-b border-white/[0.09] pb-5">
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
                  <div className="p-3.5">
                    <div className="text-[11px] text-[#94A3B8]">Critical</div>
                    <div className="text-2xl font-bold text-[#EF4444] mt-1">
                      {severityCounts.critical}
                    </div>
                  </div>
                  <div className="p-3.5">
                    <div className="text-[11px] text-[#94A3B8]">High</div>
                    <div className="text-2xl font-bold text-[#F97316] mt-1">
                      {severityCounts.high}
                    </div>
                  </div>
                  <div className="p-3.5">
                    <div className="text-[11px] text-[#94A3B8]">Medium</div>
                    <div className="text-2xl font-bold text-[#F59E0B] mt-1">
                      {severityCounts.medium}
                    </div>
                  </div>
                  <div className="p-3.5">
                    <div className="text-[11px] text-[#94A3B8]">Low</div>
                    <div className="text-2xl font-bold text-[#38BDF8] mt-1">
                      {severityCounts.low}
                    </div>
                  </div>
                </div>

                {/* Module Telemetry Summary Rows */}
                <div className="space-y-2.5 font-mono text-xs">
                  <div className="text-xs font-sans font-medium text-[#CBD5E1]">
                    Engine Execution Ledger
                  </div>
                  <div className="glass-subpanel divide-y divide-white/[0.07] rounded-xl">
                    <div className="flex items-center justify-between px-3.5 py-2.5">
                      <span className="text-[#E2E8F0]">
                        HTTP / CORS / TLS Response
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.http
                          ? `HTTP ${activeReport.rawTelemetry.http.status} (${activeReport.rawTelemetry.http.responseTimeMs} ms)`
                          : 'Not Requested'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2.5">
                      <span className="text-[#E2E8F0]">
                        Sensitive Route & Map Probes
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.probes
                          ? `${activeReport.rawTelemetry.probes.testedRoutes.length} probed · SPA Filter ${
                              activeReport.rawTelemetry.probes.isSpaCatchAll
                                ? 'Active'
                                : 'Standard'
                            }`
                          : 'Not Requested'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2.5">
                      <span className="text-[#E2E8F0]">
                        OSV.dev Dependency CVE Query
                      </span>
                      <span className="text-[#94A3B8] tabular-nums">
                        {activeReport.rawTelemetry.dependencies
                          ? `${activeReport.rawTelemetry.dependencies.totalPackages} pkgs (${activeReport.rawTelemetry.dependencies.osvQueryTimeMs} ms)`
                          : 'No package.json'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-3.5 py-2.5">
                      <span className="text-[#E2E8F0]">
                        Deterministic Code SAST
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
                <div className="flex items-center justify-between pt-3 border-t border-white/[0.09] text-xs">
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
                  <button
                    onClick={() => setIsExportModalOpen(true)}
                    className="inline-flex items-center gap-1 text-xs font-medium text-[#38BDF8] hover:underline whitespace-nowrap shrink-0"
                  >
                    <span>Export Certificate / PDF</span>
                    <ArrowUpRight className="h-3.5 w-3.5" />
                  </button>
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
                      <span>EXECUTING VERIFICATION PIPELINE...</span>
                    </div>
                    <p className="text-xs text-[#CBD5E1]">
                      Inspecting HTTP response headers, testing untrusted CORS
                      origins, probing routes with SPA filtering, and querying
                      OSV.dev.
                    </p>
                  </div>
                ) : (
                  <div className="glass-subpanel divide-y divide-white/[0.07] rounded-xl font-mono text-xs">
                    <div className="flex items-center justify-between px-4 py-3">
                      <span className="text-[#E2E8F0]">01. HTTP & TLS</span>
                      <span className="text-[#38BDF8]">Ready</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3">
                      <span className="text-[#E2E8F0]">
                        02. Route & Map Prober
                      </span>
                      <span className="text-[#38BDF8]">SPA Filter Armed</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3">
                      <span className="text-[#E2E8F0]">
                        03. OSV.dev Advisory Engine
                      </span>
                      <span className="text-[#38BDF8]">Connected</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3">
                      <span className="text-[#E2E8F0]">
                        04. Deterministic SAST
                      </span>
                      <span className="text-[#38BDF8]">11 Signatures</span>
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
            INTERACTIVE VERIFICATION LEDGER (GLASSMORPHIC)
           =================================================================== */}
        <section id="verification-ledger" className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            {/* Primary View Tabs (Functional Segmented Control) */}
            <div className="glass-panel flex items-center gap-1 rounded-xl p-1 self-start">
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
                onClick={() => setActiveLedgerTab('telemetry')}
                className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                  activeLedgerTab === 'telemetry'
                    ? 'bg-[#0078D4] text-white'
                    : 'text-[#CBD5E1] hover:text-white'
                }`}
              >
                Raw Telemetry & Headers
              </button>
            </div>

            {/* Search & Interactive Filters */}
            {activeReport && activeLedgerTab !== 'telemetry' && (
              <div className="flex flex-wrap items-center gap-2">
                {activeLedgerTab === 'findings' && (
                  <div className="glass-panel flex items-center gap-1 rounded-lg p-1">
                    {(['all', 'critical', 'high', 'medium', 'low'] as const).map(
                      (sev) => (
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
                      )
                    )}
                  </div>
                )}

                <div className="glass-panel flex items-center gap-1 rounded-lg p-1">
                  {(
                    ['all', 'http', 'exposure', 'dependencies', 'sast'] as const
                  ).map((mod) => (
                    <button
                      key={mod}
                      onClick={() => setModuleFilter(mod)}
                      className={`rounded px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                        moduleFilter === mod
                          ? 'bg-white/[0.15] text-white'
                          : 'text-[#CBD5E1] hover:text-white'
                      }`}
                    >
                      {mod === 'all'
                        ? 'All Engines'
                        : mod === 'http'
                        ? 'HTTP'
                        : mod === 'exposure'
                        ? 'Probes'
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
                Enter a live URL, GitHub repository, or source files above and
                click <span className="text-white font-medium">Run Security Audit</span> to
                populate empirical findings and passed security controls.
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
                            ? 'All enabled security checks passed verification. MLSA KIIT Sentinel never generates synthetic or bogus findings.'
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
                              <span>Inspect Proof</span>
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

              {/* TAB 3: RAW TELEMETRY, HEADERS, ROUTE PROBES & OSV MATRIX */}
              {activeLedgerTab === 'telemetry' && activeReport && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Raw HTTP Response Headers */}
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

                  {/* Sensitive Route Prober Matrix */}
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
                      <div className="glass-subpanel divide-y divide-white/[0.06] rounded-lg font-mono text-xs">
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

                  {/* OSV.dev Dependency Scan Table */}
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

                  {/* Scanned Source Files Manifest */}
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
            RECENT CHAPTER AUDITS (GLASSMORPHIC CARDS)
           =================================================================== */}
        <section id="recent-audits" className="space-y-4 pt-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-base font-semibold text-white">
                Executed Audit History
              </h2>
              <p className="text-xs text-[#CBD5E1]">
                Snapshots of verification runs executed in this browser session.
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
                    className={`p-4 ${
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
                    <div className="font-display text-sm font-semibold text-white mt-1.5 truncate">
                      {item.projectName}
                    </div>
                    <div className="flex items-center gap-2 text-xs font-mono mt-2 tabular-nums">
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
                  </SpotlightCard>
                );
              })}
            </div>
          )}
        </section>

        {/* ===================================================================
            AUTHENTIC ZERO-HALLUCINATION METHODOLOGY SECTION (GLASSMORPHIC)
           =================================================================== */}
        <section
          id="methodology"
          className="space-y-5 border-t border-white/[0.10] pt-8"
        >
          <div className="max-w-2xl space-y-1">
            <h2 className="font-display text-base font-semibold text-white">
              Zero-Hallucination Verification Architecture
            </h2>
            <p className="text-xs text-[#CBD5E1] leading-relaxed">
              Every module relies on live protocol inspection and upstream
              cryptographic advisory databases rather than speculative AI
              guessing.
            </p>
          </div>

          <div className="glass-workspace grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-white/[0.09] rounded-2xl overflow-hidden">
            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINE 01</span>
                <Globe className="h-4 w-4 text-[#38BDF8]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                Live HTTP & CORS Probe
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Captures unedited HTTP headers, tests active CORS origin
                reflection with an untrusted origin header, and verifies
                HttpOnly/Secure/SameSite cookie flags and SRI hashes.
              </p>
            </div>

            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINE 02</span>
                <CheckCircle2 className="h-4 w-4 text-[#10B981]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                SPA Catch-All Filtering
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Establishes a baseline 404 fingerprint first so React/Vite SPA
                routers returning index.html on /.env or /.git/config are never
                falsely flagged as exposed files.
              </p>
            </div>

            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINE 03</span>
                <PackageCheck className="h-4 w-4 text-[#38BDF8]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                Live OSV.dev CVE Queries
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Queries the official Open Source Vulnerabilities (api.osv.dev)
                database against exact package.json semver versions and hydrates
                upstream CVE & GHSA advisories.
              </p>
            </div>

            <div className="p-5 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[#94A3B8]">
                <span>ENGINE 04</span>
                <Code2 className="h-4 w-4 text-[#38BDF8]" />
              </div>
              <h3 className="font-display text-sm font-semibold text-white">
                Exact Line-Number SAST
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed">
                Scans uploaded or GitHub repository files line-by-line for
                leaked cloud keys, SQL string interpolation, unsanitized DOM
                sinks, and wildcard postMessage calls.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Quiet Glassmorphic Footer */}
      <footer className="relative z-10 mt-12 border-t border-white/[0.09] bg-[#04070E]/70 backdrop-blur-xl px-6 py-6">
        <div className="mx-auto flex max-w-[1360px] flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#94A3B8]">
          <div className="flex items-center gap-2.5">
            <span className="text-white font-medium">MLSA KIIT Sentinel</span>
            <span aria-hidden="true">·</span>
            <span>Microsoft Learn Student Ambassadors at KIIT</span>
          </div>
          <div className="flex items-center gap-5">
            <a
              href="#workspace"
              className="hover:text-white transition-colors"
            >
              Audit Console
            </a>
            <button
              onClick={() => setIsExportModalOpen(true)}
              disabled={!activeReport}
              className="hover:text-white disabled:opacity-40 transition-colors"
            >
              Export PDF Report
            </button>
          </div>
        </div>
      </footer>

      {/* Slide-Over Exact Evidence & Copyable Remediation Drawer */}
      <EvidenceDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {/* Official MLSA KIIT Security Audit Report Export Modal */}
      <ReportExportModal
        report={activeReport}
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
      />
    </div>
  );
}
