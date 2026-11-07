export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export type AuditModuleId = 'http' | 'exposure' | 'dependencies' | 'sast';

export interface UploadedCodeFile {
  name: string;
  content: string;
}

export interface AuditTargetConfig {
  projectName: string;
  targetUrl: string;
  githubRepoUrl: string;
  uploadedFiles: UploadedCodeFile[];
  modules: {
    httpHeaders: boolean;
    routeProbing: boolean;
    dependencyCve: boolean;
    sourceSast: boolean;
  };
}

export interface RemediationSnippet {
  label: string;
  language: string;
  code: string;
}

export interface VerifiedFinding {
  id: string;
  title: string;
  severity: SeverityLevel;
  module: AuditModuleId;
  cwe: string;
  owasp: string;
  affectedTarget: string;
  summary: string;
  impact: string;
  evidence: {
    type: 'http-header' | 'route-probe' | 'osv-cve' | 'source-line';
    rawProof: string;
    reproductionCommand: string;
    verifiedAt: string;
  };
  remediation: {
    summary: string;
    snippets: RemediationSnippet[];
  };
}

export interface PassedCheck {
  id: string;
  title: string;
  module: AuditModuleId;
  target: string;
  proofSummary: string;
}

export interface ProbeRecord {
  path: string;
  url: string;
  status: number;
  contentType: string;
  contentLength: number;
  matchedSpaFallback: boolean;
  exposedSignatureVerified: boolean;
  note: string;
}

export interface DependencyRecord {
  name: string;
  version: string;
  isDev: boolean;
  vulnCount: number;
  advisories: string[];
}

export interface ScannedFileRecord {
  name: string;
  lines: number;
  source: 'upload' | 'github';
  findingsCount: number;
}

export interface RawAuditTelemetry {
  http?: {
    requestedUrl: string;
    finalUrl: string;
    status: number;
    statusText: string;
    responseTimeMs: number;
    isHttps: boolean;
    headers: Record<string, string>;
    corsProbe: {
      testedOrigin: string;
      allowOriginHeader: string | null;
      allowCredentialsHeader: string | null;
    };
    discoveredScripts: string[];
  };
  probes?: {
    baseline404Url: string;
    baselineStatus: number;
    baselineContentType: string;
    isSpaCatchAll: boolean;
    testedRoutes: ProbeRecord[];
  };
  dependencies?: {
    sourceLabel: string;
    totalPackages: number;
    vulnerablePackages: number;
    osvQueryTimeMs: number;
    packages: DependencyRecord[];
  };
  sast?: {
    totalFiles: number;
    totalLines: number;
    files: ScannedFileRecord[];
  };
}

export interface AuditReport {
  id: string;
  projectName: string;
  timestamp: string;
  durationMs: number;
  targetSummary: {
    targetUrl?: string;
    githubRepoUrl?: string;
    filesCount: number;
    enabledModules: AuditModuleId[];
  };
  findings: VerifiedFinding[];
  passedChecks: PassedCheck[];
  rawTelemetry: RawAuditTelemetry;
}
