export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export type AuditModuleId =
  | 'http'
  | 'exposure'
  | 'dependencies'
  | 'sast'
  | 'bundle'
  | 'jwt'
  | 'protocol';

export interface UploadedCodeFile {
  name: string;
  content: string;
}

export interface AuditTargetConfig {
  projectName: string;
  targetUrl: string;
  githubRepoUrl: string;
  jwtToken?: string;
  uploadedFiles: UploadedCodeFile[];
  modules: {
    httpHeaders: boolean;
    routeProbing: boolean;
    dependencyCve: boolean;
    sourceSast: boolean;
    jsBundleAudit: boolean;
    jwtAudit: boolean;
    protocolProbing: boolean;
  };
}

export interface RemediationSnippet {
  label: string;
  language: string;
  code: string;
}

export interface ExploitProofMetadata {
  type: 'clickjacking' | 'cors' | 'jwt-forge' | 'graphql' | 'open-redirect';
  targetUrl?: string;
  crackedSecret?: string;
  forgedAdminJwt?: string;
  corsOrigin?: string;
  graphqlTypes?: string[];
  redirectLocation?: string;
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
    type:
      | 'http-header'
      | 'route-probe'
      | 'osv-cve'
      | 'source-line'
      | 'js-bundle'
      | 'jwt-crypto'
      | 'protocol-probe';
    rawProof: string;
    reproductionCommand: string;
    verifiedAt: string;
  };
  exploitProof?: ExploitProofMetadata;
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

export interface DecodedJwtRecord {
  source: string;
  rawPreview: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  weakSecretMatched: string | null;
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
  bundles?: {
    scriptsAnalyzed: number;
    totalBytes: number;
    bundleNames: string[];
    discoveredEndpoints: string[];
  };
  jwt?: {
    tokensInspected: number;
    decodedTokens: DecodedJwtRecord[];
  };
  protocol?: {
    allowedMethods: string[];
    traceEnabled: boolean;
    graphqlEndpoint: string | null;
    graphqlIntrospectionOpen: boolean;
    openRedirectParam: string | null;
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

export interface RemediationDelta {
  baselineReportId: string;
  baselineProjectName: string;
  baselineTimestamp: string;
  resolvedFindings: VerifiedFinding[];
  remainingFindings: VerifiedFinding[];
  newFindings: VerifiedFinding[];
  passedDelta: number;
}
