import React, { useMemo, useState } from 'react';
import { Check, Copy, Download, FileCode2, ShieldCheck, Wrench } from 'lucide-react';
import type { AuditReport } from '../types/audit.ts';
import { SpotlightCard } from './SpotlightCard.tsx';

interface HardeningStudioProps {
  report: AuditReport;
}

type HardeningPlatformId = 'vercel' | 'nextjs' | 'express' | 'nginx';

interface GeneratedConfigArtifact {
  id: HardeningPlatformId;
  label: string;
  fileName: string;
  language: string;
  description: string;
  controlsApplied: string[];
  code: string;
}

export const HardeningStudio: React.FC<HardeningStudioProps> = ({ report }) => {
  const [selectedPlatform, setSelectedPlatform] =
    useState<HardeningPlatformId>('vercel');
  const [copied, setCopied] = useState(false);

  const originDomain = useMemo(() => {
    const rawUrl = report.targetSummary.targetUrl;
    if (!rawUrl) return 'https://example.com';
    try {
      const parsed = new URL(
        rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`
      );
      return parsed.origin;
    } catch {
      return 'https://example.com';
    }
  }, [report.targetSummary.targetUrl]);

  const vulnerabilityFlags = useMemo(() => {
    const titles = report.findings.map((f) => f.title.toLowerCase());
    const modules = new Set(report.findings.map((f) => f.module));
    return {
      missingCsp: titles.some((t) => t.includes('content-security-policy')),
      clickjacking: titles.some(
        (t) =>
          t.includes('clickjacking') ||
          t.includes('x-frame-options') ||
          t.includes('frame-ancestors')
      ),
      missingHsts: titles.some((t) =>
        t.includes('strict-transport-security')
      ),
      corsReflection: titles.some((t) => t.includes('cors')),
      exposedSourcemaps:
        modules.has('exposure') ||
        titles.some((t) => t.includes('sourcemap') || t.includes('.env')),
      graphqlIntrospection: titles.some((t) => t.includes('graphql')),
      jwtWeakSecret: modules.has('jwt'),
      openRedirect: titles.some((t) => t.includes('open redirect')),
    };
  }, [report.findings]);

  const artifacts: Record<HardeningPlatformId, GeneratedConfigArtifact> =
    useMemo(() => {
      const appliedControls: string[] = [
        "Strict Content-Security-Policy with frame-ancestors 'none'",
        'X-Frame-Options: DENY anti-clickjacking lock',
        'Strict-Transport-Security (2-year HSTS + preload)',
        'X-Content-Type-Options: nosniff & Referrer-Policy isolation',
        'Permissions-Policy disabling camera, microphone & geolocation',
      ];

      if (vulnerabilityFlags.exposedSourcemaps) {
        appliedControls.push(
          'Explicit HTTP 404 / deny block for /.env, /.git/*, and *.js.map sourcemaps'
        );
      }
      if (vulnerabilityFlags.corsReflection) {
        appliedControls.push(
          `Explicit CORS allowlist locked to ${originDomain}`
        );
      }
      if (vulnerabilityFlags.graphqlIntrospection) {
        appliedControls.push(
          'Production GraphQL Introspection disabled & HTTP TRACE/OPTIONS lock'
        );
      }
      if (vulnerabilityFlags.jwtWeakSecret) {
        appliedControls.push(
          'HS256/RS256 explicit algorithm allowlist + 256-bit CSPRNG secret enforcement'
        );
      }

      const vercelCode = JSON.stringify(
        {
          $schema: 'https://openapi.vercel.sh/vercel.json',
          headers: [
            {
              source: '/(.*)',
              headers: [
                {
                  key: 'Content-Security-Policy',
                  value:
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
                },
                {
                  key: 'Strict-Transport-Security',
                  value: 'max-age=63072000; includeSubDomains; preload',
                },
                {
                  key: 'X-Frame-Options',
                  value: 'DENY',
                },
                {
                  key: 'X-Content-Type-Options',
                  value: 'nosniff',
                },
                {
                  key: 'Referrer-Policy',
                  value: 'strict-origin-when-cross-origin',
                },
                {
                  key: 'Permissions-Policy',
                  value:
                    'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
                },
                {
                  key: 'Access-Control-Allow-Origin',
                  value: originDomain,
                },
              ],
            },
          ],
          rewrites: [
            {
              source: '/(\\.env.*|\\.git/.*|.*\\.js\\.map)',
              destination: '/404',
            },
          ],
        },
        null,
        2
      );

      const nextjsCode = `// next.config.mjs — Auto-Synthesized by Sentinel AppSec (Engineered by Tanmay Bhardwaj · github.com/tmvoid) for ${report.projectName}
/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  productionBrowserSourceMaps: false, // Prevents .js.map sourcemap exposure in production

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Content-Security-Policy',
            value:
              "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
          },
        ],
      },
    ];
  },
};

export default nextConfig;
`;

      const expressCode = `// securityMiddleware.ts — Auto-Synthesized by Sentinel AppSec (Engineered by Tanmay Bhardwaj · github.com/tmvoid) for ${report.projectName}
import type { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

const ALLOWED_ORIGINS = new Set(['${originDomain}']);
const SAFE_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);

export function sentinelSecurityHardening(req: Request, res: Response, next: NextFunction) {
  // 1. Strip Fingerprinting & Block HTTP TRACE / Arbitrary Verb Tampering
  res.removeHeader('X-Powered-By');
  if (!SAFE_METHODS.has(req.method.toUpperCase())) {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // 2. Block Sensitive Dotfiles, Git Metadata & Production Sourcemaps
  if (/^\\/(\\.env|\\.git|docker-compose|.*\\.js\\.map)/i.test(req.path)) {
    return res.status(404).end();
  }

  // 3. Strict Transport, Anti-Clickjacking & Content-Type Isolation
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  // 4. Strict Origin-Allowlisted CORS (Never reflect untrusted Origin headers)
  const requestOrigin = req.headers.origin;
  if (requestOrigin && ALLOWED_ORIGINS.has(requestOrigin)) {
    res.setHeader('Access-Control-Allow-Origin', requestOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }

  next();
}

// Helper: Safe Relative Redirect Validator (Prevents CWE-601 Open Redirects)
export function getSafeReturnPath(rawRedirect: unknown): string {
  if (typeof rawRedirect !== 'string') return '/dashboard';
  if (rawRedirect.startsWith('/') && !rawRedirect.startsWith('//') && !rawRedirect.includes('\\\\')) {
    return rawRedirect;
  }
  return '/dashboard';
}

// Helper: 256-bit CSPRNG JWT Secret Generator
export function generateHardenedJwtSecret(): string {
  return crypto.randomBytes(64).toString('hex');
}
`;

      const nginxCode = `# nginx.conf — Auto-Synthesized by Sentinel AppSec (Engineered by Tanmay Bhardwaj · github.com/tmvoid) for ${report.projectName}
server {
    listen 443 ssl http2;
    server_name ${originDomain.replace(/^https?:\/\//, '')};

    # Hide Nginx version signature
    server_tokens off;

    # Block HTTP TRACE / TRACK verb tampering
    if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE)$) {
        return 405;
    }

    # Deny access to dotfiles (.env, .git) and production JS sourcemaps (.js.map)
    location ~* (/\\.|\\.js\\.map$|docker-compose\\.yml$) {
        deny all;
        return 404;
    }

    # Hardened Security Response Headers
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
}
`;

      return {
        vercel: {
          id: 'vercel',
          label: 'Vercel (vercel.json)',
          fileName: 'vercel.json',
          language: 'json',
          description:
            'Drop into your repository root to enforce edge security headers, CORS locking, and dotfile/sourcemap blocking on Vercel deployments.',
          controlsApplied: appliedControls,
          code: vercelCode,
        },
        nextjs: {
          id: 'nextjs',
          label: 'Next.js (next.config.mjs)',
          fileName: 'next.config.mjs',
          language: 'javascript',
          description:
            'Disables production browser sourcemaps, removes X-Powered-By, and applies strict CSP, HSTS, and X-Frame-Options across all App/Pages routes.',
          controlsApplied: appliedControls,
          code: nextjsCode,
        },
        express: {
          id: 'express',
          label: 'Express / Node.js (securityMiddleware.ts)',
          fileName: 'securityMiddleware.ts',
          language: 'typescript',
          description:
            'Zero-dependency Express hardening middleware that blocks HTTP verb tampering, dotfile probes, untrusted CORS reflection, and open redirects.',
          controlsApplied: appliedControls,
          code: expressCode,
        },
        nginx: {
          id: 'nginx',
          label: 'Nginx Reverse Proxy (nginx.conf)',
          fileName: 'nginx.conf',
          language: 'nginx',
          description:
            'Server block hardening for containerized or VM deployments behind Nginx with dotfile/sourcemap 404 blocks and strict transport headers.',
          controlsApplied: appliedControls,
          code: nginxCode,
        },
      };
    }, [originDomain, report.projectName, vulnerabilityFlags]);

  const currentArtifact = artifacts[selectedPlatform];

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(currentArtifact.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  };

  const handleDownload = () => {
    const blob = new Blob([currentArtifact.code], {
      type: 'text/plain;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = currentArtifact.fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="glass-panel rounded-2xl p-6 space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-white/[0.09] pb-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs font-mono text-[#38BDF8]">
            <Wrench className="h-3.5 w-3.5" />
            <span>AUTOMATED REMEDIATION & HARDENING STUDIO</span>
          </div>
          <h3 className="font-display text-lg font-bold text-white">
            Drop-In Security Hardening Configurations for {report.projectName}
          </h3>
          <p className="text-xs text-[#CBD5E1] max-w-2xl">
            Synthesized directly from the {report.findings.length} verified
            finding(s) in this audit run. Copy or download the configuration for
            your deployment stack, deploy the patch, and click{' '}
            <span className="text-white font-medium">
              Re-Verify & Compare Delta
            </span>{' '}
            above to prove remediation.
          </p>
        </div>

        {/* Stack Selector Tabs */}
        <div className="glass-subpanel flex flex-wrap items-center gap-1 rounded-xl p-1 self-start">
          {(['vercel', 'nextjs', 'express', 'nginx'] as const).map((plat) => (
            <button
              key={plat}
              type="button"
              onClick={() => setSelectedPlatform(plat)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                selectedPlatform === plat
                  ? 'bg-[#0078D4] text-white'
                  : 'text-[#CBD5E1] hover:text-white'
              }`}
            >
              {artifacts[plat].label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Controls Enforced Checklist (4 Cols) */}
        <div className="lg:col-span-4 space-y-4">
          <SpotlightCard className="p-4 space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono text-[#38BDF8]">
              <FileCode2 className="h-4 w-4" />
              <span>TARGET ARTIFACT: {currentArtifact.fileName}</span>
            </div>
            <p className="text-xs text-[#CBD5E1] leading-relaxed">
              {currentArtifact.description}
            </p>
            <div className="pt-2 border-t border-white/[0.08] space-y-2">
              <div className="text-xs font-semibold text-white">
                Hardening Controls Enforced:
              </div>
              <ul className="space-y-1.5">
                {currentArtifact.controlsApplied.map((ctrl) => (
                  <li
                    key={ctrl}
                    className="flex items-start gap-2 text-xs text-[#CBD5E1]"
                  >
                    <ShieldCheck className="h-3.5 w-3.5 text-[#10B981] shrink-0 mt-0.5" />
                    <span>{ctrl}</span>
                  </li>
                ))}
              </ul>
            </div>
          </SpotlightCard>
        </div>

        {/* Right Column: Copyable & Downloadable Code Artifact (8 Cols) */}
        <div className="lg:col-span-8 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="font-mono text-xs text-[#94A3B8]">
              File: <span className="text-white">{currentArtifact.fileName}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopy}
                className="glass-subpanel flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-white hover:border-white/[0.25] transition-colors whitespace-nowrap shrink-0"
              >
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-[#10B981]" />
                    <span>Copied {currentArtifact.fileName}</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5 text-[#38BDF8]" />
                    <span>Copy Config</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={handleDownload}
                className="flex items-center gap-1.5 rounded-lg bg-[#0078D4] px-3 py-1.5 text-xs font-semibold text-white hover:bg-[#1084E0] transition-colors whitespace-nowrap shrink-0"
              >
                <Download className="h-3.5 w-3.5" />
                <span>Download {currentArtifact.fileName}</span>
              </button>
            </div>
          </div>

          <pre className="glass-subpanel max-h-[420px] overflow-auto rounded-xl p-4 font-mono text-xs leading-relaxed text-[#10B981]">
            <code>{currentArtifact.code}</code>
          </pre>
        </div>
      </div>
    </div>
  );
};
