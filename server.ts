import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import type {
  AuditModuleId,
  AuditReport,
  DependencyRecord,
  PassedCheck,
  ProbeRecord,
  RawAuditTelemetry,
  ScannedFileRecord,
  SeverityLevel,
  UploadedCodeFile,
  VerifiedFinding,
} from './src/types/audit.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '10mb' }));

// ============================================================================
// LIVE SANDBOX BENCHMARK ENDPOINTS (For Authentic Local Verification Testing)
// ============================================================================

// 1. Intentionally Vulnerable Student Hackathon Portal Endpoint
app.get('/api/sandbox/vulnerable-student-portal', (req, res) => {
  const origin = req.headers.origin;
  res.setHeader('X-Powered-By', 'Express 4.17.1 (Node.js v16.14.0)');
  res.setHeader('Server', 'nginx/1.18.0 (Ubuntu)');
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader(
    'Set-Cookie',
    'mlsa_session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo_student_session; Path=/'
  );
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(`<!doctype html>
<html lang="en">
  <head>
    <title>KIIT Fest Registration Portal (Demo Target)</title>
    <script src="https://cdn.example-unverified-analytics.org/tracker-v1.js"></script>
    <script src="/api/sandbox/vulnerable-student-portal/app.bundle.js"></script>
  </head>
  <body>
    <h1>KIIT Student Event Registration Portal</h1>
  </body>
</html>`);
});

app.get('/api/sandbox/vulnerable-student-portal/.env', (_req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.status(200).send(
    `# Accidentally exposed environment configuration\nPORT=3000\nDATABASE_URL="postgres://kiit_admin:SuperSecretPass2026@db.internal:5432/events"\nJWT_SECRET="kiit_hackathon_hardcoded_jwt_secret_key_99812"\nSTRIPE_SECRET_KEY="sk_test_51MlsaKiitDemoKey000000000000000"\n`
  );
});

app.get('/api/sandbox/vulnerable-student-portal/app.bundle.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res
    .status(200)
    .send(
      `console.log("Student Portal Bundle");\n//# sourceMappingURL=/api/sandbox/vulnerable-student-portal/app.bundle.js.map`
    );
});

app.get('/api/sandbox/vulnerable-student-portal/app.bundle.js.map', (_req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.status(200).send(
    JSON.stringify({
      version: 3,
      file: 'app.bundle.js',
      sources: ['src/auth/adminController.ts', 'src/config/keys.ts'],
      sourcesContent: [
        'export const ADMIN_OVERRIDE_TOKEN = "mlsa-internal-bypass-9912";',
      ],
      mappings: 'AAAA,OAAO,MAAM,oBAAoB',
    })
  );
});

// 2. Hardened MLSA KIIT Production Endpoint
app.get('/api/sandbox/hardened-mlsa-portal', (_req, res) => {
  res.removeHeader('X-Powered-By');
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=63072000; includeSubDomains; preload'
  );
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()'
  );
  res.setHeader(
    'Set-Cookie',
    '__Host-mlsa_session=verified_secure_token; Path=/; Secure; HttpOnly; SameSite=Strict'
  );
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(`<!doctype html>
<html lang="en">
  <head>
    <title>MLSA KIIT Hardened Chapter Portal</title>
  </head>
  <body>
    <h1>MLSA KIIT Verified Secure Endpoint</h1>
  </body>
</html>`);
});

// ============================================================================
// HELPER UTILITIES FOR AUTHENTIC SECURITY AUDITING
// ============================================================================

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 8000
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent':
          'MLSA-KIIT-Sentinel/1.0 (Authentic Security Verification Engine)',
        ...(options.headers || {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

function normalizeTargetUrl(rawUrl: string, reqHost: string): string {
  const trimmed = rawUrl.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('/')) {
    return `http://127.0.0.1:3000${trimmed}`;
  }
  if (!/^https?:\/\//i.test(trimmed)) {
    return `https://${trimmed}`;
  }
  // If user enters the current dev server host, route locally for speed & reliability
  try {
    const parsed = new URL(trimmed);
    if (parsed.host === reqHost) {
      return `http://127.0.0.1:3000${parsed.pathname}${parsed.search}`;
    }
  } catch {
    // ignore
  }
  return trimmed;
}

// ============================================================================
// ENGINE 1: HTTP HEADERS, CORS, COOKIE & TLS INSPECTOR
// ============================================================================

async function runHttpHeaderInspection(
  targetUrl: string,
  displayUrl: string
): Promise<{
  findings: VerifiedFinding[];
  passedChecks: PassedCheck[];
  telemetry: NonNullable<RawAuditTelemetry['http']>;
  htmlBody: string;
}> {
  const findings: VerifiedFinding[] = [];
  const passedChecks: PassedCheck[] = [];
  const startMs = Date.now();
  const nowIso = new Date().toISOString();

  const response = await fetchWithTimeout(targetUrl, {
    method: 'GET',
    redirect: 'follow',
  });
  const responseTimeMs = Date.now() - startMs;
  const htmlBody = await response.text();

  const headersMap: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headersMap[key.toLowerCase()] = value;
  });

  // Perform active CORS reflection probe with an untrusted origin
  const probeOrigin = 'https://untrusted-origin.mlsa-kiit.audit';
  let corsAllowOrigin: string | null = null;
  let corsAllowCredentials: string | null = null;
  try {
    const corsRes = await fetchWithTimeout(targetUrl, {
      method: 'GET',
      headers: { Origin: probeOrigin },
    });
    corsAllowOrigin = corsRes.headers.get('access-control-allow-origin');
    corsAllowCredentials = corsRes.headers.get(
      'access-control-allow-credentials'
    );
  } catch {
    // Ignore if secondary probe times out
  }

  const rawHeaderDump = Object.entries(headersMap)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');

  const isHttps =
    displayUrl.startsWith('https://') ||
    headersMap['x-forwarded-proto'] === 'https' ||
    Boolean(headersMap['strict-transport-security']);

  // 1. HTTPS / TLS Check
  if (!isHttps && !displayUrl.includes('localhost') && !displayUrl.startsWith('/')) {
    findings.push({
      id: 'http-plaintext-transport',
      title: 'Unencrypted HTTP Transport (Missing TLS/HTTPS)',
      severity: 'high',
      module: 'http',
      cwe: 'CWE-319',
      owasp: 'A02:2021 Cryptographic Failures',
      affectedTarget: displayUrl,
      summary:
        'The target endpoint was served over unencrypted HTTP without enforcing HTTPS redirection.',
      impact:
        'Network intermediaries on campus Wi-Fi or public networks can intercept session tokens, credentials, and API payloads in transit.',
      evidence: {
        type: 'http-header',
        rawProof: `Target URL: ${displayUrl}\nProtocol: HTTP (Plaintext)\nHTTP/${response.status} ${response.statusText}`,
        reproductionCommand: `curl -I "${displayUrl}"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          'Enforce HTTPS across all routes and redirect port 80 traffic to 443 with a 301 Permanent Redirect.',
        snippets: [
          {
            label: 'Express / Node.js',
            language: 'typescript',
            code: `app.use((req, res, next) => {\n  if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {\n    return res.redirect(301, \`https://\${req.headers.host}\${req.url}\`);\n  }\n  next();\n});`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-https',
      title: 'Encrypted Transport / HTTPS Context Verified',
      module: 'http',
      target: displayUrl,
      proofSummary: `Transport verified on ${displayUrl} (HTTP ${response.status})`,
    });
  }

  // 2. Content-Security-Policy (CSP)
  const cspHeader = headersMap['content-security-policy'];
  const metaCspMatch = htmlBody.match(
    /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]+content=["']([^"']+)["']/i
  );
  const effectiveCsp = cspHeader || (metaCspMatch ? metaCspMatch[1] : null);

  if (!effectiveCsp) {
    findings.push({
      id: 'http-missing-csp',
      title: 'Missing Content-Security-Policy (CSP) Header',
      severity: 'medium',
      module: 'http',
      cwe: 'CWE-693',
      owasp: 'A05:2021 Security Misconfiguration',
      affectedTarget: displayUrl,
      summary:
        'Neither the HTTP response headers nor HTML <meta> tags define a Content-Security-Policy.',
      impact:
        'Without a restrictive CSP, any Cross-Site Scripting (XSS) flaw or rogue third-party script can execute arbitrary JavaScript and exfiltrate user tokens to external domains.',
      evidence: {
        type: 'http-header',
        rawProof: `GET ${displayUrl} -> HTTP ${response.status}\ncontent-security-policy: <ABSENT>\n\nActual Response Headers:\n${rawHeaderDump}`,
        reproductionCommand: `curl -sI "${displayUrl}" | grep -i "content-security-policy"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          'Configure a strict Content-Security-Policy header restricting script-src, object-src, and frame-ancestors.',
        snippets: [
          {
            label: 'Express (Helmet)',
            language: 'typescript',
            code: `import helmet from 'helmet';\n\napp.use(\n  helmet.contentSecurityPolicy({\n    directives: {\n      defaultSrc: ["'self'"],\n      scriptSrc: ["'self'"],\n      styleSrc: ["'self'", "'unsafe-inline'"],\n      imgSrc: ["'self'", "data:", "https:"],\n      objectSrc: ["'none'"],\n      frameAncestors: ["'none'"],\n    },\n  })\n);`,
          },
          {
            label: 'Vercel / vercel.json',
            language: 'json',
            code: `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n        {\n          "key": "Content-Security-Policy",\n          "value": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"\n        }\n      ]\n    }\n  ]\n}`,
          },
        ],
      },
    });
  } else if (
    effectiveCsp.includes("'unsafe-eval'") ||
    (effectiveCsp.includes("'unsafe-inline'") &&
      !effectiveCsp.includes('nonce-') &&
      !effectiveCsp.includes('sha256-'))
  ) {
    findings.push({
      id: 'http-permissive-csp',
      title: 'Permissive Content-Security-Policy Allows Unsafe Script Execution',
      severity: 'medium',
      module: 'http',
      cwe: 'CWE-693',
      owasp: 'A05:2021 Security Misconfiguration',
      affectedTarget: displayUrl,
      summary:
        "The Content-Security-Policy header is present but contains 'unsafe-inline' or 'unsafe-eval' without cryptographic nonces or hashes.",
      impact:
        'Attackers can bypass CSP protections to run injected inline scripts or eval()-based payloads.',
      evidence: {
        type: 'http-header',
        rawProof: `content-security-policy: ${effectiveCsp}`,
        reproductionCommand: `curl -sI "${displayUrl}" | grep -i "content-security-policy"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          "Remove 'unsafe-eval' and 'unsafe-inline' from script-src or pair inline scripts with per-request cryptographic nonces.",
        snippets: [
          {
            label: 'Hardened CSP Header',
            language: 'http',
            code: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-csp',
      title: 'Content-Security-Policy (CSP) Enforced',
      module: 'http',
      target: displayUrl,
      proofSummary: `content-security-policy: ${effectiveCsp}`,
    });
  }

  // 3. Strict-Transport-Security (HSTS)
  const hsts = headersMap['strict-transport-security'];
  if (!hsts) {
    findings.push({
      id: 'http-missing-hsts',
      title: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
      severity: 'low',
      module: 'http',
      cwe: 'CWE-523',
      owasp: 'A05:2021 Security Misconfiguration',
      affectedTarget: displayUrl,
      summary:
        'The response does not include a Strict-Transport-Security header to pin HTTPS connections in browsers.',
      impact:
        'First-time visitors or users clicking http:// links are vulnerable to SSL-stripping downgrade attacks.',
      evidence: {
        type: 'http-header',
        rawProof: `GET ${displayUrl} -> HTTP ${response.status}\nstrict-transport-security: <ABSENT>\n\nActual Response Headers:\n${rawHeaderDump}`,
        reproductionCommand: `curl -sI "${displayUrl}" | grep -i "strict-transport-security"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          'Add Strict-Transport-Security with a max-age of at least 1 year (31536000 seconds) and includeSubDomains.',
        snippets: [
          {
            label: 'Express / Next.js Header',
            language: 'typescript',
            code: `res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-hsts',
      title: 'HTTP Strict-Transport-Security (HSTS) Active',
      module: 'http',
      target: displayUrl,
      proofSummary: `strict-transport-security: ${hsts}`,
    });
  }

  // 4. Clickjacking Protection (X-Frame-Options or CSP frame-ancestors)
  const xfo = headersMap['x-frame-options'];
  const hasFrameAncestors =
    effectiveCsp && effectiveCsp.toLowerCase().includes('frame-ancestors');
  if (!xfo && !hasFrameAncestors) {
    findings.push({
      id: 'http-missing-frame-protection',
      title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
      severity: 'medium',
      module: 'http',
      cwe: 'CWE-1021',
      owasp: 'A05:2021 Security Misconfiguration',
      affectedTarget: displayUrl,
      summary:
        'Neither X-Frame-Options nor CSP frame-ancestors is present on the HTTP response.',
      impact:
        'Malicious external sites can embed this application inside an invisible <iframe> and trick students into clicking authenticated buttons (UI Redressing / Clickjacking).',
      evidence: {
        type: 'http-header',
        rawProof: `x-frame-options: <ABSENT>\ncontent-security-policy frame-ancestors: <ABSENT>\n\nActual Response Headers:\n${rawHeaderDump}`,
        reproductionCommand: `curl -sI "${displayUrl}" | grep -iE "x-frame-options|content-security-policy"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          "Set X-Frame-Options to DENY or SAMEORIGIN and add frame-ancestors 'none' to your Content-Security-Policy.",
        snippets: [
          {
            label: 'Express Middleware',
            language: 'typescript',
            code: `res.setHeader('X-Frame-Options', 'DENY');`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-clickjacking',
      title: 'Anti-Clickjacking Frame Restriction Verified',
      module: 'http',
      target: displayUrl,
      proofSummary: xfo
        ? `x-frame-options: ${xfo}`
        : `CSP frame-ancestors enforced`,
    });
  }

  // 5. X-Content-Type-Options
  const xcto = headersMap['x-content-type-options'];
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    findings.push({
      id: 'http-missing-nosniff',
      title: 'Missing X-Content-Type-Options: nosniff Header',
      severity: 'low',
      module: 'http',
      cwe: 'CWE-16',
      owasp: 'A05:2021 Security Misconfiguration',
      affectedTarget: displayUrl,
      summary:
        'The server does not send X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff response bodies.',
      impact:
        'Browsers may interpret user-uploaded text or image files as executable HTML or JavaScript.',
      evidence: {
        type: 'http-header',
        rawProof: `x-content-type-options: ${xcto || '<ABSENT>'}\n\nActual Response Headers:\n${rawHeaderDump}`,
        reproductionCommand: `curl -sI "${displayUrl}" | grep -i "x-content-type-options"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary: 'Send X-Content-Type-Options: nosniff on all HTTP responses.',
        snippets: [
          {
            label: 'Express / Node.js',
            language: 'typescript',
            code: `res.setHeader('X-Content-Type-Options', 'nosniff');`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-nosniff',
      title: 'MIME-Sniffing Protection (nosniff) Enforced',
      module: 'http',
      target: displayUrl,
      proofSummary: `x-content-type-options: ${xcto}`,
    });
  }

  // 6. CORS Misconfiguration Check
  if (
    corsAllowOrigin === probeOrigin &&
    corsAllowCredentials?.toLowerCase() === 'true'
  ) {
    findings.push({
      id: 'http-cors-origin-reflection',
      title: 'Critical CORS Arbitrary Origin Reflection with Credentials',
      severity: 'critical',
      module: 'http',
      cwe: 'CWE-942',
      owasp: 'A01:2021 Broken Access Control',
      affectedTarget: displayUrl,
      summary: `When probed with Origin: ${probeOrigin}, the server reflected the untrusted origin in Access-Control-Allow-Origin alongside Access-Control-Allow-Credentials: true.`,
      impact:
        'Any third-party website visited by a logged-in user can make authenticated cross-origin requests and read private account data or session responses.',
      evidence: {
        type: 'http-header',
        rawProof: `Request Header:\nOrigin: ${probeOrigin}\n\nVerified Server Response Headers:\nAccess-Control-Allow-Origin: ${corsAllowOrigin}\nAccess-Control-Allow-Credentials: ${corsAllowCredentials}`,
        reproductionCommand: `curl -sI -H "Origin: ${probeOrigin}" "${displayUrl}" | grep -i "access-control-"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          'Validate the request Origin against an explicit allowlist of trusted MLSA KIIT domains instead of reflecting arbitrary origins.',
        snippets: [
          {
            label: 'Express CORS Allowlist',
            language: 'typescript',
            code: `const ALLOWED_ORIGINS = new Set(['https://mlsakiit.tech', 'http://localhost:3000']);\n\napp.use((req, res, next) => {\n  const origin = req.headers.origin;\n  if (origin && ALLOWED_ORIGINS.has(origin)) {\n    res.setHeader('Access-Control-Allow-Origin', origin);\n    res.setHeader('Access-Control-Allow-Credentials', 'true');\n  }\n  next();\n});`,
          },
        ],
      },
    });
  } else if (corsAllowOrigin === '*') {
    findings.push({
      id: 'http-cors-wildcard',
      title: 'Permissive Wildcard CORS Policy (Access-Control-Allow-Origin: *)',
      severity: 'low',
      module: 'http',
      cwe: 'CWE-942',
      owasp: 'A05:2021 Security Misconfiguration',
      affectedTarget: displayUrl,
      summary:
        'The endpoint returns Access-Control-Allow-Origin: *, permitting any external origin to read public response data via fetch/XHR.',
      impact:
        'If applied globally to authenticated or internal API routes, untrusted origins may read sensitive application responses.',
      evidence: {
        type: 'http-header',
        rawProof: `Access-Control-Allow-Origin: ${corsAllowOrigin}`,
        reproductionCommand: `curl -sI -H "Origin: ${probeOrigin}" "${displayUrl}" | grep -i "access-control-allow-origin"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          'Restrict Access-Control-Allow-Origin to explicit trusted origins unless the endpoint is intentionally a public read-only API.',
        snippets: [
          {
            label: 'Express CORS Config',
            language: 'typescript',
            code: `res.setHeader('Access-Control-Allow-Origin', 'https://mlsakiit.tech');`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-cors',
      title: 'Cross-Origin Resource Sharing (CORS) Origin Isolation Verified',
      module: 'http',
      target: displayUrl,
      proofSummary: `Untrusted origin (${probeOrigin}) was not reflected (${corsAllowOrigin || 'no ACAO header'})`,
    });
  }

  // 7. Technology Version Disclosure (X-Powered-By / Server version numbers)
  const poweredBy = headersMap['x-powered-by'];
  const serverHeader = headersMap['server'];
  const hasServerVersion = serverHeader && /\/[0-9]+\.[0-9]+/.test(serverHeader);

  if (poweredBy || hasServerVersion) {
    findings.push({
      id: 'http-tech-fingerprinting',
      title: 'Server & Framework Technology Stack Fingerprint Disclosure',
      severity: 'low',
      module: 'http',
      cwe: 'CWE-200',
      owasp: 'A05:2021 Security Misconfiguration',
      affectedTarget: displayUrl,
      summary:
        'The HTTP response discloses explicit runtime or web server version metadata via X-Powered-By or versioned Server headers.',
      impact:
        'Allows automated scanners and attackers to fingerprint exact framework versions and target known version-specific CVEs.',
      evidence: {
        type: 'http-header',
        rawProof: [
          poweredBy ? `x-powered-by: ${poweredBy}` : null,
          serverHeader ? `server: ${serverHeader}` : null,
        ]
          .filter(Boolean)
          .join('\n'),
        reproductionCommand: `curl -sI "${displayUrl}" | grep -iE "x-powered-by|server:"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          'Disable the X-Powered-By header in Express/Next.js and set server_tokens off in Nginx.',
        snippets: [
          {
            label: 'Express.js',
            language: 'typescript',
            code: `app.disable('x-powered-by');`,
          },
          {
            label: 'Next.js (next.config.mjs)',
            language: 'javascript',
            code: `export default {\n  poweredByHeader: false,\n};`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-no-powered-by',
      title: 'Framework Fingerprinting Headers (X-Powered-By) Suppressed',
      module: 'http',
      target: displayUrl,
      proofSummary: 'x-powered-by header absent and server version masked',
    });
  }

  // 8. Cookie Hardening Inspection (Set-Cookie)
  const setCookieHeader = headersMap['set-cookie'];
  if (setCookieHeader) {
    const lowerCookie = setCookieHeader.toLowerCase();
    const missingFlags: string[] = [];
    if (!lowerCookie.includes('httponly')) missingFlags.push('HttpOnly');
    if (!lowerCookie.includes('secure')) missingFlags.push('Secure');
    if (!lowerCookie.includes('samesite')) missingFlags.push('SameSite');

    if (missingFlags.length > 0) {
      findings.push({
        id: 'http-insecure-cookie-flags',
        title: `Session Cookie Missing Hardening Attributes (${missingFlags.join(', ')})`,
        severity: missingFlags.includes('HttpOnly') ? 'high' : 'medium',
        module: 'http',
        cwe: 'CWE-614',
        owasp: 'A07:2021 Identification and Authentication Failures',
        affectedTarget: displayUrl,
        summary: `The Set-Cookie header issued by ${displayUrl} omits the ${missingFlags.join(', ')} security flag(s).`,
        impact:
          'Cookies lacking HttpOnly can be stolen via document.cookie during XSS; missing Secure allows transmission over plaintext HTTP; missing SameSite exposes endpoints to CSRF.',
        evidence: {
          type: 'http-header',
          rawProof: `set-cookie: ${setCookieHeader}\nMissing Attributes: ${missingFlags.join(', ')}`,
          reproductionCommand: `curl -sI "${displayUrl}" | grep -i "set-cookie"`,
          verifiedAt: nowIso,
        },
        remediation: {
          summary:
            'Always set HttpOnly, Secure, and SameSite=Strict (or Lax) on session and authentication cookies.',
          snippets: [
            {
              label: 'Express Cookie Options',
              language: 'typescript',
              code: `res.cookie('session_id', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  path: '/',\n  maxAge: 3600000,\n});`,
            },
          ],
        },
      });
    } else {
      passedChecks.push({
        id: 'pass-cookie-flags',
        title: 'Cookie Security Attributes (HttpOnly, Secure, SameSite) Verified',
        module: 'http',
        target: displayUrl,
        proofSummary: `set-cookie: ${setCookieHeader}`,
      });
    }
  }

  // 9. Subresource Integrity (SRI) on External Scripts
  const scriptTags = Array.from(
    htmlBody.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)
  );
  const discoveredScripts = scriptTags.map((m) => m[1]);
  const externalScriptsWithoutSri: string[] = [];

  for (const match of scriptTags) {
    const fullTag = match[0];
    const src = match[1];
    if (/^https?:\/\//i.test(src)) {
      try {
        const scriptOrigin = new URL(src).host;
        const targetOrigin = new URL(
          displayUrl.startsWith('http') ? displayUrl : `https://localhost`
        ).host;
        if (
          scriptOrigin !== targetOrigin &&
          !/\bintegrity=["']sha(256|384|512)-/i.test(fullTag)
        ) {
          externalScriptsWithoutSri.push(fullTag);
        }
      } catch {
        // ignore URL parse error
      }
    }
  }

  if (externalScriptsWithoutSri.length > 0) {
    findings.push({
      id: 'http-missing-sri',
      title: 'External Third-Party Script Loaded Without Subresource Integrity (SRI)',
      severity: 'medium',
      module: 'http',
      cwe: 'CWE-829',
      owasp: 'A08:2021 Software and Data Integrity Failures',
      affectedTarget: displayUrl,
      summary: `Found ${externalScriptsWithoutSri.length} external <script> tag(s) loaded from third-party origins without a cryptographic integrity="sha384-..." attribute.`,
      impact:
        'If the external CDN or third-party host is compromised, malicious JavaScript will execute inside your application with full DOM access.',
      evidence: {
        type: 'http-header',
        rawProof: externalScriptsWithoutSri.join('\n'),
        reproductionCommand: `curl -sL "${displayUrl}" | grep -i "<script"`,
        verifiedAt: nowIso,
      },
      remediation: {
        summary:
          'Add integrity="sha384-..." and crossorigin="anonymous" attributes to all third-party CDN scripts.',
        snippets: [
          {
            label: 'HTML Script Tag with SRI',
            language: 'html',
            code: `<script\n  src="https://cdn.example.com/library.min.js"\n  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"\n  crossorigin="anonymous"\n></script>`,
          },
        ],
      },
    });
  } else {
    passedChecks.push({
      id: 'pass-sri',
      title: 'Subresource Integrity (SRI) / Local Script Origin Verified',
      module: 'http',
      target: displayUrl,
      proofSummary: `Inspected ${discoveredScripts.length} script tag(s); 0 unverified external scripts found`,
    });
  }

  return {
    findings,
    passedChecks,
    htmlBody,
    telemetry: {
      requestedUrl: displayUrl,
      finalUrl: response.url,
      status: response.status,
      statusText: response.statusText,
      responseTimeMs,
      isHttps,
      headers: headersMap,
      corsProbe: {
        testedOrigin: probeOrigin,
        allowOriginHeader: corsAllowOrigin,
        allowCredentialsHeader: corsAllowCredentials,
      },
      discoveredScripts,
    },
  };
}

// ============================================================================
// ENGINE 2: EXPOSED ENV, SOURCEMAP & SENSITIVE ROUTE PROBER (WITH SPA FILTER)
// ============================================================================

async function runSensitiveRouteProbing(
  targetUrl: string,
  displayUrl: string,
  discoveredScripts: string[]
): Promise<{
  findings: VerifiedFinding[];
  passedChecks: PassedCheck[];
  telemetry: NonNullable<RawAuditTelemetry['probes']>;
}> {
  const findings: VerifiedFinding[] = [];
  const passedChecks: PassedCheck[] = [];
  const nowIso = new Date().toISOString();

  const baseObj = new URL(targetUrl);
  const basePath = baseObj.pathname.replace(/\/$/, '');
  const originAndBase = `${baseObj.origin}${basePath}`;
  const displayOriginAndBase = displayUrl.replace(/\/$/, '');

  // Step 1: Establish Baseline 404 / SPA Catch-All Fingerprint
  const randomSlug = `mlsa-kiit-404-check-${Date.now()}`;
  const baselineUrl = `${originAndBase}/${randomSlug}`;
  let baselineStatus = 404;
  let baselineContentType = '';
  let baselineBodySample = '';
  let isSpaCatchAll = false;

  try {
    const baseRes = await fetchWithTimeout(baselineUrl, { method: 'GET' }, 5000);
    baselineStatus = baseRes.status;
    baselineContentType = (baseRes.headers.get('content-type') || '').toLowerCase();
    const text = await baseRes.text();
    baselineBodySample = text.slice(0, 300).trim();
    if (
      baselineStatus === 200 &&
      (baselineContentType.includes('text/html') ||
        /<!doctype html|<html/i.test(baselineBodySample))
    ) {
      isSpaCatchAll = true;
    }
  } catch {
    // ignore baseline error
  }

  const probeTargets: Array<{
    path: string;
    title: string;
    severity: SeverityLevel;
    cwe: string;
    owasp: string;
    summary: string;
    impact: string;
    remediation: string;
    verifySignature: (body: string, contentType: string) => boolean;
  }> = [
    {
      path: '/.env',
      title: 'Publicly Exposed Environment Configuration File (/.env)',
      severity: 'critical',
      cwe: 'CWE-538',
      owasp: 'A05:2021 Security Misconfiguration',
      summary:
        'The server returned a verified plaintext .env file containing KEY=VALUE environment variables over HTTP 200.',
      impact:
        'Exposes database connection strings, API keys, JWT signing secrets, and third-party credentials directly to anyone on the internet.',
      remediation:
        'Block access to dotfiles (/.env, /.git) in your web server or static file middleware and rotate all leaked credentials immediately.',
      verifySignature: (body, ct) => {
        if (ct.includes('text/html') || /<!doctype html|<html/i.test(body)) {
          return false;
        }
        return /^[A-Z][A-Z0-9_]{2,}\s*=\s*.+/m.test(body);
      },
    },
    {
      path: '/.git/config',
      title: 'Publicly Exposed Git Repository Metadata (/.git/config)',
      severity: 'high',
      cwe: 'CWE-538',
      owasp: 'A05:2021 Security Misconfiguration',
      summary:
        'The /.git/config file is publicly accessible and contains valid Git configuration sections.',
      impact:
        'Attackers can reconstruct the entire source code repository, commit history, and historical secrets using git-dumper tools.',
      remediation:
        'Configure Nginx/Apache/Express static hosting to deny all requests matching ^/\\.',
      verifySignature: (body, ct) => {
        if (ct.includes('text/html') || /<!doctype html|<html/i.test(body)) {
          return false;
        }
        return /\[(core|remote|branch)\b/i.test(body);
      },
    },
  ];

  // Check discovered script sourcemaps (.map)
  for (const scriptSrc of discoveredScripts.slice(0, 3)) {
    if (scriptSrc.endsWith('.js')) {
      const mapPath = scriptSrc.startsWith('/')
        ? `${scriptSrc}.map`
        : `/${scriptSrc}.map`;
      probeTargets.push({
        path: mapPath,
        title: `Publicly Exposed JavaScript Source Map (${mapPath})`,
        severity: 'low',
        cwe: 'CWE-540',
        owasp: 'A05:2021 Security Misconfiguration',
        summary: `Production JavaScript sourcemap ${mapPath} is publicly accessible and contains original unminified source mappings.`,
        impact:
          'Allows anyone to reconstruct original TypeScript/React source files, internal comments, and hidden client routes.',
        remediation:
          'Disable production sourcemaps in vite.config.ts (build.sourcemap: false) or restrict .map files to internal error-tracking uploads.',
        verifySignature: (body, _ct) => {
          if (/<!doctype html|<html/i.test(body)) return false;
          try {
            const parsed = JSON.parse(body);
            return (
              parsed &&
              parsed.version === 3 &&
              (typeof parsed.mappings === 'string' ||
                Array.isArray(parsed.sources))
            );
          } catch {
            return false;
          }
        },
      });
    }
  }

  const testedRoutes: ProbeRecord[] = [];

  for (const probe of probeTargets) {
    const fullProbeUrl = probe.path.startsWith(basePath) && basePath !== ''
      ? `${baseObj.origin}${probe.path}`
      : `${originAndBase}${probe.path}`;
    const displayProbeUrl =
      probe.path.startsWith(basePath) && basePath !== ''
        ? `${displayUrl.split(basePath)[0]}${probe.path}`
        : `${displayOriginAndBase}${probe.path}`;

    try {
      const res = await fetchWithTimeout(fullProbeUrl, { method: 'GET' }, 5000);
      const contentType = (res.headers.get('content-type') || '').toLowerCase();
      const bodyText = await res.text();
      const sample = bodyText.slice(0, 300).trim();

      const matchedSpa =
        res.status === 200 &&
        isSpaCatchAll &&
        (contentType.includes('text/html') ||
          sample === baselineBodySample ||
          /<!doctype html|<html/i.test(sample));

      const signatureVerified =
        res.status === 200 &&
        !matchedSpa &&
        probe.verifySignature(bodyText, contentType);

      testedRoutes.push({
        path: probe.path,
        url: displayProbeUrl,
        status: res.status,
        contentType: contentType || 'unknown',
        contentLength: bodyText.length,
        matchedSpaFallback: matchedSpa,
        exposedSignatureVerified: signatureVerified,
        note: signatureVerified
          ? 'EXPOSED: Authentic file signature verified'
          : matchedSpa
          ? 'SAFE: Returned SPA HTML fallback (Filtered out false positive)'
          : `SAFE: HTTP ${res.status}`,
      });

      if (signatureVerified) {
        findings.push({
          id: `exposure-${probe.path.replace(/[^a-z0-9]/gi, '-')}`,
          title: probe.title,
          severity: probe.severity,
          module: 'exposure',
          cwe: probe.cwe,
          owasp: probe.owasp,
          affectedTarget: displayProbeUrl,
          summary: probe.summary,
          impact: probe.impact,
          evidence: {
            type: 'route-probe',
            rawProof: `GET ${displayProbeUrl} -> HTTP ${res.status}\nContent-Type: ${contentType}\nSPA Fallback Match: false\n\nVerified Response Body Excerpt:\n${bodyText.slice(0, 450)}`,
            reproductionCommand: `curl -i "${displayProbeUrl}"`,
            verifiedAt: nowIso,
          },
          remediation: {
            summary: probe.remediation,
            snippets: [
              {
                label: 'Express Dotfile & Map Deny',
                language: 'typescript',
                code: `app.use(express.static('dist', {\n  dotfiles: 'deny',\n  setHeaders: (res, filePath) => {\n    if (filePath.endsWith('.map')) {\n      res.status(404).end();\n    }\n  }\n}));`,
              },
              {
                label: 'Nginx Location Block',
                language: 'nginx',
                code: `location ~ /\\.(?!well-known).* {\n    deny all;\n    return 404;\n}`,
              },
            ],
          },
        });
      } else {
        passedChecks.push({
          id: `pass-probe-${probe.path.replace(/[^a-z0-9]/gi, '-')}`,
          title: `Sensitive Route Protected (${probe.path})`,
          module: 'exposure',
          target: displayProbeUrl,
          proofSummary: matchedSpa
            ? `HTTP 200 identified as SPA index.html catch-all (No sensitive data exposed)`
            : `Returned HTTP ${res.status} (${contentType || 'no content'})`,
        });
      }
    } catch {
      // Ignore unreachable probe
    }
  }

  return {
    findings,
    passedChecks,
    telemetry: {
      baseline404Url: `${displayOriginAndBase}/${randomSlug}`,
      baselineStatus,
      baselineContentType: baselineContentType || 'unknown',
      isSpaCatchAll,
      testedRoutes,
    },
  };
}

// ============================================================================
// GITHUB PUBLIC REPOSITORY FETCHER (Manifest & Source Files)
// ============================================================================

async function fetchGithubRepoFiles(githubRepoUrl: string): Promise<{
  files: UploadedCodeFile[];
  repoLabel: string;
}> {
  const cleaned = githubRepoUrl
    .trim()
    .replace(/^https?:\/\/(www\.)?github\.com\//i, '')
    .replace(/\.git$/i, '')
    .replace(/\/$/, '');
  const parts = cleaned.split('/').filter(Boolean);
  if (parts.length < 2) {
    throw new Error(
      'Invalid GitHub repository URL. Expected format: https://github.com/owner/repo'
    );
  }
  const owner = parts[0];
  const repo = parts[1];
  const repoLabel = `${owner}/${repo}`;

  // Fetch default branch info
  const repoInfoRes = await fetchWithTimeout(
    `https://api.github.com/repos/${owner}/${repo}`,
    {
      headers: { Accept: 'application/vnd.github+json' },
    },
    7000
  );
  if (!repoInfoRes.ok) {
    throw new Error(
      `GitHub repository "${repoLabel}" could not be fetched (HTTP ${repoInfoRes.status}). Make sure it is a public repository.`
    );
  }
  const repoInfo = (await repoInfoRes.json()) as { default_branch?: string };
  const branch = repoInfo.default_branch || 'main';

  // Fetch recursive git tree
  const treeRes = await fetchWithTimeout(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
    {
      headers: { Accept: 'application/vnd.github+json' },
    },
    8000
  );
  if (!treeRes.ok) {
    throw new Error(`Could not read repository file tree for ${repoLabel}.`);
  }
  const treeData = (await treeRes.json()) as {
    tree?: Array<{ path: string; type: string; size?: number }>;
  };

  const candidatePaths = (treeData.tree || [])
    .filter((item) => {
      if (item.type !== 'blob') return false;
      if ((item.size || 0) > 120000) return false;
      if (
        /(^|\/)(node_modules|dist|build|\.next|coverage|vendor|\.git)\//i.test(
          item.path
        )
      ) {
        return false;
      }
      if (
        item.path.endsWith('package-lock.json') ||
        item.path.endsWith('yarn.lock') ||
        item.path.endsWith('pnpm-lock.yaml')
      ) {
        return false;
      }
      return (
        item.path === 'package.json' ||
        /\.(ts|tsx|js|jsx|mjs|py|env|json|yml|yaml|html)$/i.test(item.path)
      );
    })
    // Prioritize package.json and server/auth/config/src files
    .sort((a, b) => {
      if (a.path === 'package.json') return -1;
      if (b.path === 'package.json') return 1;
      return a.path.length - b.path.length;
    })
    .slice(0, 18);

  const fetchedFiles: UploadedCodeFile[] = [];
  await Promise.all(
    candidatePaths.map(async (item) => {
      try {
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${item.path}`;
        const fileRes = await fetchWithTimeout(rawUrl, {}, 6000);
        if (fileRes.ok) {
          const content = await fileRes.text();
          fetchedFiles.push({ name: item.path, content });
        }
      } catch {
        // skip individual file failure
      }
    })
  );

  return { files: fetchedFiles, repoLabel };
}

// ============================================================================
// ENGINE 3: DEPENDENCY CVE AUDIT VIA LIVE OSV.DEV DATABASE
// ============================================================================

function cleanSemverVersion(rawVersion: string): string | null {
  const cleaned = rawVersion.trim().replace(/^[\^~>=<v\s]+/, '');
  if (!/^[0-9]+\.[0-9]+\.[0-9]+/.test(cleaned)) {
    return null;
  }
  return cleaned.split(' ')[0];
}

async function runDependencyCveAudit(
  allFiles: Array<{ name: string; content: string; source: 'upload' | 'github' }>
): Promise<{
  findings: VerifiedFinding[];
  passedChecks: PassedCheck[];
  telemetry?: RawAuditTelemetry['dependencies'];
}> {
  const findings: VerifiedFinding[] = [];
  const passedChecks: PassedCheck[] = [];
  const nowIso = new Date().toISOString();

  const pkgFile = allFiles.find(
    (f) => f.name === 'package.json' || f.name.endsWith('/package.json')
  );
  if (!pkgFile) {
    return { findings, passedChecks };
  }

  let parsedPkg: {
    name?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  try {
    parsedPkg = JSON.parse(pkgFile.content);
  } catch {
    return { findings, passedChecks };
  }

  const pkgEntries: Array<{ name: string; version: string; isDev: boolean }> = [];
  for (const [name, ver] of Object.entries(parsedPkg.dependencies || {})) {
    const cleanVer = cleanSemverVersion(String(ver));
    if (cleanVer) pkgEntries.push({ name, version: cleanVer, isDev: false });
  }
  for (const [name, ver] of Object.entries(parsedPkg.devDependencies || {})) {
    const cleanVer = cleanSemverVersion(String(ver));
    if (cleanVer) pkgEntries.push({ name, version: cleanVer, isDev: true });
  }

  if (pkgEntries.length === 0) {
    return { findings, passedChecks };
  }

  const startMs = Date.now();
  const queries = pkgEntries.map((pkg) => ({
    package: { name: pkg.name, ecosystem: 'npm' },
    version: pkg.version,
  }));

  const batchRes = await fetchWithTimeout(
    'https://api.osv.dev/v1/querybatch',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    },
    9000
  );

  const osvQueryTimeMs = Date.now() - startMs;
  const packageRecords: DependencyRecord[] = [];
  let vulnerablePackages = 0;

  if (batchRes.ok) {
    const batchData = (await batchRes.json()) as {
      results?: Array<{ vulns?: Array<{ id: string; modified?: string }> }>;
    };
    const results = batchData.results || [];

    for (let i = 0; i < pkgEntries.length; i++) {
      const pkg = pkgEntries[i];
      const vulns = results[i]?.vulns || [];
      const vulnIds = vulns.map((v) => v.id);

      packageRecords.push({
        name: pkg.name,
        version: pkg.version,
        isDev: pkg.isDev,
        vulnCount: vulnIds.length,
        advisories: vulnIds,
      });

      if (vulnIds.length > 0) {
        vulnerablePackages++;
        // Hydrate top 2 advisories per vulnerable package for detailed CVE proof
        const topIds = vulnIds.slice(0, 2);
        for (const vulnId of topIds) {
          try {
            const detailRes = await fetchWithTimeout(
              `https://api.osv.dev/v1/vulns/${encodeURIComponent(vulnId)}`,
              {},
              5000
            );
            if (!detailRes.ok) continue;
            const detail = (await detailRes.json()) as {
              id: string;
              summary?: string;
              details?: string;
              aliases?: string[];
              database_specific?: { severity?: string; cwe_ids?: string[] };
              affected?: Array<{
                ranges?: Array<{
                  events?: Array<{ introduced?: string; fixed?: string }>;
                }>;
              }>;
            };

            const rawSev = (
              detail.database_specific?.severity || 'HIGH'
            ).toLowerCase();
            const severity: SeverityLevel =
              rawSev === 'critical'
                ? 'critical'
                : rawSev === 'high'
                ? 'high'
                : rawSev === 'moderate' || rawSev === 'medium'
                ? 'medium'
                : 'low';

            const cveAlias =
              (detail.aliases || []).find((a) => a.startsWith('CVE-')) ||
              detail.id;
            const cweId = detail.database_specific?.cwe_ids?.[0] || 'CWE-1395';

            let fixedVersion = 'latest';
            for (const aff of detail.affected || []) {
              for (const rng of aff.ranges || []) {
                for (const ev of rng.events || []) {
                  if (ev.fixed) {
                    fixedVersion = ev.fixed;
                    break;
                  }
                }
              }
            }

            findings.push({
              id: `osv-${pkg.name}-${detail.id}`,
              title: `${pkg.name}@${pkg.version} — ${detail.summary || `Known Vulnerability (${cveAlias})`}`,
              severity,
              module: 'dependencies',
              cwe: cweId,
              owasp: 'A06:2021 Vulnerable and Outdated Components',
              affectedTarget: `${pkgFile.name} → ${pkg.name}@${pkg.version}`,
              summary:
                detail.summary ||
                (detail.details || '').slice(0, 260) ||
                `Verified OSV vulnerability advisory ${detail.id} affecting ${pkg.name}@${pkg.version}.`,
              impact: `Exploitable vulnerability in dependency ${pkg.name}@${pkg.version} documented in OSV.dev (${[detail.id, ...(detail.aliases || [])].join(', ')}).`,
              evidence: {
                type: 'osv-cve',
                rawProof: `OSV Advisory ID: ${detail.id}\nAliases: ${(detail.aliases || []).join(', ') || 'None'}\nPackage: npm:${pkg.name}@${pkg.version}\nSeverity: ${rawSev.toUpperCase()}\nFixed Version: ${fixedVersion}\n\nSummary:\n${detail.summary || (detail.details || '').slice(0, 350)}`,
                reproductionCommand: `curl -s https://api.osv.dev/v1/query -d '{"version":"${pkg.version}","package":{"name":"${pkg.name}","ecosystem":"npm"}}'`,
                verifiedAt: nowIso,
              },
              remediation: {
                summary: `Upgrade ${pkg.name} to version ${fixedVersion} or later to resolve ${detail.id}.`,
                snippets: [
                  {
                    label: 'npm Upgrade Command',
                    language: 'bash',
                    code: `npm install ${pkg.name}@^${fixedVersion}`,
                  },
                  {
                    label: 'package.json Patch',
                    language: 'json',
                    code: `"dependencies": {\n  "${pkg.name}": "^${fixedVersion}"\n}`,
                  },
                ],
              },
            });
          } catch {
            // Skip hydration failure
          }
        }
      } else {
        passedChecks.push({
          id: `pass-dep-${pkg.name}`,
          title: `Dependency Verified Clean (${pkg.name}@${pkg.version})`,
          module: 'dependencies',
          target: `${pkg.name}@${pkg.version}`,
          proofSummary: `0 known advisories in OSV.dev for npm:${pkg.name}@${pkg.version}`,
        });
      }
    }
  }

  return {
    findings,
    passedChecks,
    telemetry: {
      sourceLabel: pkgFile.name,
      totalPackages: pkgEntries.length,
      vulnerablePackages,
      osvQueryTimeMs,
      packages: packageRecords,
    },
  };
}

// ============================================================================
// ENGINE 4: DETERMINISTIC SOURCE CODE SAST & HARDCODED SECRET SCANNER
// ============================================================================

interface SastRule {
  id: string;
  title: string;
  severity: SeverityLevel;
  cwe: string;
  owasp: string;
  regex: RegExp;
  summary: string;
  impact: string;
  remediationSummary: string;
  fixSnippet: { label: string; language: string; code: string };
  validateLine?: (line: string, fileName: string) => boolean;
}

const SAST_RULES: SastRule[] = [
  {
    id: 'sast-aws-access-key',
    title: 'Hardcoded AWS IAM Access Key ID Detected in Source',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A07:2021 Identification and Authentication Failures',
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    summary:
      'Found a hardcoded AWS IAM Access Key ID (AKIA...) directly committed in source code.',
    impact:
      'Attackers with repository or bundle access can authenticate against AWS APIs and compromise cloud infrastructure.',
    remediationSummary:
      'Revoke the AWS key in IAM immediately and load credentials exclusively from server-side environment variables or IAM roles.',
    fixSnippet: {
      label: 'Environment Variable Lookup',
      language: 'typescript',
      code: `const awsAccessKeyId = process.env.AWS_ACCESS_KEY_ID;`,
    },
  },
  {
    id: 'sast-github-pat',
    title: 'Hardcoded GitHub Personal Access Token (PAT) in Source',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A07:2021 Identification and Authentication Failures',
    regex: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b/,
    summary:
      'Found a hardcoded GitHub Personal Access Token embedded in the file.',
    impact:
      'Grants unauthorized read/write access to GitHub repositories, workflows, and organization secrets.',
    remediationSummary:
      'Revoke the token in GitHub Developer Settings and inject it via process.env.GITHUB_TOKEN.',
    fixSnippet: {
      label: 'Secure Token Access',
      language: 'typescript',
      code: `const githubToken = process.env.GITHUB_TOKEN;`,
    },
  },
  {
    id: 'sast-stripe-secret',
    title: 'Hardcoded Stripe Secret API Key in Source',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A07:2021 Identification and Authentication Failures',
    regex: /\b(sk_(live|test)_[0-9a-zA-Z]{20,})\b/,
    summary: 'Found a Stripe secret key (sk_live_ / sk_test_) in source code.',
    impact:
      'Allows unauthorized refunds, customer data access, and payment manipulation.',
    remediationSummary:
      'Roll the API key in the Stripe Dashboard and store it strictly in server-side environment variables.',
    fixSnippet: {
      label: 'Server-Side Stripe Init',
      language: 'typescript',
      code: `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);`,
    },
  },
  {
    id: 'sast-private-key',
    title: 'Hardcoded Cryptographic Private Key Block',
    severity: 'critical',
    cwe: 'CWE-321',
    owasp: 'A02:2021 Cryptographic Failures',
    regex: /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    summary:
      'Found a PEM-encoded private cryptographic key directly inside the codebase.',
    impact:
      'Compromises TLS termination, SSH server access, or JWT RS256 token signing for all users.',
    remediationSummary:
      'Remove the private key from source control, rotate the keypair, and mount keys via secret manager volumes.',
    fixSnippet: {
      label: 'Load Key from Secret Env',
      language: 'typescript',
      code: `const privateKey = process.env.PRIVATE_KEY?.replace(/\\\\n/g, '\\n');`,
    },
  },
  {
    id: 'sast-hardcoded-jwt-or-db-secret',
    title: 'Hardcoded Secret Key or Database Credential Assignment',
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'A07:2021 Identification and Authentication Failures',
    regex:
      /\b(jwt_secret|jwtSecret|database_url|db_password|dbPassword|secretKey|API_SECRET)\s*[:=]\s*["'`]([^"'`$]{10,})["'`]/i,
    summary:
      'A sensitive secret identifier (JWT secret, database URL, or API secret) is assigned a hardcoded string literal.',
    impact:
      'Attackers who read the source code can forge valid JWT authentication tokens or connect directly to the database.',
    remediationSummary:
      'Move secrets to .env (excluded via .gitignore) and read them via process.env without hardcoded fallback strings.',
    fixSnippet: {
      label: 'Strict Env Requirement',
      language: 'typescript',
      code: `const JWT_SECRET = process.env.JWT_SECRET;\nif (!JWT_SECRET) {\n  throw new Error('Missing required JWT_SECRET environment variable');\n}`,
    },
    validateLine: (line, fileName) => {
      if (fileName.endsWith('.env.example')) return false;
      if (/process\.env|YOUR_|MY_|EXAMPLE|PLACEHOLDER|<.*>/i.test(line)) {
        return false;
      }
      return true;
    },
  },
  {
    id: 'sast-sql-injection-interpolation',
    title: 'SQL Injection via Unparameterized Template String Interpolation',
    severity: 'critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021 Injection',
    regex:
      /`\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*\$\{[^}]+\}[^`]*`/i,
    summary:
      'A raw SQL query string interpolates runtime variables directly using ${...} template literals instead of parameterized placeholders.',
    impact:
      'Attackers can inject arbitrary SQL statements to bypass authentication, dump the entire database, or modify records.',
    remediationSummary:
      'Use parameterized queries ($1, $2 or ?) with bound parameter arrays or an ORM query builder.',
    fixSnippet: {
      label: 'Parameterized SQL Query',
      language: 'typescript',
      code: `// Safe parameterized query:\nconst result = await db.query(\n  'SELECT id, email, role FROM users WHERE email = $1',\n  [req.body.email]\n);`,
    },
  },
  {
    id: 'sast-dangerously-set-inner-html',
    title: 'Potential DOM XSS via Unsanitized dangerouslySetInnerHTML',
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    summary:
      'React dangerouslySetInnerHTML is used to inject raw HTML into the DOM without verified DOMPurify sanitization on the same line.',
    impact:
      'If the HTML string contains user-supplied markdown, profile bios, or comments, attackers can execute arbitrary JavaScript in victims’ browsers.',
    remediationSummary:
      'Sanitize all HTML strings with DOMPurify.sanitize() before passing them to dangerouslySetInnerHTML.',
    fixSnippet: {
      label: 'DOMPurify Sanitization',
      language: 'tsx',
      code: `import DOMPurify from 'dompurify';\n\n<div\n  dangerouslySetInnerHTML={{\n    __html: DOMPurify.sanitize(untrustedHtmlContent),\n  }}\n/>`,
    },
    validateLine: (line) => !/DOMPurify\.sanitize/i.test(line),
  },
  {
    id: 'sast-raw-innerhtml',
    title: 'Direct DOM innerHTML / outerHTML Assignment (DOM XSS Sink)',
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    regex: /\.(innerHTML|outerHTML)\s*\+?=\s*(?!["'`]\s*["'`])/,
    summary:
      'Direct assignment to element.innerHTML or element.outerHTML parses and executes raw HTML strings.',
    impact:
      'Untrusted input assigned to innerHTML triggers Cross-Site Scripting (XSS) via <img onerror=...> or <svg onload=...> payloads.',
    remediationSummary:
      'Use element.textContent for plain text or sanitize markup with DOMPurify before inserting.',
    fixSnippet: {
      label: 'Safe textContent Assignment',
      language: 'typescript',
      code: `element.textContent = userProvidedInput;`,
    },
  },
  {
    id: 'sast-eval-execution',
    title: 'Dynamic Code Execution via eval() or new Function()',
    severity: 'high',
    cwe: 'CWE-95',
    owasp: 'A03:2021 Injection',
    regex: /\b(eval\s*\(|new\s+Function\s*\()/,
    summary:
      'The code invokes eval() or new Function(), which compiles and executes arbitrary strings as JavaScript code.',
    impact:
      'If user-controlled data reaches eval(), attackers achieve Remote Code Execution (server-side) or Cross-Site Scripting (client-side).',
    remediationSummary:
      'Replace eval() with JSON.parse() for data parsing or a safe mathematical expression parser.',
    fixSnippet: {
      label: 'Safe JSON Parsing',
      language: 'typescript',
      code: `const parsedData = JSON.parse(rawPayload);`,
    },
  },
  {
    id: 'sast-insecure-postmessage',
    title: 'Insecure window.postMessage with Wildcard Target Origin ("*")',
    severity: 'medium',
    cwe: 'CWE-346',
    owasp: 'A01:2021 Broken Access Control',
    regex: /\.postMessage\s*\([^,]+,\s*["'`]\*["'`]\s*\)/,
    summary:
      'postMessage() is called with a wildcard "*" targetOrigin, broadcasting messages to any framing or popup origin.',
    impact:
      'Malicious windows or iframes can intercept sensitive tokens or state payloads sent via postMessage.',
    remediationSummary:
      'Specify the exact expected origin (e.g. window.location.origin) as the second argument to postMessage.',
    fixSnippet: {
      label: 'Explicit Origin postMessage',
      language: 'typescript',
      code: `targetWindow.postMessage(payload, window.location.origin);`,
    },
  },
  {
    id: 'sast-disabled-tls-verification',
    title: 'Disabled TLS Certificate Validation (MITM Vulnerability)',
    severity: 'high',
    cwe: 'CWE-295',
    owasp: 'A02:2021 Cryptographic Failures',
    regex:
      /(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'`]0["'`]|rejectUnauthorized\s*:\s*false)/,
    summary:
      'TLS certificate verification is explicitly disabled via NODE_TLS_REJECT_UNAUTHORIZED="0" or rejectUnauthorized: false.',
    impact:
      'Accepts self-signed or forged TLS certificates, allowing Man-in-the-Middle (MITM) interception of outbound API calls.',
    remediationSummary:
      'Remove rejectUnauthorized: false and configure proper CA certificates for internal services.',
    fixSnippet: {
      label: 'Enforce TLS Verification',
      language: 'typescript',
      code: `const httpsAgent = new https.Agent({\n  rejectUnauthorized: true,\n});`,
    },
  },
];

function runSourceCodeSast(
  allFiles: Array<{ name: string; content: string; source: 'upload' | 'github' }>
): {
  findings: VerifiedFinding[];
  passedChecks: PassedCheck[];
  telemetry?: RawAuditTelemetry['sast'];
} {
  const findings: VerifiedFinding[] = [];
  const passedChecks: PassedCheck[] = [];
  const nowIso = new Date().toISOString();

  if (allFiles.length === 0) {
    return { findings, passedChecks };
  }

  let totalLines = 0;
  const scannedFiles: ScannedFileRecord[] = [];

  for (const file of allFiles) {
    const lines = file.content.split(/\r?\n/);
    totalLines += lines.length;
    let fileFindingsCount = 0;

    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      const trimmed = line.trim();
      // Skip pure single-line comments
      if (
        trimmed.startsWith('//') ||
        trimmed.startsWith('/*') ||
        trimmed.startsWith('* ')
      ) {
        continue;
      }

      for (const rule of SAST_RULES) {
        if (rule.regex.test(line)) {
          if (rule.validateLine && !rule.validateLine(line, file.name)) {
            continue;
          }

          fileFindingsCount++;
          const lineNumber = idx + 1;
          const prevLine = idx > 0 ? `${idx}: ${lines[idx - 1]}` : '';
          const currLine = `${lineNumber}: ${line}  <-- [VERIFIED MATCH]`;
          const nextLine =
            idx + 1 < lines.length ? `${idx + 2}: ${lines[idx + 1]}` : '';
          const contextSnippet = [prevLine, currLine, nextLine]
            .filter(Boolean)
            .join('\n');

          findings.push({
            id: `${rule.id}-${file.name}-${lineNumber}`,
            title: rule.title,
            severity: rule.severity,
            module: 'sast',
            cwe: rule.cwe,
            owasp: rule.owasp,
            affectedTarget: `${file.name}:${lineNumber}`,
            summary: rule.summary,
            impact: rule.impact,
            evidence: {
              type: 'source-line',
              rawProof: `File: ${file.name} (Line ${lineNumber})\nRule: ${rule.id} (${rule.cwe})\n\n${contextSnippet}`,
              reproductionCommand: `grep -n "${line.trim().replace(/"/g, '\\"').slice(0, 48)}" "${file.name}"`,
              verifiedAt: nowIso,
            },
            remediation: {
              summary: rule.remediationSummary,
              snippets: [rule.fixSnippet],
            },
          });
        }
      }
    }

    scannedFiles.push({
      name: file.name,
      lines: lines.length,
      source: file.source,
      findingsCount: fileFindingsCount,
    });

    if (fileFindingsCount === 0) {
      passedChecks.push({
        id: `pass-sast-${file.name}`,
        title: `Static Code Analysis Clean (${file.name})`,
        module: 'sast',
        target: file.name,
        proofSummary: `Scanned ${lines.length} lines across ${SAST_RULES.length} deterministic SAST & secret signatures — 0 issues`,
      });
    }
  }

  return {
    findings,
    passedChecks,
    telemetry: {
      totalFiles: allFiles.length,
      totalLines,
      files: scannedFiles,
    },
  };
}

// ============================================================================
// MAIN UNIFIED AUDIT API ENDPOINT
// ============================================================================

app.post('/api/audit/run', async (req, res) => {
  const startTotalMs = Date.now();
  try {
    const {
      projectName = 'MLSA KIIT Chapter Project',
      targetUrl = '',
      githubRepoUrl = '',
      uploadedFiles = [],
      modules = {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: true,
        sourceSast: true,
      },
    } = req.body as {
      projectName?: string;
      targetUrl?: string;
      githubRepoUrl?: string;
      uploadedFiles?: UploadedCodeFile[];
      modules?: {
        httpHeaders: boolean;
        routeProbing: boolean;
        dependencyCve: boolean;
        sourceSast: boolean;
      };
    };

    const allFindings: VerifiedFinding[] = [];
    const allPassedChecks: PassedCheck[] = [];
    const rawTelemetry: RawAuditTelemetry = {};
    const enabledModules: AuditModuleId[] = [];

    const reqHost = req.headers.host || 'localhost:3000';
    const normalizedUrl = normalizeTargetUrl(targetUrl, reqHost);
    const displayUrl = targetUrl.trim().startsWith('/')
      ? `${req.protocol}://${reqHost}${targetUrl.trim()}`
      : normalizedUrl;

    // 1. Live URL HTTP + Route Probing
    if (normalizedUrl && (modules.httpHeaders || modules.routeProbing)) {
      let discoveredScripts: string[] = [];
      if (modules.httpHeaders) {
        enabledModules.push('http');
        const httpResult = await runHttpHeaderInspection(
          normalizedUrl,
          displayUrl
        );
        allFindings.push(...httpResult.findings);
        allPassedChecks.push(...httpResult.passedChecks);
        rawTelemetry.http = httpResult.telemetry;
        discoveredScripts = httpResult.telemetry.discoveredScripts;
      }

      if (modules.routeProbing) {
        enabledModules.push('exposure');
        const probeResult = await runSensitiveRouteProbing(
          normalizedUrl,
          displayUrl,
          discoveredScripts
        );
        allFindings.push(...probeResult.findings);
        allPassedChecks.push(...probeResult.passedChecks);
        rawTelemetry.probes = probeResult.telemetry;
      }
    }

    // 2. Collect Code & Manifest Files (Uploaded + GitHub Repo)
    const combinedFiles: Array<{
      name: string;
      content: string;
      source: 'upload' | 'github';
    }> = (uploadedFiles || []).map((f) => ({
      name: f.name,
      content: f.content,
      source: 'upload' as const,
    }));

    if (githubRepoUrl && githubRepoUrl.trim()) {
      const ghResult = await fetchGithubRepoFiles(githubRepoUrl);
      for (const gf of ghResult.files) {
        if (!combinedFiles.some((existing) => existing.name === gf.name)) {
          combinedFiles.push({
            name: gf.name,
            content: gf.content,
            source: 'github',
          });
        }
      }
    }

    // 3. Dependency CVE Audit via OSV.dev
    if (modules.dependencyCve && combinedFiles.length > 0) {
      enabledModules.push('dependencies');
      const depResult = await runDependencyCveAudit(combinedFiles);
      allFindings.push(...depResult.findings);
      allPassedChecks.push(...depResult.passedChecks);
      if (depResult.telemetry) {
        rawTelemetry.dependencies = depResult.telemetry;
      }
    }

    // 4. Deterministic Source Code SAST & Secret Detection
    if (modules.sourceSast && combinedFiles.length > 0) {
      enabledModules.push('sast');
      const sastResult = runSourceCodeSast(combinedFiles);
      allFindings.push(...sastResult.findings);
      allPassedChecks.push(...sastResult.passedChecks);
      if (sastResult.telemetry) {
        rawTelemetry.sast = sastResult.telemetry;
      }
    }

    // Sort findings by severity (Critical -> High -> Medium -> Low)
    const severityRank: Record<SeverityLevel, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };
    allFindings.sort(
      (a, b) => severityRank[a.severity] - severityRank[b.severity]
    );

    const report: AuditReport = {
      id: `mlsa-kiit-audit-${Date.now()}`,
      projectName: projectName.trim() || 'MLSA KIIT Project Audit',
      timestamp: new Date().toISOString(),
      durationMs: Date.now() - startTotalMs,
      targetSummary: {
        targetUrl: displayUrl || undefined,
        githubRepoUrl: githubRepoUrl.trim() || undefined,
        filesCount: combinedFiles.length,
        enabledModules,
      },
      findings: allFindings,
      passedChecks: allPassedChecks,
      rawTelemetry,
    };

    res.status(200).json(report);
  } catch (err) {
    const message =
      err instanceof Error ? err.message : 'Unexpected verification failure';
    res.status(400).json({ error: message });
  }
});

// ============================================================================
// VITE DEV MIDDLEWARE / STATIC PRODUCTION SERVER
// ============================================================================

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MLSA KIIT Sentinel server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
