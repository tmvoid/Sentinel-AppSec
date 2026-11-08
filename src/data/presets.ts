import type { AuditTargetConfig } from '../types/audit.ts';

export interface AuditPreset {
  id: string;
  label: string;
  subtitle: string;
  config: AuditTargetConfig;
}

export const AUDIT_PRESETS: AuditPreset[] = [
  {
    id: 'modern-web-vulnerable',
    label: 'Modern Web Application (Vulnerable Benchmark)',
    subtitle:
      'Audits a live unhardened endpoint + repo files with real OSV CVEs, weak JWT & SAST sinks',
    config: {
      projectName: 'Modern Web Application (Sample Target)',
      targetUrl: '/api/sandbox/vulnerable-student-portal',
      githubRepoUrl: '',
      modules: {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: true,
        sourceSast: true,
        jsBundleAudit: true,
        jwtAudit: true,
        protocolProbing: true,
      },
      uploadedFiles: [
        {
          name: 'package.json',
          content: JSON.stringify(
            {
              name: 'sample-web-portal',
              version: '1.0.0',
              private: true,
              dependencies: {
                express: '4.17.1',
                axios: '0.21.1',
                lodash: '4.17.15',
                jsonwebtoken: '8.5.1',
              },
            },
            null,
            2
          ),
        },
        {
          name: 'src/server/authController.ts',
          content: `import express from 'express';
import jwt from 'jsonwebtoken';

// Hardcoded production secret and cloud access key
const JWT_SECRET = "production_super_secret_signing_key_2026_demo";
const AWS_BACKUP_KEY = "AKIAIOSFODNN7EXAMPLE";

export async function loginUser(req: express.Request, res: express.Response, db: any) {
  const { email, accountId } = req.body;
  // Unparameterized SQL string interpolation
  const query = \`SELECT id, email, role FROM users WHERE email = '\${email}' AND account_id = '\${accountId}'\`;
  const user = await db.execute(query);

  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET);
  return res.json({ token });
}
`,
        },
        {
          name: 'src/components/BroadcastNotice.tsx',
          content: `import React from 'react';

export function BroadcastNotice({ rawNoticeHtml, parentOrigin }: { rawNoticeHtml: string; parentOrigin: string }) {
  const notifyEmbed = () => {
    window.parent.postMessage({ type: 'NOTICE_VIEWED', secretToken: localStorage.getItem('token') }, '*');
  };

  return (
    <section onClick={notifyEmbed}>
      <div dangerouslySetInnerHTML={{ __html: rawNoticeHtml }} />
    </section>
  );
}
`,
        },
      ],
    },
  },
  {
    id: 'hardened-production-service',
    label: 'Hardened Production Service (Zero-Issue Benchmark)',
    subtitle:
      'Proves zero bogus reports: audits a hardened endpoint + clean codebase and reports 0 false positives',
    config: {
      projectName: 'Hardened Production Service (Clean Target)',
      targetUrl: '/api/sandbox/hardened-service',
      githubRepoUrl: '',
      modules: {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: true,
        sourceSast: true,
        jsBundleAudit: true,
        jwtAudit: true,
        protocolProbing: true,
      },
      uploadedFiles: [
        {
          name: 'package.json',
          content: JSON.stringify(
            {
              name: 'hardened-service-core',
              version: '2.4.0',
              private: true,
              dependencies: {
                react: '19.0.1',
                'react-dom': '19.0.1',
                'lucide-react': '0.546.0',
              },
            },
            null,
            2
          ),
        },
        {
          name: 'src/security/authService.ts',
          content: `export async function verifyUserSession(db: { query: (sql: string, params: unknown[]) => Promise<unknown> }, email: string) {
  const jwtSecret = process.env.APP_JWT_SECRET;
  if (!jwtSecret) {
    throw new Error('Missing APP_JWT_SECRET environment variable');
  }
  return await db.query(
    'SELECT id, email, role FROM users WHERE email = $1',
    [email]
  );
}
`,
        },
      ],
    },
  },
  {
    id: 'live-self-audit',
    label: 'Audit Current Live Workspace URL',
    subtitle:
      'Runs real HTTP header, CORS, cookie, and SPA route probing against this live deployed URL',
    config: {
      projectName: 'Current Live Deployment Self-Audit',
      targetUrl: typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000',
      githubRepoUrl: '',
      modules: {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: false,
        sourceSast: false,
        jsBundleAudit: true,
        jwtAudit: true,
        protocolProbing: true,
      },
      uploadedFiles: [],
    },
  },
];
