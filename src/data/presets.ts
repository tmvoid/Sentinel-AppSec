import type { AuditTargetConfig } from '../types/audit.ts';

export interface AuditPreset {
  id: string;
  label: string;
  subtitle: string;
  config: AuditTargetConfig;
}

export const AUDIT_PRESETS: AuditPreset[] = [
  {
    id: 'kiit-fest-vulnerable',
    label: 'KIIT Fest Registration Portal (Vulnerable Benchmark)',
    subtitle:
      'Audits a live unhardened endpoint + student repo files with real OSV CVEs & SAST sinks',
    config: {
      projectName: 'KIIT Fest Student Registration Portal',
      targetUrl: '/api/sandbox/vulnerable-student-portal',
      githubRepoUrl: '',
      modules: {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: true,
        sourceSast: true,
      },
      uploadedFiles: [
        {
          name: 'package.json',
          content: JSON.stringify(
            {
              name: 'kiit-fest-portal',
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

// Student team hardcoded production secret and AWS key during hackathon
const JWT_SECRET = "kiit_fest_super_secret_signing_key_2026_prod";
const AWS_BACKUP_KEY = "AKIAIOSFODNN7EXAMPLE";

export async function loginStudent(req: express.Request, res: express.Response, db: any) {
  const { email, rollNumber } = req.body;
  // Unparameterized SQL string interpolation
  const query = \`SELECT id, email, role FROM students WHERE email = '\${email}' AND roll = '\${rollNumber}'\`;
  const user = await db.execute(query);

  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET);
  return res.json({ token });
}
`,
        },
        {
          name: 'src/components/EventNoticeBoard.tsx',
          content: `import React from 'react';

export function EventNoticeBoard({ rawNoticeHtml, parentOrigin }: { rawNoticeHtml: string; parentOrigin: string }) {
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
    id: 'mlsa-hardened-portal',
    label: 'MLSA KIIT Hardened Portal (Zero-Issue Verification)',
    subtitle:
      'Proves zero bogus reports: audits a hardened endpoint + clean codebase and reports 0 false positives',
    config: {
      projectName: 'MLSA KIIT Official Chapter Hub (Hardened)',
      targetUrl: '/api/sandbox/hardened-mlsa-portal',
      githubRepoUrl: '',
      modules: {
        httpHeaders: true,
        routeProbing: true,
        dependencyCve: true,
        sourceSast: true,
      },
      uploadedFiles: [
        {
          name: 'package.json',
          content: JSON.stringify(
            {
              name: 'mlsa-kiit-chapter-hub',
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
          content: `export async function verifyAmbassadorSession(db: { query: (sql: string, params: unknown[]) => Promise<unknown> }, email: string) {
  const jwtSecret = process.env.MLSA_JWT_SECRET;
  if (!jwtSecret) {
    throw new Error('Missing MLSA_JWT_SECRET environment variable');
  }
  return await db.query(
    'SELECT id, email, chapter_role FROM ambassadors WHERE email = $1',
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
      },
      uploadedFiles: [],
    },
  },
];
