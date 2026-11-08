import React, { useEffect, useState } from 'react';
import {
  Check,
  Copy,
  Eye,
  Flame,
  KeyRound,
  ShieldAlert,
  Terminal,
  Wrench,
  X,
} from 'lucide-react';
import type { VerifiedFinding } from '../types/audit.ts';

interface EvidenceDrawerProps {
  finding: VerifiedFinding | null;
  onClose: () => void;
}

const SEVERITY_TEXT_COLORS: Record<VerifiedFinding['severity'], string> = {
  critical: 'text-[#EF4444]',
  high: 'text-[#F97316]',
  medium: 'text-[#F59E0B]',
  low: 'text-[#38BDF8]',
};

const MODULE_LABELS: Record<VerifiedFinding['module'], string> = {
  http: 'HTTP, CORS & Transport Engine',
  exposure: 'Sensitive Route & Sourcemap Prober',
  dependencies: 'OSV.dev Supply Chain CVE Engine',
  sast: 'Deterministic Source Code SAST',
  bundle: 'Client JS Bundle & API Harvester',
  jwt: 'JWT Cryptographic & Weak-Secret Auditor',
  protocol: 'GraphQL, HTTP Verb & Open-Redirect Prober',
};

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({
  finding,
  onClose,
}) => {
  const [activeSnippetIdx, setActiveSnippetIdx] = useState(0);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [copiedFix, setCopiedFix] = useState(false);
  const [copiedProof, setCopiedProof] = useState(false);
  const [copiedForgedJwt, setCopiedForgedJwt] = useState(false);

  // Interactive Clickjacking Sandbox State
  const [iframeOpacity, setIframeOpacity] = useState(35);
  const [hijackedClickCount, setHijackedClickCount] = useState(0);

  useEffect(() => {
    setActiveSnippetIdx(0);
    setCopiedCmd(false);
    setCopiedFix(false);
    setCopiedProof(false);
    setCopiedForgedJwt(false);
    setIframeOpacity(35);
    setHijackedClickCount(0);
  }, [finding]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (finding) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [finding, onClose]);

  if (!finding) return null;

  const activeSnippet =
    finding.remediation.snippets[activeSnippetIdx] ||
    finding.remediation.snippets[0];

  const copyText = async (
    text: string,
    setter: React.Dispatch<React.SetStateAction<boolean>>
  ) => {
    try {
      await navigator.clipboard.writeText(text);
      setter(true);
      setTimeout(() => setter(false), 2000);
    } catch {
      // ignore clipboard errors
    }
  };

  const exploit = finding.exploitProof;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/65 backdrop-blur-sm transition-opacity duration-150">
      <div
        className="flex-1"
        onClick={onClose}
        aria-label="Close evidence drawer backdrop"
      />
      <aside className="glass-workspace relative z-10 flex h-full w-full max-w-2xl flex-col border-l border-white/[0.12] text-[#F8FAFC] shadow-2xl">
        {/* Drawer Header */}
        <div className="flex items-start justify-between gap-4 border-b border-white/[0.09] bg-white/[0.02] px-6 py-5">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span
                className={`font-semibold uppercase ${SEVERITY_TEXT_COLORS[finding.severity]}`}
              >
                {finding.severity} Severity
              </span>
              <span className="text-white/25" aria-hidden="true">
                ·
              </span>
              <span className="text-[#94A3B8]">{finding.cwe}</span>
              <span className="text-white/25" aria-hidden="true">
                ·
              </span>
              <span className="text-[#94A3B8]">{finding.owasp}</span>
              <span className="text-white/25" aria-hidden="true">
                ·
              </span>
              <span className="text-[#38BDF8]">
                {MODULE_LABELS[finding.module]}
              </span>
            </div>
            <h2 className="font-display text-lg font-semibold leading-snug text-white">
              {finding.title}
            </h2>
            <p className="font-mono text-xs text-[#94A3B8] break-all">
              Affected Target: {finding.affectedTarget}
            </p>
          </div>
          <button
            onClick={onClose}
            className="glass-subpanel rounded-md p-2 text-[#94A3B8] hover:border-white/[0.22] hover:text-white transition-colors shrink-0"
            aria-label="Close drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          {/* Technical Explanation & Exploitability Impact */}
          <div className="glass-subpanel grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-white/[0.08] rounded-lg">
            <div className="p-4">
              <div className="text-xs font-medium text-[#38BDF8] mb-1.5">
                Verification Summary
              </div>
              <p className="text-sm leading-relaxed text-[#E2E8F0]">
                {finding.summary}
              </p>
            </div>
            <div className="p-4">
              <div className="text-xs font-medium text-[#38BDF8] mb-1.5">
                Exploitability & Impact
              </div>
              <p className="text-sm leading-relaxed text-[#E2E8F0]">
                {finding.impact}
              </p>
            </div>
          </div>

          {/* =================================================================
              LIVE EXPLOITABILITY PROOF SANDBOX (Clickjacking, CORS, JWT, GraphQL, Redirect)
             ================================================================= */}
          {exploit && (
            <div className="glass-subpanel rounded-xl border border-[#EF4444]/35 bg-[#EF4444]/[0.05] p-4 space-y-4">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-xs font-mono font-semibold text-[#EF4444]">
                  <Flame className="h-4 w-4 shrink-0" />
                  <span>INTERACTIVE EXPLOITABILITY PROOF SANDBOX</span>
                </div>
                <span className="font-mono text-[11px] text-[#CBD5E1] uppercase">
                  PoC Class: {exploit.type}
                </span>
              </div>

              {/* 1. CLICKJACKING LIVE IFRAME OVERLAY SANDBOX */}
              {exploit.type === 'clickjacking' && exploit.targetUrl && (
                <div className="space-y-3">
                  <p className="text-xs text-[#CBD5E1] leading-relaxed">
                    Because <code className="text-white">X-Frame-Options</code>{' '}
                    and <code className="text-white">CSP frame-ancestors</code>{' '}
                    are both absent, the live target URL is embedded inside the
                    hostile <code className="text-white">&lt;iframe&gt;</code>{' '}
                    below. Drag the opacity slider to see how an invisible target
                    frame overlays a decoy button to hijack user clicks.
                  </p>

                  <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-black/40 px-3.5 py-2.5 text-xs font-mono">
                    <div className="flex items-center gap-2 text-[#E2E8F0]">
                      <Eye className="h-3.5 w-3.5 text-[#38BDF8]" />
                      <span>Target Iframe X-Ray Opacity:</span>
                      <span className="text-[#38BDF8] font-bold tabular-nums">
                        {iframeOpacity}%
                      </span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={90}
                      value={iframeOpacity}
                      onChange={(e) => setIframeOpacity(Number(e.target.value))}
                      className="w-40 accent-[#0078D4]"
                    />
                  </div>

                  {/* Framed Target + Decoy Lure Container */}
                  <div className="relative h-56 w-full overflow-hidden rounded-lg border border-white/[0.15] bg-[#050914]">
                    {/* Decoy Attacker Layer */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center p-4 text-center space-y-2">
                      <div className="text-[11px] font-mono text-[#F59E0B]">
                        ATTACKER DECOY LAYER (VISIBLE TO VICTIM)
                      </div>
                      <div className="font-display text-sm font-bold text-white">
                        Developer Cloud Credit Giveaway
                      </div>
                      <button
                        type="button"
                        onClick={() => setHijackedClickCount((c) => c + 1)}
                        className="rounded-lg bg-[#0078D4] px-4 py-2 text-xs font-semibold text-white shadow-lg"
                      >
                        Click to Claim Free Developer Credits (Hijacked:{' '}
                        {hijackedClickCount}x)
                      </button>
                    </div>

                    {/* Live Target Iframe Layer */}
                    <iframe
                      src={exploit.targetUrl}
                      title="Clickjacking Exploitability Proof Sandbox"
                      sandbox="allow-forms allow-scripts"
                      style={{ opacity: iframeOpacity / 100 }}
                      className="pointer-events-none absolute inset-0 h-full w-full border-0"
                    />
                  </div>
                </div>
              )}

              {/* 2. JWT WEAK SECRET CRACKED & FORGED ADMIN TOKEN */}
              {exploit.type === 'jwt-forge' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                    <div className="rounded-lg bg-black/45 p-3">
                      <div className="text-[11px] text-[#94A3B8]">
                        Cracked / Verified Signing Secret
                      </div>
                      <div className="text-sm font-bold text-[#EF4444] mt-1 break-all">
                        {exploit.crackedSecret}
                      </div>
                    </div>
                    <div className="rounded-lg bg-black/45 p-3">
                      <div className="text-[11px] text-[#94A3B8]">
                        Privilege Escalation Claim Injected
                      </div>
                      <div className="text-sm font-bold text-[#10B981] mt-1">
                        {`"role": "admin", "escalatedBy": "Sentinel-AppSec-PoC"`}
                      </div>
                    </div>
                  </div>

                  {exploit.forgedAdminJwt && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-xs font-mono text-[#E2E8F0]">
                          <KeyRound className="h-3.5 w-3.5 text-[#38BDF8]" />
                          <span>
                            Cryptographically Valid Forged Admin JWT:
                          </span>
                        </span>
                        <button
                          type="button"
                          onClick={() =>
                            copyText(
                              exploit.forgedAdminJwt || '',
                              setCopiedForgedJwt
                            )
                          }
                          className="glass-subpanel flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium text-white hover:border-white/[0.25]"
                        >
                          {copiedForgedJwt ? (
                            <>
                              <Check className="h-3 w-3 text-[#10B981]" />
                              <span>Copied Forged JWT</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              <span>Copy Forged Admin Token</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="overflow-x-auto rounded-lg bg-black/50 p-3 font-mono text-[11px] text-[#38BDF8] break-all whitespace-pre-wrap">
                        <code>{exploit.forgedAdminJwt}</code>
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* 3. CORS REFLECTION EXPLOIT PROOF */}
              {exploit.type === 'cors' && (
                <div className="space-y-2.5 text-xs">
                  <div className="font-mono text-[#E2E8F0]">
                    Reflected Origin:{' '}
                    <span className="text-[#EF4444] font-semibold">
                      {exploit.corsOrigin || 'https://untrusted-origin.sentinel.audit'}
                    </span>
                  </div>
                  <pre className="overflow-x-auto rounded-lg bg-black/50 p-3 font-mono text-[11px] leading-relaxed text-[#E2E8F0]">
                    <code>{`// Cross-Origin Credentialed Read PoC (Executed from ${exploit.corsOrigin || 'https://untrusted-origin.sentinel.audit'})
fetch("${exploit.targetUrl}", {
  method: "GET",
  credentials: "include"
})
  .then(res => res.text())
  .then(sensitiveData => console.log("Exfiltrated response:", sensitiveData));`}</code>
                  </pre>
                </div>
              )}

              {/* 4. GRAPHQL INTROSPECTION SCHEMA DUMP PROOF */}
              {exploit.type === 'graphql' && exploit.graphqlTypes && (
                <div className="space-y-2 text-xs">
                  <div className="text-[#CBD5E1]">
                    Unauthenticated{' '}
                    <code className="text-white">__schema</code> query returned{' '}
                    <span className="text-white font-semibold">
                      {exploit.graphqlTypes.length}
                    </span>{' '}
                    schema types from{' '}
                    <code className="text-[#38BDF8]">{exploit.targetUrl}</code>:
                  </div>
                  <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                    {exploit.graphqlTypes.map((typeName) => (
                      <span
                        key={typeName}
                        className="rounded bg-black/50 px-2 py-0.5 text-[#38BDF8] border border-white/[0.08]"
                      >
                        {typeName}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* 5. UNVALIDATED OPEN REDIRECT PROOF */}
              {exploit.type === 'open-redirect' && (
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="text-[#CBD5E1]">
                    Tampered URL:{' '}
                    <span className="text-white break-all">
                      {exploit.targetUrl}
                    </span>
                  </div>
                  <div className="text-[#EF4444]">
                    Redirected Location Header: {exploit.redirectLocation}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Empirical Proof Artifact */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <ShieldAlert className="h-4 w-4 text-[#38BDF8]" />
                <span>Authentic Empirical Proof</span>
              </div>
              <button
                onClick={() =>
                  copyText(finding.evidence.rawProof, setCopiedProof)
                }
                className="glass-subpanel flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-[#E2E8F0] hover:border-white/[0.22] hover:text-white transition-colors whitespace-nowrap shrink-0"
              >
                {copiedProof ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-[#10B981]" />
                    <span>Copied Proof</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copy Raw Proof</span>
                  </>
                )}
              </button>
            </div>
            <pre className="glass-subpanel overflow-x-auto rounded-lg p-4 font-mono text-xs leading-relaxed text-[#E2E8F0]">
              <code>{finding.evidence.rawProof}</code>
            </pre>
            <div className="flex items-center justify-between text-xs text-[#94A3B8] font-mono">
              <span>Evidence Class: {finding.evidence.type}</span>
              <span>
                Verified At:{' '}
                {new Date(finding.evidence.verifiedAt).toLocaleTimeString()}
              </span>
            </div>
          </div>

          {/* Independent Terminal Reproduction Command */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Terminal className="h-4 w-4 text-[#38BDF8]" />
                <span>Independent Terminal Reproduction</span>
              </div>
              <button
                onClick={() =>
                  copyText(finding.evidence.reproductionCommand, setCopiedCmd)
                }
                className="glass-subpanel flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-[#E2E8F0] hover:border-white/[0.22] hover:text-white transition-colors whitespace-nowrap shrink-0"
              >
                {copiedCmd ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-[#10B981]" />
                    <span>Copied Command</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copy Command</span>
                  </>
                )}
              </button>
            </div>
            <pre className="glass-subpanel overflow-x-auto rounded-lg p-3.5 font-mono text-xs text-[#38BDF8]">
              <code>$ {finding.evidence.reproductionCommand}</code>
            </pre>
          </div>

          {/* Copyable Framework Remediation Patch */}
          <div className="space-y-3 pt-2 border-t border-white/[0.09]">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <Wrench className="h-4 w-4 text-[#10B981]" />
              <span>Recommended Remediation & Copyable Patch</span>
            </div>
            <p className="text-sm text-[#CBD5E1] leading-relaxed">
              {finding.remediation.summary}
            </p>

            {finding.remediation.snippets.length > 0 && activeSnippet && (
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="glass-subpanel flex items-center gap-1 rounded-md p-1">
                    {finding.remediation.snippets.map((snip, i) => (
                      <button
                        key={snip.label}
                        onClick={() => setActiveSnippetIdx(i)}
                        className={`rounded px-3 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                          activeSnippetIdx === i
                            ? 'bg-[#0078D4] text-white'
                            : 'text-[#94A3B8] hover:text-white'
                        }`}
                      >
                        {snip.label}
                      </button>
                    ))}
                  </div>

                  <button
                    onClick={() => copyText(activeSnippet.code, setCopiedFix)}
                    className="glass-subpanel flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium text-white hover:border-white/[0.22] transition-colors whitespace-nowrap shrink-0"
                  >
                    {copiedFix ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-[#10B981]" />
                        <span>Copied Fix Patch</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5" />
                        <span>Copy Fix Snippet</span>
                      </>
                    )}
                  </button>
                </div>

                <pre className="glass-subpanel overflow-x-auto rounded-lg p-4 font-mono text-xs leading-relaxed text-[#10B981]">
                  <code>{activeSnippet.code}</code>
                </pre>
              </div>
            )}
          </div>
        </div>
      </aside>
    </div>
  );
};
