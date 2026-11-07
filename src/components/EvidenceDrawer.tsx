import React, { useEffect, useState } from 'react';
import { Check, Copy, Terminal, X, ShieldAlert, Wrench } from 'lucide-react';
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
};

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({
  finding,
  onClose,
}) => {
  const [activeSnippetIdx, setActiveSnippetIdx] = useState(0);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [copiedFix, setCopiedFix] = useState(false);
  const [copiedProof, setCopiedProof] = useState(false);

  useEffect(() => {
    setActiveSnippetIdx(0);
    setCopiedCmd(false);
    setCopiedFix(false);
    setCopiedProof(false);
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
