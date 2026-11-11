import React, { useState } from 'react';
import {
  Check,
  Cloud,
  Copy,
  ExternalLink,
  Globe,
  RefreshCw,
  Server,
  ShieldCheck,
  Terminal,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';

export type EngineConnectionMode = 'same-origin-node' | 'remote-node' | 'browser-sandbox';

export interface BackendConnectionState {
  mode: EngineConnectionMode;
  customBackendUrl: string;
  latencyMs: number | null;
  lastCheckedAt: string | null;
  isChecking: boolean;
  error: string | null;
}

interface BackendConnectionModalProps {
  isOpen: boolean;
  onClose: () => void;
  connectionState: BackendConnectionState;
  onSaveCustomUrl: (url: string) => Promise<void>;
  onPingConnection: (overrideUrl?: string) => Promise<void>;
}

const RENDER_YAML_SNIPPET = `services:
  - type: web
    name: sentinel-appsec
    runtime: node
    plan: free
    buildCommand: npm install --legacy-peer-deps && npm run build
    startCommand: npx tsx server.ts
    healthCheckPath: /api/health
    envVars:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: 3000`;

export const BackendConnectionModal: React.FC<BackendConnectionModalProps> = ({
  isOpen,
  onClose,
  connectionState,
  onSaveCustomUrl,
  onPingConnection,
}) => {
  const [activeTab, setActiveTab] = useState<'connection' | 'deploy-guide'>('connection');
  const [inputUrl, setInputUrl] = useState(connectionState.customBackendUrl);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleApplyUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = inputUrl.trim().replace(/\/+$/, '');
    setInputUrl(cleaned);
    await onSaveCustomUrl(cleaned);
  };

  const handleSelectPreset = async (presetUrl: string) => {
    setInputUrl(presetUrl);
    await onSaveCustomUrl(presetUrl);
  };

  const isLiveNode =
    connectionState.mode === 'same-origin-node' || connectionState.mode === 'remote-node';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="backend-modal-title"
    >
      <div className="relative w-full max-w-3xl rounded-2xl border border-white/[0.12] bg-[#080D1A] text-white shadow-2xl overflow-hidden my-8">
        {/* Modal Header */}
        <div className="flex items-center justify-between gap-4 border-b border-white/[0.09] px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#0EA5E9]/15 border border-[#38BDF8]/30 text-[#38BDF8]">
              <Server className="h-4 w-4" />
            </div>
            <div>
              <h2 id="backend-modal-title" className="font-display text-base font-bold text-white">
                Audit Engine Connection & Free Cloud Hosting
              </h2>
              <p className="text-xs text-[#94A3B8]">
                Manage live Node.js socket connectivity or deploy fullstack for $0/month
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-[#94A3B8] hover:bg-white/[0.08] hover:text-white transition-colors"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Segmented Control Tabs */}
        <div className="flex items-center gap-2 border-b border-white/[0.08] bg-[#050912] px-6 py-2.5">
          <button
            type="button"
            onClick={() => setActiveTab('connection')}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'connection'
                ? 'bg-[#0284C7] text-white'
                : 'text-[#94A3B8] hover:text-white hover:bg-white/[0.05]'
            }`}
          >
            <Wifi className="h-3.5 w-3.5" />
            <span>Live Engine Connection</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('deploy-guide')}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'deploy-guide'
                ? 'bg-[#0284C7] text-white'
                : 'text-[#94A3B8] hover:text-white hover:bg-white/[0.05]'
            }`}
          >
            <Cloud className="h-3.5 w-3.5" />
            <span>Free Fullstack Hosting Guide ($0/mo)</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {activeTab === 'connection' ? (
            <>
              {/* Current Telemetry Status Banner */}
              <div
                className={`rounded-xl border p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                  isLiveNode
                    ? 'border-emerald-500/30 bg-emerald-500/[0.07]'
                    : 'border-amber-500/30 bg-amber-500/[0.07]'
                }`}
              >
                <div className="flex items-start gap-3.5">
                  <div
                    className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${
                      isLiveNode
                        ? 'border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                        : 'border-amber-500/40 bg-amber-500/20 text-amber-300'
                    }`}
                  >
                    {isLiveNode ? (
                      <ShieldCheck className="h-4 w-4" />
                    ) : (
                      <WifiOff className="h-4 w-4" />
                    )}
                  </div>
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-semibold">
                      <span className={isLiveNode ? 'text-emerald-300' : 'text-amber-300'}>
                        {connectionState.mode === 'same-origin-node'
                          ? 'Connected: Local On-Device Node.js Engine'
                          : connectionState.mode === 'remote-node'
                          ? 'Connected: Remote Node.js Engine'
                          : 'Active Mode: Static Preview & UI Showcase (Demo Mode)'}
                      </span>
                      {connectionState.latencyMs !== null && (
                        <>
                          <span className="text-white/30">·</span>
                          <span className="font-mono tabular-nums text-[#E2E8F0]">
                            {connectionState.latencyMs} ms ping
                          </span>
                        </>
                      )}
                    </div>
                    <p className="text-xs text-[#CBD5E1] leading-relaxed">
                      {isLiveNode
                        ? '100% authentic OS-level TCP/HTTP socket auditing active on your machine. Every target you scan and every report you generate stays strictly on your device.'
                        : 'Hosted GitHub Pages deployments are static UI showcases and do not produce authentic live network audit results due to browser sandbox isolation. Because we value your privacy, install and run Sentinel on your own device below so every report stays 100% on your machine.'}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => onPingConnection(inputUrl.trim().replace(/\/+$/, ''))}
                  disabled={connectionState.isChecking}
                  className="glass-subpanel flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold text-[#38BDF8] hover:border-[#38BDF8]/50 hover:text-white transition-all whitespace-nowrap shrink-0 self-start sm:self-center"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${connectionState.isChecking ? 'animate-spin' : ''}`}
                  />
                  <span>{connectionState.isChecking ? 'Testing...' : 'Test Ping'}</span>
                </button>
              </div>

              {connectionState.error && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-200">
                  {connectionState.error}
                </div>
              )}

              {/* Custom Backend URL Configuration Form */}
              <form onSubmit={handleApplyUrl} className="space-y-4">
                <div>
                  <label
                    htmlFor="custom-backend-url-input"
                    className="block text-xs font-semibold text-white mb-1.5"
                  >
                    Backend Engine Endpoint URL (Leave blank for automatic same-origin)
                  </label>
                  <div className="flex flex-col sm:flex-row gap-2.5">
                    <div className="relative flex-1">
                      <Globe className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[#94A3B8]" />
                      <input
                        id="custom-backend-url-input"
                        type="text"
                        value={inputUrl}
                        onChange={(e) => setInputUrl(e.target.value)}
                        placeholder="https://sentinel-appsec.onrender.com (or leave empty for same-origin)"
                        className="glass-input w-full rounded-lg pl-10 pr-4 py-2.5 text-xs font-mono text-white placeholder-[#94A3B8]"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={connectionState.isChecking}
                      className="primary-cta-btn flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs font-semibold whitespace-nowrap shrink-0"
                    >
                      <Check className="h-3.5 w-3.5" />
                      <span>Save & Connect</span>
                    </button>
                  </div>
                  <p className="text-[11px] text-[#94A3B8] mt-1.5">
                    Saved in browser storage. When set, even your static GitHub Pages site (
                    <code className="font-mono text-[#38BDF8]">tmvoid.github.io</code>) will route
                    audits through your live Node.js server.
                  </p>
                </div>

                {/* Quick Connection Presets */}
                <div className="space-y-2">
                  <span className="block text-xs font-medium text-[#CBD5E1]">
                    Quick Connection Presets:
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <button
                      type="button"
                      onClick={() => handleSelectPreset('')}
                      className={`text-left rounded-lg border p-3 transition-all ${
                        !inputUrl.trim()
                          ? 'border-[#38BDF8]/50 bg-[#0284C7]/15'
                          : 'border-white/[0.08] bg-white/[0.02] hover:border-white/[0.2]'
                      }`}
                    >
                      <div className="text-xs font-semibold text-white">
                        Automatic / Same-Origin Server
                      </div>
                      <div className="text-[11px] text-[#94A3B8] mt-0.5 font-mono">
                        /api/audit/run (Default for Render & Local Engine)
                      </div>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleSelectPreset('http://localhost:3000')}
                      className={`text-left rounded-lg border p-3 transition-all ${
                        inputUrl.trim() === 'http://localhost:3000'
                          ? 'border-[#38BDF8]/50 bg-[#0284C7]/15'
                          : 'border-white/[0.08] bg-white/[0.02] hover:border-white/[0.2]'
                      }`}
                    >
                      <div className="text-xs font-semibold text-white">
                        Local Node.js Dev Engine
                      </div>
                      <div className="text-[11px] text-[#94A3B8] mt-0.5 font-mono">
                        http://localhost:3000 (npm run engine)
                      </div>
                    </button>
                  </div>
                </div>

                {/* 100% Private Local Engine Quickstart Card */}
                <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/[0.05] p-3.5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                      <Terminal className="h-3.5 w-3.5" />
                      <span>100% Private Local Audit Daemon (0 Cloud Accounts)</span>
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        handleCopy('local-cmd', 'npm run engine')
                      }
                      className="inline-flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-mono text-emerald-300 hover:bg-emerald-500/20"
                    >
                      {copiedKey === 'local-cmd' ? (
                        <>
                          <Check className="h-3 w-3" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>Copy Command</span>
                        </>
                      )}
                    </button>
                  </div>
                  <p className="text-xs text-[#CBD5E1] leading-relaxed">
                    Clone your repository on your computer and run{' '}
                    <code className="font-mono text-emerald-300">npm run engine</code>. The server
                    starts on <code className="font-mono text-white">localhost:3000</code>. Then select
                    the preset above. Your browser will execute raw socket audits through your local
                    daemon with zero external cloud dependencies.
                  </p>
                </div>
              </form>

              {/* Engine Capability Matrix */}
              <div className="border-t border-white/[0.08] pt-5 space-y-3">
                <h3 className="text-xs font-semibold text-white">
                  Why Fullstack Node.js Beats Static Hosting
                </h3>
                <div className="overflow-x-auto rounded-xl border border-white/[0.08]">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-white/[0.04] text-[#CBD5E1] border-b border-white/[0.08]">
                      <tr>
                        <th className="py-2.5 px-3.5 font-semibold">Security Audit Capability</th>
                        <th className="py-2.5 px-3.5 font-semibold">
                          Fullstack Node Engine (Render / Local)
                        </th>
                        <th className="py-2.5 px-3.5 font-semibold">
                          Static Only (GitHub Pages Alone)
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/[0.06] text-[#CBD5E1]">
                      <tr>
                        <td className="py-2.5 px-3.5 font-medium text-white">
                          Third-Party Raw HTTP Headers (e.g. YouTube, Google)
                        </td>
                        <td className="py-2.5 px-3.5 text-emerald-300 font-medium">
                          100% Genuine (Direct OS Sockets)
                        </td>
                        <td className="py-2.5 px-3.5 text-amber-300">
                          Blocked by Browser CORS Sandbox
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 px-3.5 font-medium text-white">
                          HTTP-to-HTTPS Redirect & Set-Cookie Capture
                        </td>
                        <td className="py-2.5 px-3.5 text-emerald-300 font-medium">
                          100% Genuine (Raw Hop Inspection)
                        </td>
                        <td className="py-2.5 px-3.5 text-amber-300">
                          Forbidden by Fetch Spec (Set-Cookie hidden)
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 px-3.5 font-medium text-white">
                          CORS Origin Reflection & GraphQL Probing
                        </td>
                        <td className="py-2.5 px-3.5 text-emerald-300 font-medium">
                          100% Genuine (Custom Origin Header)
                        </td>
                        <td className="py-2.5 px-3.5 text-amber-300">
                          Browser Overrides Origin Header
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 px-3.5 font-medium text-white">
                          OSV.dev Dependency CVEs, JWT Cracking & Code SAST
                        </td>
                        <td className="py-2.5 px-3.5 text-emerald-300 font-medium">
                          100% Genuine
                        </td>
                        <td className="py-2.5 px-3.5 text-emerald-300 font-medium">
                          100% Genuine
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            /* Tab 2: Free Fullstack Hosting Guide */
            <div className="space-y-6">
              <div className="rounded-xl border border-[#38BDF8]/30 bg-[#0284C7]/10 p-4 space-y-2">
                <div className="text-xs font-bold text-[#38BDF8]">
                  Recommended Architecture: Render Free Web Service ($0/month, No Credit Card)
                </div>
                <p className="text-xs text-[#E2E8F0] leading-relaxed">
                  Your repository now includes both <code className="font-mono text-[#38BDF8]">render.yaml</code> and{' '}
                  <code className="font-mono text-[#38BDF8]">Dockerfile</code>. Deploying on Render
                  runs the exact same <code className="font-mono text-[#38BDF8]">server.ts</code>{' '}
                  Node.js engine—hosting both your React UI and live backend on a
                  single <code className="font-mono">https://*.onrender.com</code> URL with
                  automatic deploys on every <code className="font-mono">git push</code>.
                </p>
              </div>

              {/* 3-Step Setup Walkthrough */}
              <div className="space-y-4">
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">
                      01. Push the Updated Codebase to Your GitHub Repository
                    </span>
                    <span className="text-[11px] font-mono text-[#94A3B8]">
                      Includes render.yaml + Dockerfile + CORS API
                    </span>
                  </div>
                  <p className="text-xs text-[#CBD5E1]">
                    Commit and push this project to your GitHub repo (e.g.{' '}
                    <code className="font-mono text-white">tmvoid/Sentinel-AppSec</code>). Your
                    existing GitHub Actions workflow will automatically update GitHub Pages, and
                    Render will read <code className="font-mono text-white">render.yaml</code>.
                  </p>
                </div>

                <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-4 space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-white">
                      02. Connect Your Repo on Render.com (Free Tier)
                    </span>
                    <a
                      href="https://dashboard.render.com/select-repo?type=web"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-semibold text-[#38BDF8] hover:underline"
                    >
                      <span>Open Render Dashboard</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                  <ul className="space-y-1.5 text-xs text-[#CBD5E1] list-disc list-inside">
                    <li>
                      Sign in to <strong>Render.com</strong> with your GitHub account (100% free, no
                      card required for Free Web Services).
                    </li>
                    <li>
                      Click <strong>New +</strong> → <strong>Web Service</strong> and select your{' '}
                      <code className="font-mono text-white">Sentinel-AppSec</code> repository.
                    </li>
                    <li>
                      Use these exact settings (or click <strong>New → Blueprint</strong> to load{' '}
                      <code className="font-mono text-white">render.yaml</code> automatically):
                    </li>
                  </ul>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1 font-mono text-[11px]">
                    <div className="rounded-lg border border-white/[0.08] bg-black/40 p-2.5">
                      <div className="text-[#94A3B8]">Build Command</div>
                      <div className="text-emerald-300 mt-0.5 break-all">
                        npm install --legacy-peer-deps && npm run build
                      </div>
                    </div>
                    <div className="rounded-lg border border-white/[0.08] bg-black/40 p-2.5">
                      <div className="text-[#94A3B8]">Start Command</div>
                      <div className="text-emerald-300 mt-0.5">npx tsx server.ts</div>
                    </div>
                    <div className="rounded-lg border border-white/[0.08] bg-black/40 p-2.5">
                      <div className="text-[#94A3B8]">Instance Type</div>
                      <div className="text-emerald-300 mt-0.5">Free ($0 / month)</div>
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-4 space-y-2">
                  <div className="text-xs font-bold text-white">
                    03. Use Directly or Pair with GitHub Pages
                  </div>
                  <p className="text-xs text-[#CBD5E1] leading-relaxed">
                    Once Render finishes building (~90 seconds), you get a live URL like{' '}
                    <code className="font-mono text-[#38BDF8]">
                      https://sentinel-appsec.onrender.com
                    </code>
                    :
                  </p>
                  <ul className="space-y-1 text-xs text-[#CBD5E1] list-disc list-inside">
                    <li>
                      <strong>All-in-One Mode:</strong> Visit your{' '}
                      <code className="font-mono text-white">onrender.com</code> URL directly—both
                      the UI and genuine Node.js engine work out of the box!
                    </li>
                    <li>
                      <strong>GitHub Pages Hybrid Mode:</strong> Open{' '}
                      <code className="font-mono text-white">
                        tmvoid.github.io/Sentinel-AppSec
                      </code>
                      , click <strong>Live Engine Connection</strong>, and paste your{' '}
                      <code className="font-mono text-white">onrender.com</code> URL so GitHub Pages
                      uses your real Node backend too.
                    </li>
                  </ul>
                </div>
              </div>

              {/* Included render.yaml preview */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-xs font-semibold text-white">
                    <Terminal className="h-3.5 w-3.5 text-[#38BDF8]" />
                    <span>Included render.yaml Blueprint (Already Added to Root)</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('render-yaml', RENDER_YAML_SNIPPET)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.12] bg-white/[0.04] px-2.5 py-1 text-[11px] font-medium text-[#E2E8F0] hover:bg-white/[0.1]"
                  >
                    {copiedKey === 'render-yaml' ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" />
                        <span className="text-emerald-300">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy YAML</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="rounded-xl border border-white/[0.08] bg-black/50 p-3.5 text-[11px] font-mono text-[#CBD5E1] overflow-x-auto leading-relaxed">
                  {RENDER_YAML_SNIPPET}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-white/[0.08] bg-[#050912] px-6 py-3.5">
          <div className="text-[11px] text-[#94A3B8]">
            Engine Mode:{' '}
            <span className="font-semibold text-white">
              {connectionState.mode === 'same-origin-node'
                ? 'Local On-Device Node.js (Direct Sockets)'
                : connectionState.mode === 'remote-node'
                ? `Remote Node Engine (${connectionState.customBackendUrl})`
                : 'Static Preview & UI Showcase (Demo Mode)'}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-white/[0.15] bg-white/[0.05] px-4 py-1.5 text-xs font-semibold text-white hover:bg-white/[0.1] transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
