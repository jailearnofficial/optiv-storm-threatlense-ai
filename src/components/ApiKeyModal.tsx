import React, { useState, useEffect } from 'react';
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  ShieldCheck,
  AlertCircle,
  Calendar,
  Lock,
  RefreshCw,
  X,
  Code2,
  Sparkles,
  ShieldAlert
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.js';

export interface ApiKeyItem {
  id: string;
  name: string;
  keyMasked: string;
  fullKey?: string;
  createdAt: string;
  expiresAt: string;
  scope: string;
  status: 'active' | 'revoked';
}

interface ApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ApiKeyModal: React.FC<ApiKeyModalProps> = ({ isOpen, onClose }) => {
  const { user, isAdmin } = useAuth();
  const [keys, setKeys] = useState<ApiKeyItem[]>(() => {
    try {
      const stored = localStorage.getItem('threatlense_admin_api_keys');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {}
    // Default initial key for admin
    return [
      {
        id: 'key-init-1',
        name: 'Default SOC Telemetry Ingest',
        keyMasked: 'tl_live_4f9a••••••••••••••••••••••••3e81',
        createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
        expiresAt: 'Never',
        scope: 'Ingest & Triage',
        status: 'active'
      }
    ];
  });

  const [isCreating, setIsCreating] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [keyScope, setKeyScope] = useState('Ingest & Triage');
  const [keyExpiry, setKeyExpiry] = useState('90 Days');
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem('threatlense_admin_api_keys', JSON.stringify(keys));
    } catch {}
  }, [keys]);

  if (!isOpen) return null;

  // Enforce RBAC guard
  if (!isAdmin) {
    return (
      <div className="fixed inset-0 z-[99999] bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-white dark:bg-slate-900 border border-rose-500/50 rounded-2xl p-6 shadow-2xl text-center">
          <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-500 mx-auto flex items-center justify-center mb-4">
            <Lock className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
            Access Restricted (RBAC Enforced)
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-2 leading-relaxed">
            API Key generation and management is restricted to authorized Administrator (Jai Kumar Singh P via Sign in with Google).
          </p>
          <button
            onClick={onClose}
            className="mt-5 px-4 py-2 rounded-xl bg-slate-800 text-slate-100 text-xs font-semibold hover:bg-slate-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  const handleCreateKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyName.trim()) return;

    // Generate random secure token
    const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const fullKey = `tl_live_${randomHex}`;
    const masked = `tl_live_${randomHex.slice(0, 4)}••••••••••••••••••••••••${randomHex.slice(-4)}`;

    let expiresAt = 'Never';
    if (keyExpiry === '30 Days') {
      expiresAt = new Date(Date.now() + 86400000 * 30).toLocaleDateString();
    } else if (keyExpiry === '90 Days') {
      expiresAt = new Date(Date.now() + 86400000 * 90).toLocaleDateString();
    } else if (keyExpiry === '1 Year') {
      expiresAt = new Date(Date.now() + 86400000 * 365).toLocaleDateString();
    }

    const newKeyItem: ApiKeyItem = {
      id: `key-${Date.now()}`,
      name: keyName.trim(),
      keyMasked: masked,
      fullKey,
      createdAt: new Date().toISOString(),
      expiresAt,
      scope: keyScope,
      status: 'active'
    };

    setKeys([newKeyItem, ...keys]);
    setNewlyCreatedKey(fullKey);
    setKeyName('');
    setIsCreating(false);
  };

  const handleRevokeKey = (id: string) => {
    setKeys(
      keys.map((k) =>
        k.id === id ? { ...k, status: k.status === 'active' ? 'revoked' : 'active' } : k
      )
    );
  };

  const handleDeleteKey = (id: string) => {
    setKeys(keys.filter((k) => k.id !== id));
  };

  const handleCopy = (text: string, identifier: string) => {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(identifier);
      setTimeout(() => setCopiedKey(null), 2500);
    }
  };

  return (
    <div className="fixed inset-0 z-[99999] bg-slate-950/70 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
      <div className="relative w-full max-w-2xl bg-white dark:bg-[#0B1324] border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8 animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-violet-500/10 dark:bg-violet-500/20 border border-violet-500/30 flex items-center justify-center text-violet-500">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  SOC API Keys & Ingestion Webhooks
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 flex items-center gap-1 font-semibold">
                  <ShieldCheck className="w-3 h-3" />
                  Admin Authorized
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Generate secure bearer tokens for automated SIEM pipelines and headless triage
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {/* One-time Key Creation Notification */}
          {newlyCreatedKey && (
            <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-500/40 space-y-2.5">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-300 font-bold text-xs">
                  <Sparkles className="w-4 h-4 text-emerald-500" />
                  <span>API Key Generated Successfully</span>
                </div>
                <button
                  onClick={() => setNewlyCreatedKey(null)}
                  className="text-emerald-600 dark:text-emerald-400 hover:underline text-[11px] font-mono"
                >
                  Dismiss
                </button>
              </div>
              <p className="text-xs text-emerald-800 dark:text-emerald-200/90 leading-relaxed">
                Please copy your secret key now. For your security, the secret token will not be displayed again.
              </p>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={newlyCreatedKey}
                  className="flex-1 px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-emerald-500/40 font-mono text-xs text-emerald-600 dark:text-emerald-400 font-semibold select-all"
                />
                <button
                  onClick={() => handleCopy(newlyCreatedKey, 'new-key')}
                  className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shrink-0"
                >
                  {copiedKey === 'new-key' ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Key</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}

          {/* Action Row: Create Key Button */}
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-700 dark:text-slate-300 font-mono uppercase tracking-wider">
              Active Ingestion Keys ({keys.length})
            </span>
            {!isCreating && (
              <button
                onClick={() => setIsCreating(true)}
                className="px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create New API Key</span>
              </button>
            )}
          </div>

          {/* Create Form */}
          {isCreating && (
            <form
              onSubmit={handleCreateKey}
              className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  Configure New Ingestion API Key
                </span>
                <button
                  type="button"
                  onClick={() => setIsCreating(false)}
                  className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  Cancel
                </button>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Key Name / Purpose <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Splunk Enterprise Forwarder, XSOAR Ingestion Pipeline"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 text-xs focus:ring-2 focus:ring-violet-500 outline-none"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Permission Scope
                  </label>
                  <select
                    value={keyScope}
                    onChange={(e) => setKeyScope(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 text-xs focus:ring-2 focus:ring-violet-500 outline-none"
                  >
                    <option value="Ingest & Triage">Ingest & Triage (Default)</option>
                    <option value="Full SOC Access">Full SOC Access (Read/Write)</option>
                    <option value="Read-Only Intelligence">Read-Only Intelligence</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Expiration
                  </label>
                  <select
                    value={keyExpiry}
                    onChange={(e) => setKeyExpiry(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 text-xs focus:ring-2 focus:ring-violet-500 outline-none"
                  >
                    <option value="30 Days">30 Days</option>
                    <option value="90 Days">90 Days</option>
                    <option value="1 Year">1 Year</option>
                    <option value="Never">Never (Permanent)</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setIsCreating(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold transition-colors shadow-sm"
                >
                  Generate Key
                </button>
              </div>
            </form>
          )}

          {/* Keys List */}
          <div className="space-y-2.5">
            {keys.map((k) => (
              <div
                key={k.id}
                className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                      {k.name}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-semibold ${
                        k.status === 'active'
                          ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                      }`}
                    >
                      {k.status.toUpperCase()}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                      {k.scope}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                      {k.keyMasked}
                    </span>
                  </div>

                  <div className="text-[11px] text-slate-400 font-mono flex items-center gap-3">
                    <span>Created: {new Date(k.createdAt).toLocaleDateString()}</span>
                    <span>Expires: {k.expiresAt}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center">
                  <button
                    onClick={() => handleRevokeKey(k.id)}
                    className="px-2.5 py-1 rounded-lg border border-slate-300 dark:border-slate-700 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors"
                  >
                    {k.status === 'active' ? 'Revoke' : 'Reactivate'}
                  </button>
                  <button
                    onClick={() => handleDeleteKey(k.id)}
                    className="p-1 rounded-lg text-slate-400 hover:text-rose-500 hover:bg-rose-500/10 transition-colors"
                    title="Delete Key Record"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Quick Integration Guide */}
          <div className="p-4 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-800 dark:text-slate-200">
              <Code2 className="w-4 h-4 text-violet-500" />
              <span>Headless Ingest Example (cURL)</span>
            </div>
            <pre className="p-3 rounded-lg bg-slate-950 text-slate-200 font-mono text-[11px] overflow-x-auto">
{`curl -X POST https://ais-dev-...run.app/api/triage \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"indicator": "194.26.29.112", "type": "ip"}'`}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 flex items-center justify-between">
          <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
            Signed in as: <span className="font-semibold text-violet-500">{user?.displayName || user?.email}</span> (Admin)
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
