import React, { useEffect, useState, useCallback } from 'react';
import {
  Server, Plus, Upload, Search, CheckCircle,
  XCircle, HelpCircle, Globe, ExternalLink, FlaskConical,
  RefreshCw, X, AlertCircle,
} from 'lucide-react';
import { apiErrorMessage, assetsApi } from '../lib/api';
import { useSession } from '../lib/session';
import NoProject from '../components/NoProject';
import type { Asset, AssetStatus } from '../types';

// ============================================================
// Constants
// ============================================================


// ============================================================
// Sub-components
// ============================================================

function StatusBadge({ status }: { status: AssetStatus }) {
  if (status === 'live') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/25">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]" />
        Live
      </span>
    );
  }
  if (status === 'down') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium bg-red-500/15 text-red-400 border border-red-500/25">
        <span className="w-1.5 h-1.5 rounded-full bg-red-400 shadow-[0_0_6px_rgba(239,68,68,0.6)]" />
        Down
      </span>
    );
  }
  if (status === 'out_of_scope') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium bg-slate-500/15 text-slate-400 border border-slate-500/25">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
        Out of Scope
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium bg-yellow-500/15 text-yellow-400 border border-yellow-500/25">
      <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shadow-[0_0_6px_rgba(234,179,8,0.6)]" />
      Unknown
    </span>
  );
}

function HttpStatusBadge({ code }: { code?: number }) {
  if (!code) return <span className="text-slate-600 text-xs">—</span>;
  const color =
    code < 300 ? 'text-emerald-400' :
    code < 400 ? 'text-blue-400' :
    code < 500 ? 'text-yellow-400' : 'text-red-400';
  return <span className={`font-mono text-xs font-semibold ${color}`}>{code}</span>;
}

function AssetTypeIcon({ type }: { type: string }) {
  if (type === 'api') return <Globe size={14} className="text-cyber-blue" />;
  return <Server size={14} className="text-slate-400" />;
}

function formatRelativeTime(dateStr?: string): string {
  if (!dateStr) return '—';
  const diff = Date.now() - new Date(dateStr).getTime();
  const hours = Math.floor(diff / 3600000);
  if (hours < 1) return 'Just now';
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// ============================================================
// Import Modal
// ============================================================

interface ImportModalProps {
  onClose: () => void;
  onImport: (json: string) => Promise<void>;
}

function ImportModal({ onClose, onImport }: ImportModalProps) {
  const [jsonText, setJsonText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const EXAMPLE = JSON.stringify([
    {
      hostname: 'example.com',
      asset_type: 'web',
      status: 'live',
      ip_addresses: ['1.2.3.4'],
      technologies: ['nginx'],
      http_status_code: 200,
      discovery_source: 'manual',
    }
  ], null, 2);

  async function handleSubmit() {
    setError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      setError('Invalid JSON — please check your syntax.');
      return;
    }
    if (!Array.isArray(parsed)) {
      setError('JSON must be an array of asset objects.');
      return;
    }
    setLoading(true);
    try {
      await onImport(jsonText);
      onClose();
    } catch (err: unknown) {
      setError(apiErrorMessage(err, 'Import failed.'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl card p-0 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-cyber-blue/10">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyber-orange/15 flex items-center justify-center">
              <Upload size={15} className="text-cyber-orange" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-200">Import Assets from JSON</h2>
              <p className="text-xs text-slate-500 mt-0.5">Paste a JSON array of asset objects</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-navy-700 text-slate-500 hover:text-slate-300 transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {/* Example */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-slate-400">JSON Input</span>
              <button
                onClick={() => setJsonText(EXAMPLE)}
                className="text-xs text-cyber-blue hover:text-cyber-blue-bright transition-colors"
              >
                Load example
              </button>
            </div>
            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              placeholder={EXAMPLE}
              rows={12}
              className="input font-mono text-xs resize-none leading-relaxed"
              spellCheck={false}
            />
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">
              <AlertCircle size={14} className="mt-0.5 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* Schema hint */}
          <div className="text-xs text-slate-600 space-y-1">
            <p className="font-medium text-slate-500">Required fields per asset object:</p>
            <code className="text-slate-500">hostname and asset_type. Status is assigned by the server.</code>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-cyber-blue/10">
          <button onClick={onClose} className="btn-secondary">Cancel</button>
          <button
            onClick={handleSubmit}
            disabled={loading || !jsonText.trim()}
            className="btn-orange flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Importing...
              </>
            ) : (
              <>
                <Upload size={14} />
                Import Assets
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// Main Assets Page
// ============================================================

type StatusFilter = 'all' | AssetStatus;

export default function AssetsPage() {
  const { projectId } = useSession();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [search, setSearch] = useState('');
  const [showImport, setShowImport] = useState(false);

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = {};
      if (statusFilter !== 'all') params.status = statusFilter;
      if (search.trim()) params.search = search.trim();
      if (!projectId) { setAssets([]); return; }
      const res = await assetsApi.list(projectId, params);
      setAssets(res.data);
    } catch {
      setError('Could not load assets.');
      setAssets([]);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, search, projectId]);

  useEffect(() => {
    const timer = setTimeout(() => { fetchAssets(); }, search ? 400 : 0);
    return () => clearTimeout(timer);
  }, [fetchAssets, search]);

  async function handleImport(jsonText: string) {
    const parsed = JSON.parse(jsonText);
    if (!projectId) return;
    await assetsApi.import({ project_id: projectId, assets: parsed });
    fetchAssets();
  }

  const filtered = assets.filter((a) => {
    const matchStatus = statusFilter === 'all' || a.status === statusFilter;
    const q = search.toLowerCase();
    const matchSearch = !q ||
      a.hostname.toLowerCase().includes(q) ||
      (a.technologies ?? []).some(t => t.toLowerCase().includes(q)) ||
      (a.ip_addresses ?? []).some(ip => ip.includes(q));
    return matchStatus && matchSearch;
  });

  const statusTabs: { label: string; value: StatusFilter; icon: React.ReactNode }[] = [
    { label: 'All', value: 'all', icon: null },
    { label: 'Live', value: 'live', icon: <CheckCircle size={12} /> },
    { label: 'Down', value: 'down', icon: <XCircle size={12} /> },
    { label: 'Unknown', value: 'unknown', icon: <HelpCircle size={12} /> },
  ];

  if (!projectId) return <NoProject />;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title flex items-center gap-2">
            <Server size={22} className="text-cyber-blue" />
            Assets
          </h1>
          <p className="page-subtitle">
            Discovered attack surface — {assets.length} asset{assets.length !== 1 ? 's' : ''} total
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowImport(true)}
            className="btn-secondary flex items-center gap-2"
          >
            <Upload size={15} />
            Import JSON
          </button>
          <button type="button" disabled title="Single-asset entry is not available. Use Import JSON." className="btn-primary flex items-center gap-2 opacity-60 cursor-not-allowed">
            <Plus size={15} />
            Add Asset unavailable
          </button>
        </div>
      </div>

      {/* Demo / error banner */}
      {error && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-xs text-yellow-400">
          <AlertCircle size={13} />
          {error}
          <div className="ml-auto demo-banner !py-1">
            <FlaskConical size={11} />
            Demo Data
          </div>
        </div>
      )}

      {/* Filter bar */}
      <div className="card p-4 flex flex-col sm:flex-row items-start sm:items-center gap-3">
        {/* Status tabs */}
        <div className="flex items-center gap-1 bg-navy-900 p-1 rounded-lg flex-shrink-0">
          {statusTabs.map((tab) => (
            <button
              key={tab.value}
              onClick={() => setStatusFilter(tab.value)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${
                statusFilter === tab.value
                  ? 'bg-cyber-blue text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.icon}
              {tab.label}
              {tab.value !== 'all' && (
                <span className={`ml-0.5 text-xs opacity-70`}>
                  ({assets.filter(a => a.status === tab.value).length})
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-0">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search hostname, IP, technology…"
            className="input pl-9 h-9 text-xs"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <X size={13} />
            </button>
          )}
        </div>

        {/* Refresh */}
        <button
          onClick={fetchAssets}
          disabled={loading}
          className="btn-secondary flex items-center gap-1.5 !py-1.5 !px-3 text-xs flex-shrink-0"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Assets table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-12 flex flex-col items-center gap-3">
            <div className="w-8 h-8 border-2 border-cyber-blue/30 border-t-cyber-blue rounded-full animate-spin" />
            <p className="text-sm text-slate-500">Loading assets…</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-16 flex flex-col items-center gap-4 text-center">
            <div className="w-14 h-14 rounded-2xl bg-navy-700 flex items-center justify-center">
              <Server size={26} className="text-slate-500" />
            </div>
            <div>
              <p className="text-sm font-medium text-slate-300 mb-1">No assets found</p>
              <p className="text-xs text-slate-500 max-w-xs">
                {search || statusFilter !== 'all'
                  ? 'Try adjusting your filters or search query.'
                  : 'Start a scan or import assets to populate your attack surface map.'}
              </p>
            </div>
            {!search && statusFilter === 'all' && (
              <div className="flex items-center gap-2 mt-2">
                <button onClick={() => setShowImport(true)} className="btn-secondary text-xs flex items-center gap-1.5">
                  <Upload size={12} /> Import JSON
                </button>
                <span className="text-slate-600 text-xs">or</span>
                <span className="text-xs text-slate-500">Single-asset entry is not available.</span>
              </div>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>IP Address(es)</th>
                  <th>Technologies</th>
                  <th>HTTP</th>
                  <th>Source</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((asset) => (
                  <tr key={asset.id}>
                    {/* Hostname */}
                    <td>
                      <div className="flex flex-col gap-0.5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium text-slate-200 text-xs">{asset.hostname}</span>
                          {asset.is_demo && (
                            <span className="inline-flex items-center gap-0.5 px-1 py-0.5 rounded text-purple-400 bg-purple-500/10 border border-purple-500/20 text-xs">
                              <FlaskConical size={9} />
                            </span>
                          )}
                          <a
                            href={`https://${asset.hostname}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-slate-600 hover:text-cyber-blue transition-colors"
                          >
                            <ExternalLink size={11} />
                          </a>
                        </div>
                        {asset.title && (
                          <span className="text-xs text-slate-500">{asset.title}</span>
                        )}
                      </div>
                    </td>

                    {/* Type */}
                    <td>
                      <div className="flex items-center gap-1.5">
                        <AssetTypeIcon type={asset.asset_type} />
                        <span className="text-xs text-slate-400 capitalize">{asset.asset_type}</span>
                      </div>
                    </td>

                    {/* Status */}
                    <td>
                      <StatusBadge status={asset.status} />
                    </td>

                    {/* IPs */}
                    <td>
                      <div className="flex flex-col gap-0.5">
                        {(asset.ip_addresses ?? []).length > 0
                          ? (asset.ip_addresses ?? []).map((ip) => (
                              <span key={ip} className="font-mono text-xs text-slate-400">{ip}</span>
                            ))
                          : <span className="text-slate-600 text-xs">—</span>
                        }
                      </div>
                    </td>

                    {/* Technologies */}
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {(asset.technologies ?? []).length > 0
                          ? (asset.technologies ?? []).slice(0, 3).map((tech) => (
                              <span key={tech} className="px-1.5 py-0.5 rounded bg-navy-700 text-slate-400 text-xs border border-cyber-blue/10">
                                {tech}
                              </span>
                            ))
                          : <span className="text-slate-600 text-xs">—</span>
                        }
                        {(asset.technologies ?? []).length > 3 && (
                          <span className="px-1.5 py-0.5 rounded bg-navy-700 text-slate-500 text-xs border border-cyber-blue/10">
                            +{(asset.technologies ?? []).length - 3}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* HTTP status */}
                    <td>
                      <HttpStatusBadge code={asset.http_status_code} />
                    </td>

                    {/* Discovery source */}
                    <td>
                      <span className="font-mono text-xs text-slate-500">
                        {asset.discovery_source ?? '—'}
                      </span>
                    </td>

                    {/* Last seen */}
                    <td>
                      <span className="text-xs text-slate-500">
                        {formatRelativeTime(asset.last_seen)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Table footer */}
        {!loading && filtered.length > 0 && (
          <div className="px-4 py-3 border-t border-cyber-blue/8 flex items-center justify-between">
            <span className="text-xs text-slate-500">
              Showing {filtered.length} of {assets.length} assets
            </span>
            <div className="flex items-center gap-4 text-xs text-slate-500">
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                {assets.filter(a => a.status === 'live').length} live
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                {assets.filter(a => a.status === 'down').length} down
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                {assets.filter(a => a.status === 'unknown').length} unknown
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Import modal */}
      {showImport && (
        <ImportModal
          onClose={() => setShowImport(false)}
          onImport={handleImport}
        />
      )}
    </div>
  );
}
