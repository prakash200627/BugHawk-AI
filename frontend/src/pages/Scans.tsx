import React, { useEffect, useState, useCallback } from 'react';
import {
  ScanLine, Plus, Play, Clock, CheckCircle, XCircle,
  Loader2, Shield, ChevronRight, FlaskConical, AlertTriangle,
  Terminal, RefreshCw
} from 'lucide-react';
import { apiErrorMessage, scansApi } from '../lib/api';
import { useSession } from '../lib/session';
import NoProject from '../components/NoProject';
import type { ScanJob } from '../types';
import clsx from 'clsx';


const SCAN_MODULES = [
  { id: 'subfinder', label: 'Subfinder', desc: 'Passive subdomain discovery. Runs only as its own job.', badge: 'passive', runs: true },
  { id: 'httpx', label: 'httpx', desc: 'HTTP service discovery for stored assets on ports 80 and 443. Runs only as its own job.', badge: 'HTTP discovery', runs: true },
  { id: 'nuclei', label: 'Nuclei', desc: 'Vulnerability detection with five reviewed header checks. It scans only HTTPX-verified assets, as its own job. Exploit, fuzz, brute-force, and out-of-band templates are not included.', badge: 'vulnerability detection', runs: true },
  { id: 'semgrep', label: 'Semgrep', desc: 'Static source analysis with three reviewed rules. A job fails until this project has an uploaded source archive. It does not scan the server disk or clone a repository.', badge: 'source analysis', runs: true },
  { id: 'zap', label: 'ZAP', desc: 'Passive baseline of HTTPX-verified origins on ports 80 and 443. No active scan, spider, or fuzzer. Results are potential issues, not confirmed vulnerabilities.', badge: 'passive baseline', runs: true },
];

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; icon: React.ReactNode; label: string }> = {
    pending:   { cls: 'badge-info',    icon: <Clock size={10} />,                                label: 'Pending' },
    running:   { cls: 'badge-low',     icon: <Loader2 size={10} className="animate-spin" />,     label: 'Running' },
    completed: { cls: 'badge-success', icon: <CheckCircle size={10} />,                          label: 'Completed' },
    failed:    { cls: 'bg-red-500/20 text-red-400 border border-red-500/30', icon: <XCircle size={10} />, label: 'Failed' },
    cancelled: { cls: 'badge-info',    icon: <XCircle size={10} />,                              label: 'Cancelled' },
  };
  const item = map[status] || map.pending;
  return (
    <span className={`badge flex items-center gap-1 ${item.cls}`}>
      {item.icon}{item.label}
    </span>
  );
}

function NewScanModal({ onClose, onCreated, projectId }: { onClose: () => void; onCreated: () => void; projectId: string }) {
  const [form, setForm] = useState({ name: '', target: '', modules: ['subfinder'] });
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const toggleModule = (id: string) => {
    setForm(prev => {
      if (id === 'subfinder' || id === 'httpx' || id === 'nuclei' || id === 'semgrep' || id === 'zap') {
        const onlyThis = prev.modules.length === 1 && prev.modules[0] === id;
        return { ...prev, modules: onlyThis ? [] : [id] };
      }
      const storedOnly = prev.modules.filter(module => !['subfinder', 'httpx', 'nuclei', 'semgrep', 'zap'].includes(module));
      const modules = storedOnly.includes(id)
        ? storedOnly.filter(module => module !== id)
        : [...storedOnly, id];
      return { ...prev, modules };
    });
  };

  const submit = async () => {
    if (!form.name.trim() || !form.target.trim()) { setError('Name and target are required.'); return; }
    setCreating(true); setError('');
    try {
      await scansApi.create({ project_id: projectId, name: form.name, target: form.target, modules: form.modules });
      onCreated(); onClose();
    } catch (e: unknown) {
      setError(apiErrorMessage(e, 'The scan job was not stored.'));
    } finally { setCreating(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-lg bg-navy-800 border border-cyber-blue/20 rounded-2xl shadow-2xl animate-fade-in" onClick={e => e.stopPropagation()}>
        <div className="p-5 border-b border-cyber-blue/10 flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2"><Play size={16} className="text-cyber-blue" /> New Scan Job</h2>
            <p className="text-xs text-slate-400 mt-0.5">Each scanner runs as its own job. Semgrep needs a source archive that this project does not collect yet.</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200"><XCircle size={18} /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Scan Name</label>
            <input type="text" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="e.g. Demo App — Full Scan" className="input text-sm" id="scan-name-input" />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Target</label>
            <div className="relative">
              <Shield size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input type="text" value={form.target} onChange={e => setForm(p => ({ ...p, target: e.target.value }))} placeholder="demo-app.internal" className="input pl-9 text-sm font-mono" id="scan-target-input" />
            </div>
            <p className="text-xs text-slate-500 mt-1">Use an authorized domain. Subfinder looks up names. httpx probes stored assets. Nuclei and ZAP use HTTPX-verified origins. Semgrep does not scan a URL.</p>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-2">Scan Modules</label>
            <div className="space-y-2">
              {SCAN_MODULES.map(mod => (
                <label key={mod.id} className={clsx('flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all', form.modules.includes(mod.id) ? 'bg-cyber-blue/10 border-cyber-blue/30' : 'bg-navy-900 border-navy-700 hover:border-cyber-blue/20')}>
                  <input type="checkbox" checked={form.modules.includes(mod.id)} onChange={() => toggleModule(mod.id)} className="accent-cyber-blue" id={`module-${mod.id}`} />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-200 font-mono">{mod.label}</span>
                      <span className={clsx('text-xs px-1.5 py-0.5 rounded font-medium', mod.runs ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-500/20 text-slate-400')}>{mod.badge}</span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">{mod.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
          {error && <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2"><AlertTriangle size={12} />{error}</div>}
        </div>
        <div className="p-5 border-t border-cyber-blue/10 flex justify-end gap-3">
          <button onClick={onClose} className="btn-secondary">Cancel</button>
          <button onClick={submit} disabled={creating} className="btn-primary flex items-center gap-2" id="create-scan-btn">
            {creating ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            {creating ? 'Saving...' : 'Save scan job'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ScansPage() {
  const { projectId } = useSession();
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [error, setError] = useState('');

  const fetchScans = useCallback(async () => {
    if (!projectId) { setScans([]); setLoading(false); return; }
    try {
      const res = await scansApi.list(projectId);
      setScans(res.data); setError('');
    } catch { setError('Could not load scans. Ensure backend is running.'); }
    finally { setLoading(false); }
  }, [projectId]);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  useEffect(() => {
    const waiting = scans.some(scan => (
      scan.modules.length === 1
      && ['subfinder', 'httpx', 'nuclei', 'semgrep', 'zap'].includes(scan.modules[0])
      && (scan.status === 'pending' || scan.status === 'running')
    ));
    if (!waiting) return undefined;
    const timer = window.setInterval(fetchScans, 5000);
    return () => window.clearInterval(timer);
  }, [scans, fetchScans]);

  if (!projectId) return <NoProject />;

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="page-header">
        <div>
          <div className="demo-banner mb-3"><FlaskConical size={12} />Scanners run in a separate worker. Semgrep reports that no source archive is stored. ZAP is a passive baseline. Pending means the job has not started.</div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500"><Shield size={12} className="text-cyber-green" />Scope Guardian checks the target before a job is stored.</div>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchScans} className="btn-secondary flex items-center gap-1.5" id="refresh-scans-btn"><RefreshCw size={14} />Refresh</button>
          <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2" id="new-scan-btn"><Plus size={16} />New Scan</button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {SCAN_MODULES.map(mod => (
          <div key={mod.id} className="card p-4">
            <div className="flex items-center gap-2 mb-2"><Terminal size={14} className="text-cyber-blue" /><span className="text-sm font-semibold text-slate-200 font-mono">{mod.label}</span></div>
            <p className="text-xs text-slate-500">{mod.desc}</p>
            <div className={clsx('mt-2 text-xs px-2 py-0.5 rounded w-fit font-medium', mod.runs ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-500/20 text-slate-400')}>{mod.badge}</div>
          </div>
        ))}
      </div>

      <div className="card overflow-hidden">
        <div className="flex items-center justify-between p-5 border-b border-cyber-blue/10">
          <h3 className="text-sm font-semibold text-slate-200">Scan History</h3>
          <span className="text-xs text-slate-400">{scans.length} job{scans.length !== 1 ? 's' : ''}</span>
        </div>
        {loading ? (
          <div className="flex items-center justify-center h-48"><Loader2 className="w-6 h-6 text-cyber-blue animate-spin" /></div>
        ) : error ? (
          <div className="p-8 text-center"><AlertTriangle size={24} className="text-red-400 mx-auto mb-2" /><p className="text-sm text-slate-400">{error}</p></div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center">
            <ScanLine size={32} className="text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 text-sm mb-1">No scan jobs yet</p>
            <p className="text-slate-600 text-xs">Save one scanner job for an authorized domain. It stays pending until the worker is running.</p>
            <button onClick={() => setShowModal(true)} className="btn-primary mt-4 inline-flex items-center gap-2"><Plus size={14} />New Scan Job</button>
          </div>
        ) : (
          <table className="data-table">
            <thead><tr><th>Name</th><th>Target</th><th>Modules</th><th>Status</th><th>Discovered</th><th>Scope</th><th>Created</th></tr></thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.id} id={`scan-row-${scan.id.substring(0, 8)}`}>
                  <td>
                    <div className="flex items-center gap-2">{scan.is_demo && <FlaskConical size={10} className="text-purple-400" />}<span className="text-sm font-medium text-slate-200">{scan.name}</span></div>
                    {scan.error_message && <p className="text-xs text-red-400 mt-1 max-w-xs">{scan.error_message}</p>}
                    {scan.result_summary?.module === 'semgrep' && scan.result_summary.results?.length ? (
                      <ul className="mt-1 max-w-xs space-y-1">
                        {scan.result_summary.results.map(row => (
                          <li key={`${row.rule_id}-${row.path}-${row.line}`} className="text-xs text-slate-500">
                            Static source, not confirmed
                            {row.severity ? ` · ${row.severity}` : ''}
                            {row.rule_id ? ` · ${row.rule_id}` : ''}
                            {row.path ? ` · ${row.path}` : ''}
                            {row.line != null ? `:${row.line}` : ''}
                          </li>
                        ))}
                      </ul>
                    ) : scan.result_summary?.module === 'zap' && scan.result_summary.results?.length ? (
                      <ul className="mt-1 max-w-xs space-y-1">
                        {scan.result_summary.results.map(row => (
                          <li key={`${row.plugin_id}-${row.url}`} className="text-xs text-slate-500">
                            Potential, not confirmed
                            {row.risk ? ` · ${row.risk}` : ''}
                            {row.plugin_id ? ` · ${row.plugin_id}` : ''}
                            {row.url ? ` · ${row.url}` : ''}
                          </li>
                        ))}
                      </ul>
                    ) : scan.result_summary?.module === 'nuclei' && scan.result_summary.results?.length ? (
                      <ul className="mt-1 max-w-xs space-y-1">
                        {scan.result_summary.results.map(row => (
                          <li key={`${row.template_id}-${row.url}`} className="text-xs text-slate-500">
                            {row.classification === 'informational' ? 'Informational' : 'Potential, not confirmed'}
                            {row.severity ? ` · ${row.severity}` : ''}
                            {row.template_id ? ` · ${row.template_id}` : ''}
                            {row.url ? ` · ${row.url}` : ''}
                          </li>
                        ))}
                      </ul>
                    ) : scan.result_summary?.hostnames?.length ? (
                      <p className="text-xs text-slate-500 mt-1 max-w-xs">{scan.result_summary.hostnames.join(', ')}</p>
                    ) : scan.result_summary?.module === 'httpx' && scan.result_summary.results?.length ? (
                      <ul className="mt-1 max-w-xs space-y-1">
                        {scan.result_summary.results.map(row => (
                          <li key={row.url} className="text-xs text-slate-500">
                            {row.url}
                            {row.status_code != null ? ` · ${row.status_code}` : ''}
                            {row.title ? ` · ${row.title}` : ''}
                            {row.webserver ? ` · ${row.webserver}` : ''}
                            {row.technologies?.length ? ` · ${row.technologies.join(', ')}` : ''}
                          </li>
                        ))}
                      </ul>
                    ) : scan.status === 'completed' && scan.modules.length === 1 && scan.modules[0] === 'subfinder' ? (
                      <p className="text-xs text-slate-500 mt-1">No new names were stored.</p>
                    ) : scan.status === 'completed' && scan.modules.length === 1 && scan.modules[0] === 'httpx' ? (
                      <p className="text-xs text-slate-500 mt-1">No HTTP services were stored.</p>
                    ) : scan.status === 'completed' && scan.modules.length === 1 && scan.modules[0] === 'nuclei' ? (
                      <p className="text-xs text-slate-500 mt-1">No findings were stored.</p>
                    ) : scan.status === 'completed' && scan.modules.length === 1 && scan.modules[0] === 'zap' ? (
                      <p className="text-xs text-slate-500 mt-1">No baseline alerts were stored.</p>
                    ) : scan.status === 'completed' && scan.modules.length === 1 && scan.modules[0] === 'semgrep' ? (
                      <p className="text-xs text-slate-500 mt-1">No source findings were stored.</p>
                    ) : null}
                    {scan.result_summary?.module === 'httpx' && (scan.result_summary.skipped_over_limit ?? 0) > 0 ? (
                      <p className="text-xs text-slate-500 mt-1">{scan.result_summary.skipped_over_limit} stored assets were not probed in this job.</p>
                    ) : null}
                  </td>
                  <td><span className="text-xs font-mono text-cyber-blue-bright">{scan.target}</span></td>
                  <td><div className="flex flex-wrap gap-1">{scan.modules.map(m => <span key={m} className="text-xs px-1.5 py-0.5 rounded bg-navy-900 border border-cyber-blue/15 text-slate-400 font-mono">{m}</span>)}</div></td>
                  <td><StatusBadge status={scan.status} /></td>
                  <td>
                    {scan.result_summary?.module === 'nuclei' || scan.result_summary?.module === 'semgrep' || scan.result_summary?.module === 'zap' ? (
                      <span className="text-xs text-slate-300">{scan.result_summary.findings ?? 0} findings</span>
                    ) : scan.result_summary?.module === 'httpx' ? (
                      <span className="text-xs text-slate-300">{scan.result_summary.updated ?? 0} updated</span>
                    ) : scan.result_summary ? (
                      <span className="text-xs text-slate-300">{scan.result_summary.stored ?? 0} stored</span>
                    ) : (
                      <span className="text-xs text-slate-500">{
                        scan.status === 'pending' && scan.modules.length === 1 && ['subfinder', 'httpx', 'nuclei', 'semgrep', 'zap'].includes(scan.modules[0])
                          ? 'Waiting for worker'
                          : '—'
                      }</span>
                    )}
                  </td>
                  <td>{scan.scope_validated ? <span className="flex items-center gap-1 text-xs text-cyber-green"><CheckCircle size={12} />Checked</span> : <span className="flex items-center gap-1 text-xs text-slate-400"><Clock size={12} />Not checked</span>}</td>
                  <td className="text-xs text-slate-400">{new Date(scan.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {showModal && <NewScanModal projectId={projectId} onClose={() => setShowModal(false)} onCreated={fetchScans} />}
    </div>
  );
}
