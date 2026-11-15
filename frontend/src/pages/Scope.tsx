import React, { useEffect, useState, useCallback } from 'react';
import {
  Shield, Plus, Trash2, CheckCircle, XCircle, Loader2,
  FlaskConical, AlertTriangle, Globe, ChevronRight
} from 'lucide-react';
import { scopesApi } from '../lib/api';
import type { AuthorizedScope, ScopeValidationResult } from '../types';
import clsx from 'clsx';

const DEMO_PROJECT_ID = 'demo-project-id';

function AddScopeModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [form, setForm] = useState({ scope_value: '', notes: '', authorized_by: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    if (!form.scope_value.trim()) { setError('Scope value is required.'); return; }
    setSaving(true); setError('');
    try {
      await scopesApi.add(DEMO_PROJECT_ID, form);
      onAdded(); onClose();
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Failed to add scope rule.');
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-md bg-navy-800 border border-cyber-blue/20 rounded-2xl shadow-2xl animate-fade-in" onClick={e => e.stopPropagation()}>
        <div className="p-5 border-b border-cyber-blue/10 flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2"><Shield size={16} className="text-cyber-green" />Add Authorized Scope</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200"><XCircle size={18} /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Scope Value</label>
            <input type="text" value={form.scope_value} onChange={e => setForm(p => ({ ...p, scope_value: e.target.value }))} placeholder="example.com or *.example.com" className="input text-sm font-mono" id="scope-value-input" />
            <p className="text-xs text-slate-500 mt-1">Use <code className="text-cyber-blue">*.example.com</code> for wildcard. Exact hostname only unless wildcard is specified.</p>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Notes (optional)</label>
            <input type="text" value={form.notes} onChange={e => setForm(p => ({ ...p, notes: e.target.value }))} placeholder="e.g. Bug bounty program target" className="input text-sm" />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Authorized By (optional)</label>
            <input type="text" value={form.authorized_by} onChange={e => setForm(p => ({ ...p, authorized_by: e.target.value }))} placeholder="e.g. Security Team Lead" className="input text-sm" />
          </div>
          {error && <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2"><AlertTriangle size={12} />{error}</div>}
        </div>
        <div className="p-5 border-t border-cyber-blue/10 flex justify-end gap-3">
          <button onClick={onClose} className="btn-secondary">Cancel</button>
          <button onClick={submit} disabled={saving} className="btn-primary flex items-center gap-2" id="add-scope-btn">
            {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
            Add Scope Rule
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ScopePage() {
  const [scopes, setScopes] = useState<AuthorizedScope[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [validateTarget, setValidateTarget] = useState('');
  const [validationResult, setValidationResult] = useState<ScopeValidationResult | null>(null);
  const [validating, setValidating] = useState(false);

  const fetchScopes = useCallback(async () => {
    try {
      const res = await scopesApi.list(DEMO_PROJECT_ID);
      setScopes(res.data);
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchScopes(); }, [fetchScopes]);

  const runValidation = async () => {
    if (!validateTarget.trim()) return;
    setValidating(true); setValidationResult(null);
    try {
      const res = await scopesApi.validate({ target: validateTarget, project_id: DEMO_PROJECT_ID });
      setValidationResult(res.data);
    } catch { setValidationResult(null); }
    finally { setValidating(false); }
  };

  const deleteScope = async (id: string) => {
    try {
      await scopesApi.delete(id);
      setScopes(prev => prev.filter(s => s.id !== id));
    } catch {}
  };

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="demo-banner"><FlaskConical size={12} />Scope Management — Demo project · Scope Guardian enforces these rules deterministically</div>

      {/* How it works */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2"><Shield size={14} className="text-cyber-green" />Scope Guardian — How It Works</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-slate-400">
          <div className="bg-navy-900 rounded-lg p-3">
            <div className="text-cyber-blue font-semibold mb-1">Exact Match</div>
            <code className="text-slate-300">example.com</code>
            <p className="mt-1">Allows <code>example.com</code> only. Does NOT allow <code>sub.example.com</code>.</p>
          </div>
          <div className="bg-navy-900 rounded-lg p-3">
            <div className="text-cyber-blue font-semibold mb-1">Wildcard Match</div>
            <code className="text-slate-300">*.example.com</code>
            <p className="mt-1">Allows <code>example.com</code>, <code>sub.example.com</code>, <code>api.sub.example.com</code>.</p>
          </div>
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
            <div className="text-red-400 font-semibold mb-1">Always Rejected</div>
            <p>Suffix bypass: <code>example.com.evil.test</code></p>
            <p>Unauthorized IPs (unless explicitly listed)</p>
            <p>Malformed hostnames</p>
          </div>
        </div>
      </div>

      {/* Validator */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-3">Test Scope Validation</h3>
        <div className="flex gap-3">
          <input
            type="text"
            value={validateTarget}
            onChange={e => { setValidateTarget(e.target.value); setValidationResult(null); }}
            onKeyDown={e => e.key === 'Enter' && runValidation()}
            placeholder="Enter a hostname or URL to validate..."
            className="input flex-1 text-sm font-mono"
            id="validate-target-input"
          />
          <button onClick={runValidation} disabled={validating} className="btn-primary flex items-center gap-2 whitespace-nowrap" id="validate-btn">
            {validating ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle size={14} />}
            Validate
          </button>
        </div>
        {validationResult && (
          <div className={clsx('mt-3 p-4 rounded-lg border animate-fade-in', validationResult.is_allowed ? 'bg-emerald-500/10 border-emerald-500/25' : 'bg-red-500/10 border-red-500/25')}>
            <div className="flex items-center gap-2 mb-2">
              {validationResult.is_allowed ? <CheckCircle size={16} className="text-emerald-400" /> : <XCircle size={16} className="text-red-400" />}
              <span className={clsx('font-semibold text-sm', validationResult.is_allowed ? 'text-emerald-300' : 'text-red-300')}>
                {validationResult.decision.toUpperCase()}: {validationResult.target}
              </span>
            </div>
            <div className="text-xs text-slate-400 space-y-1">
              <div>Normalized host: <code className="text-slate-200 font-mono">{validationResult.normalized_host}</code></div>
              {validationResult.matched_rule && <div>Matched rule: <code className="text-cyber-blue-bright font-mono">{validationResult.matched_rule}</code></div>}
              <div>Reason: <span className="text-slate-300">{validationResult.reason}</span></div>
            </div>
          </div>
        )}
      </div>

      {/* Scopes list */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between p-5 border-b border-cyber-blue/10">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Authorized Scope Rules</h3>
            <p className="text-xs text-slate-500 mt-0.5">{scopes.length} rule{scopes.length !== 1 ? 's' : ''} defined</p>
          </div>
          <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2 !text-xs !py-2" id="add-scope-modal-btn">
            <Plus size={14} />Add Rule
          </button>
        </div>
        {loading ? (
          <div className="flex items-center justify-center h-32"><Loader2 className="w-6 h-6 text-cyber-blue animate-spin" /></div>
        ) : scopes.length === 0 ? (
          <div className="p-12 text-center">
            <Shield size={32} className="text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 text-sm mb-1">No scope rules defined</p>
            <p className="text-slate-600 text-xs">Add authorized targets to enable scanning</p>
          </div>
        ) : (
          <table className="data-table">
            <thead><tr><th>Scope Value</th><th>Type</th><th>Notes</th><th>Authorized By</th><th>Added</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {scopes.map(scope => (
                <tr key={scope.id} id={`scope-row-${scope.id.substring(0, 8)}`}>
                  <td>
                    <div className="flex items-center gap-2">
                      <Globe size={12} className="text-cyber-blue flex-shrink-0" />
                      <code className="text-sm text-cyber-blue-bright font-mono">{scope.scope_value}</code>
                    </div>
                  </td>
                  <td>
                    <span className={clsx('badge text-xs', scope.is_wildcard ? 'badge-medium' : 'badge-low')}>
                      {scope.is_wildcard ? 'Wildcard' : 'Exact'}
                    </span>
                  </td>
                  <td className="text-xs text-slate-400 max-w-xs truncate">{scope.notes || '—'}</td>
                  <td className="text-xs text-slate-400">{scope.authorized_by || '—'}</td>
                  <td className="text-xs text-slate-400">{new Date(scope.created_at).toLocaleDateString()}</td>
                  <td>
                    {scope.is_active
                      ? <span className="flex items-center gap-1 text-xs text-cyber-green"><CheckCircle size={12} />Active</span>
                      : <span className="flex items-center gap-1 text-xs text-slate-500"><XCircle size={12} />Inactive</span>}
                  </td>
                  <td>
                    <button
                      onClick={() => deleteScope(scope.id)}
                      className="p-1.5 text-slate-500 hover:text-red-400 transition-colors rounded"
                      id={`delete-scope-${scope.id.substring(0, 8)}`}
                      title="Remove scope rule"
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {showModal && <AddScopeModal onClose={() => setShowModal(false)} onAdded={fetchScopes} />}
    </div>
  );
}
