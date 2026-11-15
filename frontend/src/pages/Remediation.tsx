import React, { useEffect, useState, useCallback } from 'react';
import {
  Wrench, CheckCircle, Clock, XCircle, ChevronDown, ChevronRight,
  Copy, FlaskConical, Loader2, AlertTriangle, Code2
} from 'lucide-react';
import { remediationApi, findingsApi } from '../lib/api';
import type { RemediationSuggestion, SecurityFinding } from '../types';
import clsx from 'clsx';

const DEMO_PROJECT_ID = 'demo-project-id';

const STATUS_OPTIONS = ['pending', 'accepted', 'in_progress', 'completed', 'wont_fix'];

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending:     'badge-info',
    accepted:    'badge-low',
    in_progress: 'badge-medium',
    completed:   'badge-success',
    wont_fix:    'bg-slate-500/20 text-slate-400 border border-slate-500/30',
  };
  return <span className={`badge ${map[status] || 'badge-info'}`}>{status.replace('_', ' ')}</span>;
}

function RemediationCard({ finding, remediation, onStatusChange }: {
  finding: SecurityFinding;
  remediation: RemediationSuggestion | null;
  onStatusChange: (id: string, status: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [updating, setUpdating] = useState(false);

  const copyCode = async () => {
    if (remediation?.secure_code_example) {
      await navigator.clipboard.writeText(remediation.secure_code_example);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const changeStatus = async (status: string) => {
    if (!remediation) return;
    setUpdating(true);
    try {
      await remediationApi.updateStatus(remediation.id, status);
      onStatusChange(remediation.id, status);
    } catch {}
    finally { setUpdating(false); }
  };

  const sevColor: Record<string, string> = {
    critical: 'border-l-red-500',
    high:     'border-l-orange-500',
    medium:   'border-l-yellow-500',
    low:      'border-l-blue-500',
    info:     'border-l-slate-500',
  };

  return (
    <div className={clsx('card border-l-4 overflow-hidden', sevColor[finding.effective_severity] || 'border-l-slate-500')}>
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-5 text-left hover:bg-cyber-blue/5 transition-colors"
        id={`remediation-toggle-${finding.id.substring(0, 8)}`}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`badge text-xs uppercase ${finding.effective_severity === 'critical' ? 'badge-critical' : finding.effective_severity === 'high' ? 'badge-high' : finding.effective_severity === 'medium' ? 'badge-medium' : 'badge-low'}`}>
              {finding.effective_severity}
            </span>
            {finding.is_demo && <span className="badge badge-demo flex items-center gap-1 text-xs"><FlaskConical size={9} />Demo</span>}
            {remediation && <StatusBadge status={remediation.status} />}
          </div>
          <h3 className="text-sm font-semibold text-slate-200 mt-1.5">{finding.title}</h3>
          {finding.endpoint && <p className="text-xs text-slate-500 font-mono mt-0.5 truncate">{finding.endpoint}</p>}
        </div>
        {expanded ? <ChevronDown size={16} className="text-slate-400 flex-shrink-0" /> : <ChevronRight size={16} className="text-slate-400 flex-shrink-0" />}
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-cyber-blue/10 p-5 space-y-5 animate-fade-in">
          {!remediation ? (
            <div className="text-center py-8 text-slate-400 text-sm">
              <Wrench size={24} className="mx-auto mb-2 text-slate-600" />
              <p>No remediation suggestion available yet.</p>
              <p className="text-xs text-slate-500 mt-1">Run AI Analysis on this finding to generate guidance.</p>
            </div>
          ) : (
            <>
              {/* Root cause */}
              {remediation.root_cause && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Root Cause</h4>
                  <p className="text-sm text-slate-300 leading-relaxed bg-navy-900 rounded-lg p-3">{remediation.root_cause}</p>
                </div>
              )}
              {/* Impact */}
              {remediation.impact && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Security Impact</h4>
                  <p className="text-sm text-slate-300 leading-relaxed bg-orange-500/5 border border-orange-500/15 rounded-lg p-3">{remediation.impact}</p>
                </div>
              )}
              {/* Recommendation */}
              {remediation.recommendation && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Recommendation</h4>
                  <p className="text-sm text-slate-300 leading-relaxed bg-emerald-500/5 border border-emerald-500/15 rounded-lg p-3">{remediation.recommendation}</p>
                </div>
              )}
              {/* Secure code example */}
              {remediation.secure_code_example && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Code2 size={12} />
                      Secure Code Example
                      {remediation.code_language && (
                        <span className="normal-case px-2 py-0.5 rounded bg-cyber-blue/15 text-cyber-blue font-mono">{remediation.code_language}</span>
                      )}
                    </h4>
                    <button
                      onClick={copyCode}
                      className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                      id="copy-code-btn"
                    >
                      <Copy size={12} />
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-block whitespace-pre-wrap text-xs leading-relaxed overflow-x-auto max-h-64">
                    {remediation.secure_code_example}
                  </pre>
                </div>
              )}
              {/* Verification checklist */}
              {remediation.verification_checklist && remediation.verification_checklist.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Verification Checklist</h4>
                  <div className="space-y-2">
                    {remediation.verification_checklist.map((item, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <div className="w-5 h-5 rounded border border-cyber-green/30 flex items-center justify-center flex-shrink-0 mt-0.5 bg-cyber-green/10">
                          <CheckCircle size={11} className="text-cyber-green" />
                        </div>
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* Status control */}
              <div className="flex items-center gap-3 pt-3 border-t border-cyber-blue/10 flex-wrap">
                <span className="text-xs text-slate-400 font-medium">Update Status:</span>
                <div className="flex flex-wrap gap-2">
                  {STATUS_OPTIONS.map(s => (
                    <button
                      key={s}
                      onClick={() => changeStatus(s)}
                      disabled={updating || remediation.status === s}
                      className={clsx(
                        'text-xs px-3 py-1.5 rounded-lg border transition-all duration-150',
                        remediation.status === s
                          ? 'bg-cyber-blue/20 border-cyber-blue/40 text-cyber-blue-bright'
                          : 'bg-navy-900 border-navy-700 text-slate-400 hover:border-cyber-blue/30 hover:text-slate-300'
                      )}
                      id={`status-${s}`}
                    >
                      {s.replace('_', ' ')}
                    </button>
                  ))}
                </div>
                {updating && <Loader2 size={14} className="text-cyber-blue animate-spin" />}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default function RemediationPage() {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [remediations, setRemediations] = useState<Record<string, RemediationSuggestion | null>>({});
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('all');

  const loadData = useCallback(async () => {
    try {
      const res = await findingsApi.list(DEMO_PROJECT_ID, {});
      const fList: SecurityFinding[] = res.data;
      setFindings(fList);
      // Fetch remediation for each finding
      const remMap: Record<string, RemediationSuggestion | null> = {};
      await Promise.all(fList.map(async (f) => {
        try {
          const r = await remediationApi.get(f.id);
          remMap[f.id] = r.data;
        } catch { remMap[f.id] = null; }
      }));
      setRemediations(remMap);
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleStatusChange = (remId: string, status: string) => {
    setRemediations(prev => {
      const updated = { ...prev };
      const findingId = Object.keys(updated).find(k => updated[k]?.id === remId);
      if (findingId && updated[findingId]) {
        updated[findingId] = { ...updated[findingId]!, status: status as any };
      }
      return updated;
    });
  };

  const filtered = findings.filter(f => {
    if (statusFilter === 'all') return true;
    const rem = remediations[f.id];
    return rem?.status === statusFilter;
  });

  const counts = {
    all: findings.length,
    pending: Object.values(remediations).filter(r => r?.status === 'pending').length,
    accepted: Object.values(remediations).filter(r => r?.status === 'accepted').length,
    completed: Object.values(remediations).filter(r => r?.status === 'completed').length,
  };

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="demo-banner"><FlaskConical size={12} />Remediation Center — Demo project · AI-generated guidance · Do NOT apply to production automatically</div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total', count: counts.all, color: 'text-slate-200', bg: 'bg-slate-500/10' },
          { label: 'Pending', count: counts.pending, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
          { label: 'Accepted', count: counts.accepted, color: 'text-blue-400', bg: 'bg-blue-500/10' },
          { label: 'Completed', count: counts.completed, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
        ].map(({ label, count, color, bg }) => (
          <div key={label} className={`card p-4 flex items-center gap-3 ${bg}`}>
            <span className={`text-2xl font-bold ${color}`}>{count}</span>
            <span className="text-sm text-slate-400">{label}</span>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex gap-2 flex-wrap">
        {(['all', 'pending', 'accepted', 'in_progress', 'completed', 'wont_fix'] as const).map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={clsx(
              'text-xs px-3 py-1.5 rounded-lg border transition-all',
              statusFilter === s ? 'bg-cyber-blue/20 border-cyber-blue/40 text-cyber-blue-bright' : 'bg-navy-800 border-navy-700 text-slate-400 hover:text-slate-200'
            )}
            id={`filter-${s}`}
          >
            {s === 'all' ? 'All' : s.replace('_', ' ')} {s === 'all' ? `(${counts.all})` : ''}
          </button>
        ))}
      </div>

      {/* Warning */}
      <div className="flex items-start gap-3 px-4 py-3 rounded-lg bg-orange-500/8 border border-orange-500/20 text-xs text-orange-300">
        <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
        <span><strong>Important:</strong> Remediation suggestions are AI-generated guidance. Always review with your team and test in a staging environment before applying to production. BugHawk AI never modifies application source code automatically.</span>
      </div>

      {/* Cards */}
      {loading ? (
        <div className="flex items-center justify-center h-48"><Loader2 className="w-6 h-6 text-cyber-blue animate-spin" /></div>
      ) : (
        <div className="space-y-3">
          {filtered.map(f => (
            <RemediationCard
              key={f.id}
              finding={f}
              remediation={remediations[f.id] || null}
              onStatusChange={handleStatusChange}
            />
          ))}
          {filtered.length === 0 && (
            <div className="card p-12 text-center">
              <Wrench size={32} className="text-slate-600 mx-auto mb-3" />
              <p className="text-slate-400 text-sm">No items match the selected filter</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
