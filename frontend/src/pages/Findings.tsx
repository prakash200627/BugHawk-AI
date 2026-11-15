import React, { useEffect, useState, useCallback } from 'react';
import {
  Bug, AlertTriangle, Filter, Search, Eye, Loader2,
  ChevronDown, ExternalLink, Shield, FlaskConical,
  CheckCircle, Clock, XCircle, HelpCircle, ChevronRight,
  Fingerprint, Code2, Globe
} from 'lucide-react';
import { findingsApi } from '../lib/api';
import type { SecurityFinding, Severity } from '../types';
import clsx from 'clsx';

const DEMO_PROJECT_ID = 'demo-project-id';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

function SeverityBadge({ sev }: { sev: string }) {
  const cls: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
    unknown: 'badge-info',
  };
  return <span className={`badge ${cls[sev] || 'badge-info'} uppercase`}>{sev}</span>;
}

function ValidationBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; icon: React.ReactNode; label: string }> = {
    confirmed: { cls: 'badge-success', icon: <CheckCircle size={10} />, label: 'Confirmed' },
    pending: { cls: 'badge-info', icon: <Clock size={10} />, label: 'Pending' },
    needs_review: { cls: 'badge-high', icon: <Eye size={10} />, label: 'Needs Review' },
    false_positive: { cls: 'badge-info', icon: <XCircle size={10} />, label: 'False Positive' },
    duplicate: { cls: 'badge-info', icon: <HelpCircle size={10} />, label: 'Duplicate' },
  };
  const item = map[status] || { cls: 'badge-info', icon: null, label: status };
  return (
    <span className={`badge ${item.cls} flex items-center gap-1`}>
      {item.icon}
      {item.label}
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const map: Record<string, string> = {
    high: 'text-emerald-400',
    medium: 'text-yellow-400',
    low: 'text-orange-400',
    unverified: 'text-slate-400',
  };
  return <span className={`text-xs font-medium ${map[confidence] || 'text-slate-400'}`}>{confidence.toUpperCase()}</span>;
}

function FindingDrawer({ finding, onClose }: { finding: SecurityFinding; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        className="w-full max-w-2xl bg-navy-800 border-l border-cyber-blue/20 shadow-2xl overflow-y-auto animate-slide-in"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 bg-navy-800 border-b border-cyber-blue/10 p-5 z-10">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <SeverityBadge sev={finding.effective_severity} />
                <ValidationBadge status={finding.validation_status} />
                {finding.is_demo && (
                  <span className="badge badge-demo flex items-center gap-1">
                    <FlaskConical size={10} /> DEMO
                  </span>
                )}
                {finding.needs_human_review && (
                  <span className="badge badge-high flex items-center gap-1">
                    <Eye size={10} /> Review Needed
                  </span>
                )}
              </div>
              <h2 className="text-base font-bold text-slate-100">{finding.title}</h2>
            </div>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 p-1"
            >
              <XCircle size={18} />
            </button>
          </div>
        </div>

        <div className="p-5 space-y-5">
          {/* Meta info grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'CWE', value: finding.cwe_id || '—' },
              { label: 'CVE', value: finding.cve_id || '—' },
              { label: 'Source Tool', value: finding.source_tool || '—' },
              { label: 'Confidence', value: <ConfidenceBadge confidence={finding.confidence} /> },
              { label: 'Risk Score', value: finding.risk_score ? `${finding.risk_score.toFixed(1)} / 10` : '—' },
              { label: 'CVSS', value: finding.cvss_score ? finding.cvss_score.toFixed(1) : '—' },
            ].map(({ label, value }) => (
              <div key={label} className="bg-navy-900 rounded-lg p-3">
                <div className="text-xs text-slate-500 mb-1">{label}</div>
                <div className="text-sm font-medium text-slate-200">{typeof value === 'string' ? value : value}</div>
              </div>
            ))}
          </div>

          {/* Endpoint */}
          {finding.endpoint && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">Endpoint</h4>
              <div className="flex items-center gap-2 bg-navy-900 rounded-lg p-3">
                <Globe size={12} className="text-slate-500 flex-shrink-0" />
                <code className="text-xs text-cyber-blue-bright font-mono break-all">{finding.endpoint}</code>
              </div>
            </div>
          )}

          {/* Description */}
          {finding.description && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">Description</h4>
              <p className="text-sm text-slate-300 leading-relaxed bg-navy-900 rounded-lg p-3">
                {finding.description}
              </p>
            </div>
          )}

          {/* Impact */}
          {finding.impact && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">Security Impact</h4>
              <p className="text-sm text-slate-300 leading-relaxed bg-orange-500/5 border border-orange-500/15 rounded-lg p-3">
                {finding.impact}
              </p>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">Evidence</h4>
              <div className="code-block text-xs space-y-2">
                {Object.entries(finding.evidence)
                  .filter(([k]) => !['demo', 'note'].includes(k))
                  .map(([key, val]) => (
                    <div key={key}>
                      <span className="text-cyber-blue-bright">{key}:</span>{' '}
                      <span className="text-slate-300">
                        {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                      </span>
                    </div>
                  ))}
                <div className="text-purple-400 mt-2 pt-2 border-t border-purple-500/20">
                  ⚠ DEMO DATA — Synthetic evidence for demonstration purposes only
                </div>
              </div>
            </div>
          )}

          {/* Risk factors */}
          {finding.risk_factors && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">Risk Score Factors</h4>
              <div className="bg-navy-900 rounded-lg p-3 space-y-2">
                {Object.entries(finding.risk_factors)
                  .filter(([k]) => k !== 'note')
                  .map(([key, val]) => (
                    <div key={key} className="flex items-center justify-between text-xs">
                      <span className="text-slate-400 capitalize">{key.replace('_', ' ')}</span>
                      <span className="font-mono text-slate-300">{String(val)}</span>
                    </div>
                  ))}
                {finding.risk_factors.note && (
                  <div className="text-xs text-purple-400 pt-2 border-t border-purple-500/15">
                    {String(finding.risk_factors.note)}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Remediation hint */}
          {finding.remediation && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">Remediation</h4>
              <p className="text-sm text-slate-300 leading-relaxed bg-emerald-500/5 border border-emerald-500/15 rounded-lg p-3">
                {finding.remediation}
              </p>
              <a
                href={`/remediation`}
                className="mt-2 btn-secondary flex items-center gap-1.5 text-xs w-full justify-center"
              >
                View Full Remediation Guide <ChevronRight size={12} />
              </a>
            </div>
          )}

          {/* AI Explanation */}
          {finding.ai_explanation && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                AI Analysis
                <span className="badge badge-demo">AI</span>
              </h4>
              <p className="text-sm text-slate-300 leading-relaxed bg-cyber-blue/5 border border-cyber-blue/15 rounded-lg p-3">
                {finding.ai_explanation}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchFindings = useCallback(async () => {
    try {
      setError(null);
      const params: Record<string, string> = {};
      if (severityFilter !== 'all') params.severity = severityFilter;
      if (statusFilter !== 'all') params.validation_status = statusFilter;
      if (search) params.search = search;
      const res = await findingsApi.list(DEMO_PROJECT_ID, params);
      setFindings(res.data);
    } catch {
      setError('Could not load findings. Ensure backend is running and demo data is seeded.');
    } finally {
      setLoading(false);
    }
  }, [severityFilter, statusFilter, search]);

  useEffect(() => {
    const timer = setTimeout(fetchFindings, 300);
    return () => clearTimeout(timer);
  }, [fetchFindings]);

  const severityCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.effective_severity] = (acc[f.effective_severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Demo banner */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="demo-banner">
          <FlaskConical size={12} />
          <span>Vulnerability Intelligence — Demo Project findings</span>
        </div>
        {error && (
          <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-3 py-1.5 rounded-lg">
            {error}
          </div>
        )}
      </div>

      {/* Severity summary pills */}
      <div className="flex flex-wrap gap-2">
        {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
          const count = sev === 'all' ? findings.length : (severityCounts[sev] || 0);
          const cls: Record<string, string> = {
            all: 'bg-slate-500/15 text-slate-300 border-slate-500/20',
            critical: 'bg-red-500/15 text-red-400 border-red-500/25',
            high: 'bg-orange-500/15 text-orange-400 border-orange-500/25',
            medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/25',
            low: 'bg-blue-500/15 text-blue-400 border-blue-500/25',
            info: 'bg-slate-500/15 text-slate-400 border-slate-500/20',
          };
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={clsx(
                'px-3 py-1.5 rounded-lg border text-xs font-medium transition-all duration-150',
                cls[sev],
                severityFilter === sev && 'ring-1 ring-current opacity-100',
                severityFilter !== sev && 'opacity-60 hover:opacity-80'
              )}
              id={`severity-filter-${sev}`}
            >
              {sev === 'all' ? 'All' : sev.toUpperCase()} ({count})
            </button>
          );
        })}
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input pl-9 text-xs"
            id="findings-search"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="input !w-auto text-xs"
          id="status-filter"
        >
          <option value="all">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="confirmed">Confirmed</option>
          <option value="needs_review">Needs Review</option>
          <option value="false_positive">False Positive</option>
          <option value="duplicate">Duplicate</option>
        </select>
        <div className="text-xs text-slate-400">
          {findings.length} finding{findings.length !== 1 ? 's' : ''} found
        </div>
      </div>

      {/* Findings table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <Loader2 className="w-6 h-6 text-cyber-blue animate-spin" />
          </div>
        ) : findings.length === 0 ? (
          <div className="p-12 text-center">
            <Bug size={32} className="text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 text-sm mb-1">No findings match your filters</p>
            <p className="text-slate-600 text-xs">Try adjusting your severity or status filters</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Status</th>
                <th>Tool</th>
                <th>Risk</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedFinding(f)}
                  id={`finding-row-${f.id.substring(0, 8)}`}
                >
                  <td>
                    <div className="flex flex-col max-w-xs">
                      <div className="flex items-center gap-2">
                        {f.is_demo && (
                          <FlaskConical size={10} className="text-purple-400 flex-shrink-0" />
                        )}
                        {f.needs_human_review && (
                          <Eye size={10} className="text-yellow-400 flex-shrink-0" />
                        )}
                        <span className="text-slate-200 text-xs font-medium line-clamp-1">{f.title}</span>
                      </div>
                      <div className="text-slate-500 text-xs mt-0.5 font-mono truncate">
                        {f.endpoint ? f.endpoint.substring(0, 50) : f.cwe_id || '—'}
                      </div>
                    </div>
                  </td>
                  <td><SeverityBadge sev={f.effective_severity} /></td>
                  <td><ConfidenceBadge confidence={f.confidence} /></td>
                  <td><ValidationBadge status={f.validation_status} /></td>
                  <td>
                    <span className="text-xs text-slate-400 font-mono bg-navy-900 px-2 py-0.5 rounded">
                      {f.source_tool || '—'}
                    </span>
                  </td>
                  <td>
                    {f.risk_score != null ? (
                      <div className="flex items-center gap-2">
                        <div
                          className="h-1.5 w-16 bg-navy-700 rounded-full overflow-hidden"
                          title={`Risk score: ${f.risk_score.toFixed(1)}/10`}
                        >
                          <div
                            className={clsx(
                              'h-full rounded-full',
                              f.risk_score >= 8 ? 'bg-red-500' :
                              f.risk_score >= 6 ? 'bg-orange-500' :
                              f.risk_score >= 4 ? 'bg-yellow-500' : 'bg-blue-500'
                            )}
                            style={{ width: `${(f.risk_score / 10) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs text-slate-300 font-mono">{f.risk_score.toFixed(1)}</span>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-500">—</span>
                    )}
                  </td>
                  <td>
                    <ChevronRight size={14} className="text-slate-500" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail drawer */}
      {selectedFinding && (
        <FindingDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
