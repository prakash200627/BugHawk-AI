import React, { useEffect, useState, useCallback } from 'react';
import {
  FileText, Download, Plus, Loader2, FlaskConical,
  CheckCircle, Clock, AlertTriangle, FileJson, FileDown
} from 'lucide-react';
import { reportsApi } from '../lib/api';
import { useSession } from '../lib/session';
import NoProject from '../components/NoProject';
import type { SecurityReport } from '../types';
import clsx from 'clsx';


export default function ReportsPage() {
  const { projectId } = useSession();
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState('');

  const fetchReports = useCallback(async () => {
    if (!projectId) { setReports([]); setLoading(false); return; }
    try {
      const res = await reportsApi.list(projectId);
      setReports(res.data); setError('');
    } catch { setError('Could not load reports. Ensure backend is running.'); }
    finally { setLoading(false); }
  }, [projectId]);

  useEffect(() => { fetchReports(); }, [fetchReports]);

  const generateReport = async () => {
    if (!projectId) return;
    setGenerating(true);
    try {
      await reportsApi.generate({
        project_id: projectId,
        title: `Security Assessment Report — ${new Date().toLocaleDateString()}`,
        format: 'json',
      });
      await fetchReports();
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Failed to generate report.');
    } finally { setGenerating(false); }
  };

  const downloadReport = async (report: SecurityReport) => {
    try {
      const res = await reportsApi.download(report.id);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.title.replace(/\s+/g, '_')}.json`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch { alert('Download failed. Ensure backend is running.'); }
  };

  // Report sections for the preview
  const REPORT_SECTIONS = [
    { label: 'Executive Summary', desc: 'High-level risk posture and key findings overview' },
    { label: 'Assessment Scope', desc: 'Authorized targets and scope rules' },
    { label: 'Methodology', desc: 'Tools used, scan modules, and AI analysis approach' },
    { label: 'Assets Assessed', desc: 'Discovered and live assets within scope' },
    { label: 'Findings', desc: 'All vulnerabilities with evidence and severity' },
    { label: 'Risk Prioritization', desc: 'AI risk scoring and prioritization rationale' },
    { label: 'Remediation', desc: 'Fix guidance and secure code examples' },
    { label: 'Limitations', desc: 'Scope boundaries and assessment constraints' },
    { label: 'Timestamp & Attribution', desc: 'Assessment date, platform version, and analyst notes' },
  ];

  if (!projectId) return <NoProject />;

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Demo banner */}
      <div className="demo-banner"><FlaskConical size={12} />Reports — Demo project · JSON export available · PDF requires paid plan</div>

      {/* Header action */}
      <div className="flex justify-between items-center">
        <div>
          <p className="text-sm text-slate-400">Generate professional security assessment reports with evidence, findings, and remediation guidance.</p>
        </div>
        <button
          onClick={generateReport}
          disabled={generating}
          className="btn-primary flex items-center gap-2"
          id="generate-report-btn"
        >
          {generating ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
          {generating ? 'Generating...' : 'Generate Report'}
        </button>
      </div>

      {/* Report structure preview */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
          <FileText size={14} className="text-cyber-blue" />
          Report Structure
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {REPORT_SECTIONS.map((s, i) => (
            <div key={s.label} className="flex items-start gap-3 p-3 rounded-lg bg-navy-900 border border-navy-700">
              <span className="text-xs font-mono text-cyber-blue font-bold w-5 flex-shrink-0">{String(i + 1).padStart(2, '0')}</span>
              <div>
                <div className="text-xs font-semibold text-slate-200">{s.label}</div>
                <div className="text-xs text-slate-500 mt-0.5">{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          <AlertTriangle size={12} />{error}
        </div>
      )}

      {/* Reports list */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between p-5 border-b border-cyber-blue/10">
          <h3 className="text-sm font-semibold text-slate-200">Generated Reports</h3>
          <span className="text-xs text-slate-400">{reports.length} report{reports.length !== 1 ? 's' : ''}</span>
        </div>
        {loading ? (
          <div className="flex items-center justify-center h-32"><Loader2 className="w-6 h-6 text-cyber-blue animate-spin" /></div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center">
            <FileText size={32} className="text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 text-sm mb-1">No reports generated yet</p>
            <p className="text-slate-600 text-xs mb-4">Click "Generate Report" to create your first security assessment report</p>
            <button onClick={generateReport} disabled={generating} className="btn-primary inline-flex items-center gap-2">
              {generating ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              Generate Report
            </button>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr><th>Title</th><th>Format</th><th>Findings</th><th>Size</th><th>Generated</th><th>Demo</th><th>Action</th></tr>
            </thead>
            <tbody>
              {reports.map(r => (
                <tr key={r.id} id={`report-row-${r.id.substring(0, 8)}`}>
                  <td>
                    <div className="flex items-center gap-2">
                      <FileJson size={14} className="text-cyber-blue flex-shrink-0" />
                      <span className="text-sm text-slate-200 font-medium">{r.title}</span>
                    </div>
                  </td>
                  <td>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-navy-900 border border-cyber-blue/15 text-slate-400 uppercase">{r.report_format}</span>
                  </td>
                  <td><span className="text-sm font-semibold text-cyber-orange">{r.findings_count}</span></td>
                  <td className="text-xs text-slate-400">{r.file_size ? `${Math.round(r.file_size / 1024)} KB` : '—'}</td>
                  <td className="text-xs text-slate-400">{new Date(r.created_at).toLocaleString()}</td>
                  <td>{r.is_demo ? <span className="badge badge-demo flex items-center gap-1 text-xs"><FlaskConical size={9} />Demo</span> : <span className="text-slate-500 text-xs">—</span>}</td>
                  <td>
                    <button
                      onClick={() => downloadReport(r)}
                      className="btn-secondary flex items-center gap-1.5 !py-1.5 !px-3 text-xs"
                      id={`download-${r.id.substring(0, 8)}`}
                    >
                      <Download size={12} />
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
