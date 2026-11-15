import React, { useEffect, useState, useCallback } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import {
  Server, Bug, AlertTriangle, Shield, Activity, Eye,
  TrendingUp, Clock, CheckCircle, XCircle, Loader2,
  RefreshCw, ChevronRight, Zap, Target, FlaskConical
} from 'lucide-react';
import { findingsApi, projectsApi } from '../lib/api';
import type { DashboardStats, SecurityFinding } from '../types';
import clsx from 'clsx';

// ============================================================
// Demo data for charts (always shown to demonstrate the platform)
// ============================================================

const FINDINGS_OVER_TIME = [
  { date: 'Nov 1', findings: 0, critical: 0 },
  { date: 'Nov 5', findings: 2, critical: 0 },
  { date: 'Nov 8', findings: 2, critical: 0 },
  { date: 'Nov 10', findings: 5, critical: 1 },
  { date: 'Nov 12', findings: 5, critical: 1 },
  { date: 'Nov 14', findings: 5, critical: 1 },
];

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#3b82f6',
  info: '#64748b',
};

const AGENT_ACTIVITY = [
  { name: 'Recon Agent', status: 'completed', time: '2h ago', tasks: 3 },
  { name: 'Scan Agent', status: 'completed', time: '1h ago', tasks: 1 },
  { name: 'Analyst Agent', status: 'completed', time: '45m ago', tasks: 5 },
  { name: 'Triage Agent', status: 'completed', time: '30m ago', tasks: 5 },
  { name: 'Remediation Agent', status: 'completed', time: '20m ago', tasks: 4 },
];

// ============================================================
// Sub-components
// ============================================================

interface StatCardProps {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  color?: string;
  trend?: string;
  critical?: boolean;
  demo?: boolean;
}

function StatCard({ label, value, icon, color = 'blue', critical, demo }: StatCardProps) {
  const colorMap: Record<string, string> = {
    blue: 'text-cyber-blue',
    red: 'text-red-400',
    orange: 'text-cyber-orange',
    yellow: 'text-yellow-400',
    green: 'text-cyber-green',
    purple: 'text-purple-400',
    slate: 'text-slate-400',
  };

  const bgMap: Record<string, string> = {
    blue: 'bg-cyber-blue/10',
    red: 'bg-red-500/10',
    orange: 'bg-cyber-orange/10',
    yellow: 'bg-yellow-500/10',
    green: 'bg-emerald-500/10',
    purple: 'bg-purple-500/10',
    slate: 'bg-slate-500/10',
  };

  return (
    <div className={clsx('stat-card', critical && 'border-red-500/20')}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-2">
            {label}
          </p>
          <p className={clsx('text-3xl font-bold', colorMap[color])}>
            {value}
          </p>
        </div>
        <div className={clsx('p-2.5 rounded-lg', bgMap[color])}>
          <span className={colorMap[color]}>{icon}</span>
        </div>
      </div>
      {demo && (
        <div className="mt-3 flex items-center gap-1 text-xs text-purple-400">
          <FlaskConical size={10} />
          <span>Demo data</span>
        </div>
      )}
      {critical && (
        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-red-500 to-transparent opacity-50" />
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
    unknown: 'badge-info',
  };
  return <span className={`badge ${cls[severity] || 'badge-info'}`}>{severity.toUpperCase()}</span>;
}

function ValidationBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; label: string }> = {
    confirmed: { cls: 'badge-success', label: 'Confirmed' },
    pending: { cls: 'badge-info', label: 'Pending' },
    needs_review: { cls: 'badge-high', label: 'Review' },
    false_positive: { cls: 'badge-info', label: 'FP' },
    duplicate: { cls: 'badge-info', label: 'Duplicate' },
  };
  const item = map[status] || { cls: 'badge-info', label: status };
  return <span className={`badge ${item.cls}`}>{item.label}</span>;
}

// ============================================================
// Main Overview Page
// ============================================================

const DEMO_PROJECT_ID = 'demo-project-id';

export default function OverviewPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentFindings, setRecentFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const [statsRes, findingsRes] = await Promise.all([
        findingsApi.stats(DEMO_PROJECT_ID),
        findingsApi.list(DEMO_PROJECT_ID, {}),
      ]);
      setStats(statsRes.data);
      setRecentFindings(findingsRes.data.slice(0, 5));
      setLastUpdated(new Date());
    } catch (err: any) {
      if (err?.response?.status === 404 || err?.code === 'ERR_NETWORK') {
        setError('Backend not connected. Start the FastAPI server and seed demo data.');
      } else {
        setError('Failed to load dashboard data.');
      }
      // Fallback demo stats
      setStats({
        total_assets: 5,
        live_assets: 4,
        total_findings: 5,
        critical_findings: 1,
        high_findings: 2,
        medium_findings: 1,
        low_findings: 1,
        info_findings: 0,
        potential_duplicates: 0,
        findings_pending_review: 3,
        total_scans: 1,
        active_scans: 0,
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const severityData = stats ? [
    { name: 'Critical', value: stats.critical_findings, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.high_findings, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.medium_findings, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.low_findings, color: SEVERITY_COLORS.low },
    { name: 'Info', value: stats.info_findings, color: SEVERITY_COLORS.info },
  ].filter(d => d.value > 0) : [];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <Loader2 className="w-8 h-8 text-cyber-blue animate-spin mx-auto mb-3" />
          <p className="text-sm text-slate-400">Loading security intelligence...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Demo + Error banner */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="demo-banner">
            <FlaskConical size={12} />
            <span>BugHawk Demo Application — Synthetic data for demonstration</span>
          </div>
          {error && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">
              <XCircle size={12} />
              <span>{error}</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
          <button
            onClick={fetchData}
            className="btn-secondary flex items-center gap-1.5 !py-1.5 !px-3 text-xs"
            id="refresh-dashboard-btn"
          >
            <RefreshCw size={12} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stat cards — row 1 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Total Assets"
          value={stats?.total_assets ?? 0}
          icon={<Server size={20} />}
          color="blue"
          demo
        />
        <StatCard
          label="Live Assets"
          value={stats?.live_assets ?? 0}
          icon={<CheckCircle size={20} />}
          color="green"
          demo
        />
        <StatCard
          label="Total Findings"
          value={stats?.total_findings ?? 0}
          icon={<Bug size={20} />}
          color="orange"
          demo
        />
        <StatCard
          label="Active Scans"
          value={stats?.active_scans ?? 0}
          icon={<Activity size={20} />}
          color="purple"
          demo
        />
      </div>

      {/* Stat cards — row 2 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Critical"
          value={stats?.critical_findings ?? 0}
          icon={<AlertTriangle size={20} />}
          color="red"
          critical={(stats?.critical_findings ?? 0) > 0}
          demo
        />
        <StatCard
          label="High"
          value={stats?.high_findings ?? 0}
          icon={<AlertTriangle size={20} />}
          color="orange"
          demo
        />
        <StatCard
          label="Awaiting Review"
          value={stats?.findings_pending_review ?? 0}
          icon={<Eye size={20} />}
          color="yellow"
          demo
        />
        <StatCard
          label="Potential Duplicates"
          value={stats?.potential_duplicates ?? 0}
          icon={<Shield size={20} />}
          color="slate"
          demo
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Findings over time */}
        <div className="card p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Findings Over Time</h3>
              <p className="text-xs text-slate-500 mt-0.5">Demo project — November 2026</p>
            </div>
            <TrendingUp size={16} className="text-cyber-blue" />
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={FINDINGS_OVER_TIME} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="findingsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(59, 130, 246, 0.08)" />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#091428', border: '1px solid rgba(59, 130, 246, 0.2)', borderRadius: '8px', fontSize: '12px' }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Area type="monotone" dataKey="findings" stroke="#3b82f6" fill="url(#findingsGrad)" strokeWidth={2} name="Total Findings" />
              <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#critGrad)" strokeWidth={2} name="Critical" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity distribution */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Severity Distribution</h3>
              <p className="text-xs text-slate-500 mt-0.5">By effective severity</p>
            </div>
            <Target size={16} className="text-cyber-orange" />
          </div>
          {severityData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={index} fill={entry.color} opacity={0.85} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#091428', border: '1px solid rgba(59, 130, 246, 0.2)', borderRadius: '8px', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5 mt-2">
                {severityData.map((item) => (
                  <div key={item.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-sm" style={{ background: item.color }} />
                      <span className="text-slate-400">{item.name}</span>
                    </div>
                    <span className="font-medium text-slate-300">{item.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-32 text-slate-500 text-xs">
              No findings data
            </div>
          )}
        </div>
      </div>

      {/* Bottom row: Recent findings + Agent status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent findings table */}
        <div className="card lg:col-span-2">
          <div className="flex items-center justify-between p-5 border-b border-cyber-blue/10">
            <h3 className="text-sm font-semibold text-slate-200">Recent Findings</h3>
            <a href="/findings" className="text-xs text-cyber-blue hover:text-cyber-blue-bright flex items-center gap-1 transition-colors">
              View all <ChevronRight size={12} />
            </a>
          </div>
          <div className="overflow-x-auto">
            {recentFindings.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {recentFindings.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <div className="flex flex-col">
                          <span className="text-slate-200 font-medium text-xs line-clamp-1">{f.title}</span>
                          <span className="text-slate-500 text-xs mt-0.5 font-mono">{f.endpoint?.substring(0, 50)}</span>
                        </div>
                      </td>
                      <td><SeverityBadge severity={f.effective_severity} /></td>
                      <td><ValidationBadge status={f.validation_status} /></td>
                      <td>
                        <span className="text-xs text-slate-400 font-mono">
                          {f.source_tool || 'unknown'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="p-8 text-center">
                <Bug size={24} className="text-slate-600 mx-auto mb-2" />
                <p className="text-sm text-slate-500">
                  {error ? 'Start backend and seed demo data to see findings.' : 'No findings yet.'}
                </p>
                {error && (
                  <div className="mt-3 text-xs text-slate-600 font-mono bg-navy-900 rounded p-2 text-left max-w-sm mx-auto">
                    cd backend<br />
                    python seed_demo.py
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Agent status panel */}
        <div className="card">
          <div className="flex items-center justify-between p-5 border-b border-cyber-blue/10">
            <h3 className="text-sm font-semibold text-slate-200">Agent Activity</h3>
            <div className="demo-banner !text-xs">
              <FlaskConical size={10} />
              Demo
            </div>
          </div>
          <div className="p-4 space-y-3">
            {AGENT_ACTIVITY.map((agent) => (
              <div key={agent.name} className="flex items-center gap-3">
                <div className="w-7 h-7 rounded-lg bg-cyber-blue/10 flex items-center justify-center flex-shrink-0">
                  <Zap size={12} className="text-cyber-blue" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-slate-300 truncate">{agent.name}</div>
                  <div className="text-xs text-slate-500">{agent.tasks} tasks · {agent.time}</div>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-1.5 h-1.5 rounded-full bg-cyber-green" />
                  <span className="text-xs text-cyber-green">Done</span>
                </div>
              </div>
            ))}
          </div>
          <div className="px-4 pb-4">
            <a
              href="/agents"
              className="btn-secondary w-full text-center block text-xs !py-2"
            >
              View Full Activity Log
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
