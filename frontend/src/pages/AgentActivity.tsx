import React from 'react';
import { Activity, Zap, Bot, CheckCircle, Clock, FlaskConical, Terminal } from 'lucide-react';

const DEMO_EXECUTIONS = [
  {
    id: '1', agent: 'Orchestrator', status: 'completed', finding: 'N/A',
    description: 'Initialized LangGraph workflow. Loaded 5 findings from demo project.',
    tokens: 410, started: '2026-11-14T08:00:00Z', duration: '0.3s',
  },
  {
    id: '2', agent: 'Scope Guardian', status: 'completed', finding: 'N/A',
    description: 'Validated 5 assets against 2 scope rules. All within authorized scope.',
    tokens: 0, started: '2026-11-14T08:00:01Z', duration: '0.01s',
  },
  {
    id: '3', agent: 'Recon Agent', status: 'completed', finding: 'N/A',
    description: 'Processed Subfinder output. Discovered 5 subdomains. 0 rejected (out of scope).',
    tokens: 320, started: '2026-11-14T08:00:02Z', duration: '1.2s',
  },
  {
    id: '4', agent: 'Scan Agent', status: 'completed', finding: 'N/A',
    description: 'Normalized Nuclei and Semgrep findings. Stored 5 security findings with evidence.',
    tokens: 580, started: '2026-11-14T08:01:00Z', duration: '2.1s',
  },
  {
    id: '5', agent: 'AI Analyst', status: 'completed', finding: 'SQL Injection via unsanitized input',
    description: 'Analyzed evidence. Assessed severity: CRITICAL. Identified CWE-89. Confidence: HIGH.',
    tokens: 1240, started: '2026-11-14T08:03:00Z', duration: '4.3s',
  },
  {
    id: '6', agent: 'AI Analyst', status: 'completed', finding: 'Hardcoded AWS credentials',
    description: 'Analyzed static analysis finding. Confirmed: active credentials. Severity: CRITICAL.',
    tokens: 980, started: '2026-11-14T08:03:10Z', duration: '3.8s',
  },
  {
    id: '7', agent: 'Triage Agent', status: 'completed', finding: 'All 5 findings',
    description: 'Duplicate detection: 0 duplicates found. Confidence assessment complete. 2 findings flagged for human review.',
    tokens: 760, started: '2026-11-14T08:04:00Z', duration: '5.1s',
  },
  {
    id: '8', agent: 'Correlation Agent', status: 'completed', finding: 'N/A',
    description: 'Built attack path graph. Identified 3 potential paths. Marked as hypothetical — not confirmed exploitation.',
    tokens: 890, started: '2026-11-14T08:05:00Z', duration: '6.2s',
  },
  {
    id: '9', agent: 'Remediation Agent', status: 'completed', finding: 'All 5 findings',
    description: 'Generated 5 remediation suggestions with secure code examples and verification checklists.',
    tokens: 2100, started: '2026-11-14T08:06:00Z', duration: '8.4s',
  },
  {
    id: '10', agent: 'Orchestrator', status: 'completed', finding: 'N/A',
    description: 'Workflow complete. Awaiting human review. 2 findings require manual validation before report generation.',
    tokens: 210, started: '2026-11-14T08:07:00Z', duration: '0.1s',
  },
];

const TOTAL_TOKENS = DEMO_EXECUTIONS.reduce((s, e) => s + e.tokens, 0);

function StatusDot({ status }: { status: string }) {
  if (status === 'completed') return <div className="w-2 h-2 rounded-full bg-cyber-green" />;
  if (status === 'running')   return <div className="w-2 h-2 rounded-full bg-cyber-blue animate-pulse" />;
  if (status === 'failed')    return <div className="w-2 h-2 rounded-full bg-red-500" />;
  return <div className="w-2 h-2 rounded-full bg-slate-500" />;
}

export default function AgentActivityPage() {
  return (
    <div className="space-y-5 animate-fade-in">
      <div className="demo-banner"><FlaskConical size={12} />Agent Activity — demo illustration only. This log is not loaded from the API and is not your account data.</div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total Executions', value: DEMO_EXECUTIONS.length, color: 'text-cyber-blue', icon: <Activity size={18} /> },
          { label: 'Completed', value: DEMO_EXECUTIONS.filter(e => e.status === 'completed').length, color: 'text-cyber-green', icon: <CheckCircle size={18} /> },
          { label: 'Total LLM Tokens', value: TOTAL_TOKENS.toLocaleString(), color: 'text-cyber-orange', icon: <Zap size={18} /> },
          { label: 'Agents Used', value: new Set(DEMO_EXECUTIONS.map(e => e.agent)).size, color: 'text-purple-400', icon: <Bot size={18} /> },
        ].map(s => (
          <div key={s.label} className="stat-card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{s.label}</p>
                <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
              </div>
              <div className="p-2 rounded-lg bg-navy-900 text-slate-500">{s.icon}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Workflow diagram */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
          <Zap size={14} className="text-cyber-blue" />LangGraph Orchestration Flow
        </h3>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {['Scope Guardian', 'Recon Agent', 'Scan Agent', 'AI Analyst', 'Triage Agent', 'Correlation Agent', 'Remediation Agent', 'Human Review', 'Report'].map((step, i, arr) => (
            <React.Fragment key={step}>
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-blue/10 border border-cyber-blue/25 text-cyber-blue-bright font-medium">
                <StatusDot status="completed" />
                {step}
              </div>
              {i < arr.length - 1 && <span className="text-slate-600">→</span>}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Execution log */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between p-5 border-b border-cyber-blue/10">
          <h3 className="text-sm font-semibold text-slate-200">Execution Log</h3>
          <span className="text-xs text-slate-400">Most recent run — Demo project</span>
        </div>
        <div className="divide-y divide-cyber-blue/5">
          {DEMO_EXECUTIONS.map((exec, i) => (
            <div key={exec.id} className="flex gap-4 p-4 hover:bg-cyber-blue/5 transition-colors" id={`exec-${exec.id}`}>
              {/* Timeline line */}
              <div className="flex flex-col items-center gap-1 flex-shrink-0">
                <div className="w-6 h-6 rounded-full bg-navy-900 border border-cyber-blue/20 flex items-center justify-center">
                  <StatusDot status={exec.status} />
                </div>
                {i < DEMO_EXECUTIONS.length - 1 && <div className="w-px flex-1 bg-cyber-blue/10 min-h-4" />}
              </div>
              {/* Content */}
              <div className="flex-1 min-w-0 pb-2">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="text-sm font-semibold text-slate-200 flex items-center gap-1.5">
                    <Bot size={12} className="text-cyber-blue" />
                    {exec.agent}
                  </span>
                  <span className="badge badge-success text-xs flex items-center gap-1">
                    <CheckCircle size={9} /> Done
                  </span>
                  <span className="text-xs text-slate-500 font-mono">{exec.duration}</span>
                  {exec.tokens > 0 && (
                    <span className="text-xs text-slate-500 flex items-center gap-1">
                      <Zap size={10} className="text-cyber-orange" />
                      {exec.tokens} tokens
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{exec.description}</p>
                {exec.finding !== 'N/A' && (
                  <div className="mt-1.5 flex items-center gap-1.5 text-xs text-cyber-blue-bright">
                    <Terminal size={10} />
                    <span className="font-mono">{exec.finding}</span>
                  </div>
                )}
                <p className="text-xs text-slate-600 mt-1">{new Date(exec.started).toLocaleTimeString()}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
