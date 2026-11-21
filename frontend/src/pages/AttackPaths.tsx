import React, { useEffect, useState, useCallback } from 'react';
import {
  Share2, FlaskConical, AlertTriangle, Shield, Bug,
  Server, Globe, Loader2, Info
} from 'lucide-react';
import ReactFlow, {
  Node, Edge, Background, Controls, MiniMap,
  BackgroundVariant, MarkerType, NodeTypes
} from 'reactflow';
import 'reactflow/dist/style.css';

// ─── Custom Node Components ──────────────────────────────────────────────────

function AssetNode({ data }: { data: { label: string; sub?: string; status?: string } }) {
  return (
    <div className="bg-navy-700 border border-cyber-blue/40 rounded-lg px-4 py-3 min-w-[140px] shadow-lg">
      <div className="flex items-center gap-2 mb-1">
        <Server size={12} className="text-cyber-blue flex-shrink-0" />
        <span className="text-xs font-semibold text-cyber-blue-bright truncate">{data.label}</span>
      </div>
      {data.sub && <p className="text-xs text-slate-400 pl-5">{data.sub}</p>}
    </div>
  );
}

function VulnNode({ data }: { data: { label: string; severity?: string; cwe?: string } }) {
  const sevColor: Record<string, string> = {
    critical: 'border-red-500/70 bg-red-500/10',
    high: 'border-orange-500/70 bg-orange-500/10',
    medium: 'border-yellow-500/70 bg-yellow-500/10',
    low: 'border-blue-500/70 bg-blue-500/10',
  };
  const cls = sevColor[data.severity || 'low'] || sevColor.low;
  return (
    <div className={`border rounded-lg px-4 py-3 min-w-[150px] shadow-lg ${cls}`}>
      <div className="flex items-center gap-2 mb-1">
        <Bug size={12} className="text-cyber-orange flex-shrink-0" />
        <span className="text-xs font-semibold text-slate-200 truncate">{data.label}</span>
      </div>
      {data.severity && (
        <span className={`text-xs font-bold uppercase ${data.severity === 'critical' ? 'text-red-400' : data.severity === 'high' ? 'text-orange-400' : data.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400'}`}>
          {data.severity}
        </span>
      )}
      {data.cwe && <p className="text-xs text-slate-500 mt-0.5">{data.cwe}</p>}
    </div>
  );
}

function ImpactNode({ data }: { data: { label: string; sub?: string } }) {
  return (
    <div className="bg-red-500/10 border border-red-500/40 rounded-lg px-4 py-3 min-w-[140px] shadow-lg">
      <div className="flex items-center gap-2 mb-1">
        <AlertTriangle size={12} className="text-red-400 flex-shrink-0" />
        <span className="text-xs font-semibold text-red-300 truncate">{data.label}</span>
      </div>
      {data.sub && <p className="text-xs text-slate-400 pl-5">{data.sub}</p>}
    </div>
  );
}

function EndpointNode({ data }: { data: { label: string } }) {
  return (
    <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg px-3 py-2 min-w-[120px] shadow-lg">
      <div className="flex items-center gap-2">
        <Globe size={11} className="text-purple-400 flex-shrink-0" />
        <span className="text-xs text-purple-300 font-mono truncate">{data.label}</span>
      </div>
    </div>
  );
}

const nodeTypes: NodeTypes = {
  asset: AssetNode,
  vuln: VulnNode,
  impact: ImpactNode,
  endpoint: EndpointNode,
};

// ─── Demo graph data ─────────────────────────────────────────────────────────

const DEMO_NODES: Node[] = [
  // Assets
  { id: 'asset-1', type: 'asset', position: { x: 60,  y: 200 }, data: { label: 'demo-app.internal', sub: 'Main web app' } },
  { id: 'asset-2', type: 'asset', position: { x: 60,  y: 320 }, data: { label: 'api.demo-app.internal', sub: 'REST API' } },
  // Endpoints
  { id: 'ep-1', type: 'endpoint', position: { x: 300, y: 160 }, data: { label: '/admin/dashboard' } },
  { id: 'ep-2', type: 'endpoint', position: { x: 300, y: 260 }, data: { label: '/api/v1/users' } },
  { id: 'ep-3', type: 'endpoint', position: { x: 300, y: 360 }, data: { label: '/api/v1/upload' } },
  // Vulnerabilities
  { id: 'vuln-1', type: 'vuln', position: { x: 540, y: 100 }, data: { label: 'SQL Injection', severity: 'critical', cwe: 'CWE-89' } },
  { id: 'vuln-2', type: 'vuln', position: { x: 540, y: 230 }, data: { label: 'Broken Auth', severity: 'high', cwe: 'CWE-287' } },
  { id: 'vuln-3', type: 'vuln', position: { x: 540, y: 360 }, data: { label: 'Path Traversal', severity: 'high', cwe: 'CWE-22' } },
  // Impacts
  { id: 'impact-1', type: 'impact', position: { x: 780, y: 150 }, data: { label: 'Data Exfiltration', sub: 'Hypothetical' } },
  { id: 'impact-2', type: 'impact', position: { x: 780, y: 310 }, data: { label: 'Privilege Escalation', sub: 'Hypothetical' } },
];

const confirmed = { animated: false, style: { stroke: '#3b82f6', strokeWidth: 2 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' } };
const hypothetical = { animated: true, style: { stroke: '#f97316', strokeWidth: 1.5, strokeDasharray: '5 3' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#f97316' } };

const DEMO_EDGES: Edge[] = [
  // asset → endpoint (confirmed)
  { id: 'e1', source: 'asset-1', target: 'ep-1', ...confirmed },
  { id: 'e2', source: 'asset-2', target: 'ep-2', ...confirmed },
  { id: 'e3', source: 'asset-2', target: 'ep-3', ...confirmed },
  // endpoint → vuln (confirmed findings)
  { id: 'e4', source: 'ep-1', target: 'vuln-1', ...confirmed, label: 'scanner finding' },
  { id: 'e5', source: 'ep-2', target: 'vuln-2', ...confirmed, label: 'scanner finding' },
  { id: 'e6', source: 'ep-3', target: 'vuln-3', ...confirmed, label: 'scanner finding' },
  // vuln → impact (hypothetical)
  { id: 'e7', source: 'vuln-1', target: 'impact-1', ...hypothetical, label: 'hypothetical' },
  { id: 'e8', source: 'vuln-2', target: 'impact-2', ...hypothetical, label: 'hypothetical' },
  { id: 'e9', source: 'vuln-3', target: 'impact-1', ...hypothetical },
];

export default function AttackPathsPage() {
  return (
    <div className="space-y-5 animate-fade-in">
      {/* Demo banner */}
      <div className="demo-banner">
        <FlaskConical size={12} />
        Attack Path Analysis — demo illustration only. This graph is not loaded from the API and is not your account data. Hypothetical paths are not confirmed exploits.
      </div>

      {/* Legend */}
      <div className="card p-4 flex flex-wrap gap-6 text-xs">
        <div className="flex items-center gap-2 font-medium text-slate-300">
          <div className="w-8 h-0.5 bg-cyber-blue" />
          <span>Confirmed relationship (scanner evidence)</span>
        </div>
        <div className="flex items-center gap-2 font-medium text-slate-300">
          <div className="w-8 h-0.5 bg-cyber-orange border-dashed" style={{ borderTop: '2px dashed #f97316', background: 'none' }} />
          <span>Hypothetical attack path (not confirmed)</span>
        </div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded bg-cyber-blue/30 border border-cyber-blue/50" /><span className="text-slate-400">Asset</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded bg-orange-500/20 border border-orange-500/40" /><span className="text-slate-400">Vulnerability</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded bg-red-500/20 border border-red-500/40" /><span className="text-slate-400">Potential Impact</span></div>
        <div className="flex items-center gap-2"><div className="w-3 h-3 rounded bg-purple-500/20 border border-purple-500/40" /><span className="text-slate-400">Endpoint</span></div>
      </div>

      {/* Warning */}
      <div className="flex items-start gap-3 px-4 py-3 rounded-lg bg-orange-500/8 border border-orange-500/20 text-xs text-orange-300">
        <Info size={14} className="flex-shrink-0 mt-0.5" />
        <span>
          <strong>Important:</strong> Dashed orange edges represent <em>hypothetical</em> attack paths derived from vulnerability correlation.
          They do not represent confirmed exploitation chains. All active testing requires explicit authorization.
        </span>
      </div>

      {/* React Flow graph */}
      <div className="card overflow-hidden" style={{ height: '540px' }}>
        <ReactFlow
          nodes={DEMO_NODES}
          edges={DEMO_EDGES}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          attributionPosition="bottom-right"
          proOptions={{ hideAttribution: true }}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={24}
            size={1}
            color="rgba(59,130,246,0.15)"
          />
          <Controls className="bg-navy-800 border border-cyber-blue/20 rounded-lg" />
          <MiniMap
            className="bg-navy-900 border border-cyber-blue/15 rounded-lg"
            nodeColor={(node) => {
              if (node.type === 'asset') return '#3b82f6';
              if (node.type === 'vuln') return '#f97316';
              if (node.type === 'impact') return '#ef4444';
              return '#8b5cf6';
            }}
            maskColor="rgba(2,8,24,0.7)"
          />
        </ReactFlow>
      </div>

      {/* Summary table */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-cyber-blue/10">
          <h3 className="text-sm font-semibold text-slate-200">Identified Attack Paths</h3>
        </div>
        <table className="data-table">
          <thead>
            <tr><th>Entry Point</th><th>Vulnerability</th><th>Potential Impact</th><th>Type</th><th>Status</th></tr>
          </thead>
          <tbody>
            {[
              { entry: '/admin/dashboard', vuln: 'SQL Injection (CWE-89)', impact: 'Data Exfiltration', type: 'Hypothetical', severity: 'critical' },
              { entry: '/api/v1/users', vuln: 'Broken Authentication (CWE-287)', impact: 'Privilege Escalation', type: 'Hypothetical', severity: 'high' },
              { entry: '/api/v1/upload', vuln: 'Path Traversal (CWE-22)', impact: 'Data Exfiltration', type: 'Hypothetical', severity: 'high' },
            ].map((path, i) => (
              <tr key={i}>
                <td><span className="font-mono text-xs text-purple-300">{path.entry}</span></td>
                <td><span className="text-xs text-slate-300">{path.vuln}</span></td>
                <td><span className="text-xs text-red-300">{path.impact}</span></td>
                <td><span className="badge bg-orange-500/15 text-orange-400 border border-orange-500/25 text-xs">{path.type}</span></td>
                <td><span className={`badge text-xs ${path.severity === 'critical' ? 'badge-critical' : 'badge-high'}`}>{path.severity.toUpperCase()}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
