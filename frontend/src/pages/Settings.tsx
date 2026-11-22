import React from 'react';
import {
  Settings, Bot, Shield, Wrench, Database, Key,
  Save, FlaskConical, Info
} from 'lucide-react';

function Section({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="card p-5 space-y-4">
      <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2 pb-3 border-b border-cyber-blue/10">
        {icon}{title}
      </h3>
      {children}
    </div>
  );
}

function FieldRow({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col md:flex-row md:items-center gap-3">
      <div className="md:w-56 flex-shrink-0">
        <div className="text-sm font-medium text-slate-300">{label}</div>
        {desc && <div className="text-xs text-slate-500 mt-0.5">{desc}</div>}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <div className="space-y-5 max-w-3xl animate-fade-in">
      <div className="demo-banner">
        <FlaskConical size={12} />
        Display only. Nothing on this page is saved. Server configuration stays in environment variables.
      </div>

      <Section title="General" icon={<Settings size={14} className="text-cyber-blue" />}>
        <FieldRow label="Platform Name" desc="Shown in the interface">
          <input className="input text-sm" defaultValue="BugHawk AI 2.0" readOnly />
        </FieldRow>
        <FieldRow label="Environment" desc="Current deployment environment">
          <div className="flex items-center gap-2">
            <span className="badge badge-demo">not loaded</span>
            <span className="text-xs text-slate-500">APP_ENV is read by the server. This page does not fetch it.</span>
          </div>
        </FieldRow>
        <FieldRow label="Demo Mode" desc="Server setting. This control cannot change it.">
          <label className="inline-flex items-center gap-2 text-sm text-slate-400">
            <input type="checkbox" disabled className="accent-cyber-blue" />
            Unavailable here
          </label>
        </FieldRow>
      </Section>

      <Section title="AI Provider" icon={<Bot size={14} className="text-cyber-purple" />}>
        <div className="flex items-start gap-2 text-xs text-blue-300 bg-blue-500/10 border border-blue-500/20 rounded-lg px-3 py-2">
          <Info size={12} className="flex-shrink-0 mt-0.5" />
          Provider and model are server environment values. Selecting a name here does not connect a model.
        </div>
        <FieldRow label="Provider" desc="Not editable in the browser">
          <div className="flex flex-wrap gap-2">
            {['demo', 'openai', 'anthropic', 'google'].map(p => (
              <button
                key={p}
                type="button"
                disabled
                className="px-3 py-1.5 rounded-lg border text-xs font-medium bg-navy-900 border-navy-700 text-slate-500 cursor-not-allowed"
              >
                {p.charAt(0).toUpperCase() + p.slice(1)}
              </button>
            ))}
          </div>
        </FieldRow>
        <FieldRow label="Model" desc="Not sent to the server">
          <input className="input text-sm font-mono" value="" placeholder="Unavailable" disabled readOnly />
        </FieldRow>
        <FieldRow label="API Key" desc="Keys are not entered or stored in the browser">
          <div className="relative">
            <Key size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="password"
              className="input pl-9 text-sm font-mono"
              placeholder="Not collected on this page"
              disabled
              readOnly
            />
          </div>
        </FieldRow>
      </Section>

      <Section title="Security Tool Paths" icon={<Wrench size={14} className="text-cyber-orange" />}>
        <p className="text-xs text-slate-500 bg-navy-900 rounded-lg p-3">
          Tool paths are server settings. These fields are disabled, and path checks are not available.
        </p>
        {[
          { key: 'SUBFINDER_PATH', label: 'Subfinder' },
          { key: 'HTTPX_PATH', label: 'httpx' },
          { key: 'NUCLEI_PATH', label: 'Nuclei' },
          { key: 'SEMGREP_PATH', label: 'Semgrep' },
        ].map(tool => (
          <FieldRow key={tool.key} label={tool.label} desc={`${tool.key} is not edited here`}>
            <div className="flex gap-2">
              <input className="input text-sm font-mono flex-1" placeholder="Unavailable" disabled readOnly />
              <button type="button" disabled className="btn-secondary text-xs !py-2 !px-3 whitespace-nowrap opacity-60 cursor-not-allowed">
                Test unavailable
              </button>
            </div>
          </FieldRow>
        ))}
      </Section>

      <Section title="Rate Limiting" icon={<Shield size={14} className="text-cyber-green" />}>
        <FieldRow label="Max Requests/Second" desc="Not configured from this page">
          <input type="text" className="input text-sm w-40" value="Unavailable" disabled readOnly />
        </FieldRow>
        <FieldRow label="Scan Concurrency" desc="Not configured from this page">
          <input type="text" className="input text-sm w-40" value="Unavailable" disabled readOnly />
        </FieldRow>
      </Section>

      <Section title="Database" icon={<Database size={14} className="text-slate-400" />}>
        <FieldRow label="Connection" desc="Set with DATABASE_URL on the server">
          <p className="text-sm text-slate-400">
            Credentials stay on the server. This page does not display a connection string or a connection status.
          </p>
        </FieldRow>
      </Section>

      <div className="flex justify-end">
        <button type="button" disabled className="btn-primary flex items-center gap-2 opacity-60 cursor-not-allowed">
          <Save size={14} />Nothing to save
        </button>
      </div>
    </div>
  );
}
