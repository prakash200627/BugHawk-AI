import React, { useState } from 'react';
import {
  Settings, Zap, Bot, Shield, Wrench, Database, Key,
  Eye, EyeOff, Save, CheckCircle, FlaskConical, Info
} from 'lucide-react';
import clsx from 'clsx';

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
  const [showKey, setShowKey] = useState(false);
  const [saved, setSaved] = useState(false);
  const [demoMode, setDemoMode] = useState(true);
  const [llmProvider, setLlmProvider] = useState('demo');

  const save = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-5 max-w-3xl animate-fade-in">
      <div className="demo-banner">
        <FlaskConical size={12} />
        Settings — All configuration is stored server-side via environment variables. Changes here update .env only in demo mode.
      </div>

      {/* General */}
      <Section title="General" icon={<Settings size={14} className="text-cyber-blue" />}>
        <FieldRow label="Platform Name" desc="Displayed in reports and UI">
          <input className="input text-sm" defaultValue="BugHawk AI 2.0" readOnly />
        </FieldRow>
        <FieldRow label="Environment" desc="Current deployment environment">
          <div className="flex items-center gap-2">
            <span className="badge badge-demo">demo</span>
            <span className="text-xs text-slate-500">Set via ENVIRONMENT env var</span>
          </div>
        </FieldRow>
        <FieldRow label="Demo Mode" desc="Uses synthetic data, no real LLM calls">
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={demoMode}
              onChange={e => setDemoMode(e.target.checked)}
              className="sr-only peer"
              id="demo-mode-toggle"
            />
            <div className="w-11 h-6 bg-navy-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-blue border border-cyber-blue/20" />
            <span className="ml-2 text-sm text-slate-300">{demoMode ? 'Enabled' : 'Disabled'}</span>
          </label>
        </FieldRow>
      </Section>

      {/* AI Provider */}
      <Section title="AI Provider" icon={<Bot size={14} className="text-cyber-purple" />}>
        <div className="flex items-start gap-2 text-xs text-blue-300 bg-blue-500/10 border border-blue-500/20 rounded-lg px-3 py-2 mb-2">
          <Info size={12} className="flex-shrink-0 mt-0.5" />
          Configure via <code className="font-mono mx-1">LLM_PROVIDER</code> and <code className="font-mono">LLM_API_KEY</code> environment variables in your <code className="font-mono">.env</code> file.
        </div>
        <FieldRow label="Provider" desc="LLM backend for AI agents">
          <div className="flex flex-wrap gap-2">
            {['demo', 'openai', 'anthropic', 'google'].map(p => (
              <button
                key={p}
                onClick={() => setLlmProvider(p)}
                className={clsx(
                  'px-3 py-1.5 rounded-lg border text-xs font-medium transition-all',
                  llmProvider === p
                    ? 'bg-cyber-blue/20 border-cyber-blue/40 text-cyber-blue-bright'
                    : 'bg-navy-900 border-navy-700 text-slate-400 hover:text-slate-200'
                )}
                id={`provider-${p}`}
              >
                {p.charAt(0).toUpperCase() + p.slice(1)}
                {p === 'demo' && ' (no key needed)'}
              </button>
            ))}
          </div>
        </FieldRow>
        <FieldRow label="Model" desc="e.g. gpt-4o, claude-3-5-sonnet, gemini-2.0-flash">
          <input
            className="input text-sm font-mono"
            defaultValue={llmProvider === 'demo' ? 'demo-mode' : ''}
            placeholder="e.g. gpt-4o-mini"
            disabled={llmProvider === 'demo'}
            id="model-input"
          />
        </FieldRow>
        <FieldRow label="API Key" desc="Stored in .env, never logged">
          <div className="relative">
            <Key size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type={showKey ? 'text' : 'password'}
              className="input pl-9 pr-10 text-sm font-mono"
              placeholder={llmProvider === 'demo' ? 'Not required in demo mode' : 'sk-...'}
              disabled={llmProvider === 'demo'}
              id="api-key-input"
            />
            <button
              onClick={() => setShowKey(!showKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              id="toggle-key-visibility"
            >
              {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </FieldRow>
      </Section>

      {/* Security Tools */}
      <Section title="Security Tool Paths" icon={<Wrench size={14} className="text-cyber-orange" />}>
        <div className="text-xs text-slate-500 bg-navy-900 rounded-lg p-3 mb-2">
          Specify the paths to installed security tools. Leave blank to use system PATH.
          Configure via environment variables: <code className="text-cyber-blue">SUBFINDER_PATH</code>, <code className="text-cyber-blue">NUCLEI_PATH</code>, <code className="text-cyber-blue">SEMGREP_PATH</code>.
        </div>
        {[
          { key: 'SUBFINDER_PATH', label: 'Subfinder', placeholder: '/usr/local/bin/subfinder', category: 'recon' },
          { key: 'NUCLEI_PATH',    label: 'Nuclei',    placeholder: '/usr/local/bin/nuclei',    category: 'active' },
          { key: 'SEMGREP_PATH',   label: 'Semgrep',   placeholder: '/usr/local/bin/semgrep',   category: 'code' },
        ].map(tool => (
          <FieldRow key={tool.key} label={tool.label} desc={`${tool.key} env var`}>
            <div className="flex gap-2">
              <input className="input text-sm font-mono flex-1" placeholder={tool.placeholder} id={`tool-${tool.label.toLowerCase()}`} />
              <button className="btn-secondary text-xs !py-2 !px-3 whitespace-nowrap" id={`test-${tool.label.toLowerCase()}`}>Test Path</button>
            </div>
          </FieldRow>
        ))}
      </Section>

      {/* Rate Limiting */}
      <Section title="Rate Limiting" icon={<Shield size={14} className="text-cyber-green" />}>
        <FieldRow label="Max Requests/Second" desc="Per scan session rate limit">
          <input type="number" className="input text-sm w-32" defaultValue="10" id="rate-limit-input" />
        </FieldRow>
        <FieldRow label="Scan Concurrency" desc="Max simultaneous scan workers">
          <input type="number" className="input text-sm w-32" defaultValue="3" id="concurrency-input" />
        </FieldRow>
      </Section>

      {/* Database */}
      <Section title="Database" icon={<Database size={14} className="text-slate-400" />}>
        <FieldRow label="Connection" desc="Set via DATABASE_URL env var">
          <div className="flex items-center gap-2">
            <code className="text-xs font-mono text-slate-400 bg-navy-900 px-3 py-2 rounded-lg">postgresql://user:pass@localhost:5432/bughawk</code>
            <span className="badge badge-success flex items-center gap-1 text-xs"><CheckCircle size={10} />Connected</span>
          </div>
        </FieldRow>
      </Section>

      {/* Save */}
      <div className="flex justify-end">
        <button onClick={save} className="btn-primary flex items-center gap-2" id="save-settings-btn">
          {saved ? <><CheckCircle size={14} />Saved!</> : <><Save size={14} />Save Settings</>}
        </button>
      </div>
    </div>
  );
}
