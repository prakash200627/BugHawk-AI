import React, { useEffect, useState } from 'react';
import { LogOut, RefreshCw } from 'lucide-react';
import { apiErrorMessage, healthApi, projectsApi } from '../../lib/api';
import { useSession } from '../../lib/session';
import type { HealthResponse } from '../../types';

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export default function Header({ title, subtitle }: HeaderProps) {
  const { user, projects, projectId, selectProject, refreshProjects, logout } = useSession();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthState, setHealthState] = useState<'unknown' | 'online' | 'offline'>('unknown');
  const [checking, setChecking] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [projectError, setProjectError] = useState('');

  const checkHealth = async () => {
    setChecking(true);
    try {
      const res = await healthApi.check();
      setHealth(res.data);
      setHealthState(res.data?.status === 'ok' ? 'online' : 'offline');
    } catch {
      setHealth(null);
      setHealthState('offline');
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 flex items-center justify-between px-6 border-b border-cyber-blue/10 bg-navy-900/60 backdrop-blur-sm flex-shrink-0">
      {/* Page title */}
      <div>
        <h1 className="text-lg font-semibold text-slate-100">{title}</h1>
        {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
      </div>

      {/* Right controls */}
      <div className="flex items-center gap-3">
        <select
          className="input py-1.5 text-xs max-w-[180px]"
          value={projectId || ''}
          onChange={(event) => selectProject(event.target.value)}
          aria-label="Selected project"
        >
          {projects.length === 0 && <option value="">No projects</option>}
          {projects.map((project) => (
            <option key={project.id} value={project.id}>{project.name}</option>
          ))}
        </select>
        <form
          className="flex items-center gap-2"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!projectName.trim()) return;
            setProjectError('');
            try {
              const created = await projectsApi.create({ name: projectName.trim() });
              setProjectName('');
              await refreshProjects(created.data.id);
            } catch (err: unknown) {
              setProjectError(apiErrorMessage(err, 'Project was not created.'));
            }
          }}
        >
          <input
            className="input py-1.5 w-36 text-xs"
            placeholder="New project"
            value={projectName}
            onChange={(event) => setProjectName(event.target.value)}
          />
          <button className="btn-secondary text-xs py-1.5" type="submit">Add</button>
        </form>

        {/* Backend status */}
        <button
          onClick={checkHealth}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-800 border border-cyber-blue/15 text-xs hover:border-cyber-blue/30 transition-all"
          id="health-check-btn"
          title="Check backend health"
        >
          <RefreshCw
            size={12}
            className={`text-slate-400 ${checking ? 'animate-spin' : ''}`}
          />
          <span className={healthState === 'online' ? 'text-cyber-green' : healthState === 'offline' ? 'text-red-400' : 'text-slate-400'}>
            {healthState === 'online' ? 'API Online' : healthState === 'offline' ? 'API Offline' : 'Checking API'}
          </span>
          {projectError && <span className="text-xs text-red-400 max-w-[180px] truncate" title={projectError}>{projectError}</span>}
        </button>

        <button
          className="p-2 rounded-lg bg-navy-800 border border-cyber-blue/15 text-slate-400 hover:text-slate-200"
          onClick={() => { logout(); window.location.href = '/login'; }}
          aria-label="Sign out"
          title={user?.email || 'Sign out'}
        >
          <LogOut size={16} />
        </button>
      </div>
    </header>
  );
}
