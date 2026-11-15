import React, { useEffect, useState } from 'react';
import { Bell, Search, RefreshCw, Zap } from 'lucide-react';
import { healthApi } from '../../lib/api';
import type { HealthResponse } from '../../types';

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export default function Header({ title, subtitle }: HeaderProps) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [checking, setChecking] = useState(false);

  const checkHealth = async () => {
    setChecking(true);
    try {
      const res = await healthApi.check();
      setHealth(res.data);
    } catch {
      setHealth(null);
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
        {/* Search */}
        <div className="relative hidden md:flex items-center">
          <Search size={14} className="absolute left-3 text-slate-500" />
          <input
            type="text"
            placeholder="Search findings, assets..."
            className="input pl-9 pr-4 py-1.5 w-56 text-xs"
            id="global-search"
          />
        </div>

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
          <span className={health ? 'text-cyber-green' : 'text-red-400'}>
            {health ? 'API Online' : 'API Offline'}
          </span>
        </button>

        {/* Notifications */}
        <button
          className="relative p-2 rounded-lg bg-navy-800 border border-cyber-blue/15 text-slate-400 hover:text-slate-200 hover:border-cyber-blue/30 transition-all"
          id="notifications-btn"
          aria-label="Notifications"
        >
          <Bell size={16} />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-cyber-orange border border-navy-800" />
        </button>

        {/* User avatar */}
        <div
          className="w-8 h-8 rounded-full bg-gradient-to-br from-cyber-blue to-cyber-purple flex items-center justify-center cursor-pointer"
          id="user-menu-btn"
          title="demo@bughawk.ai"
        >
          <Zap size={14} className="text-white" />
        </div>
      </div>
    </header>
  );
}
