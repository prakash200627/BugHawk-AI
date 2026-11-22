import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Server, ScanLine, Bug, Bot, Share2,
  Wrench, FileText, Activity, Shield, Settings, ChevronLeft,
  ChevronRight, Zap, AlertTriangle
} from 'lucide-react';
import clsx from 'clsx';
import { useSession } from '../../lib/session';

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  badge?: string;
  badgeType?: 'danger' | 'warning' | 'info';
}

const navItems: NavItem[] = [
  { path: '/', label: 'Overview', icon: <LayoutDashboard size={18} /> },
  { path: '/assets', label: 'Asset Inventory', icon: <Server size={18} /> },
  { path: '/scans', label: 'Scan Management', icon: <ScanLine size={18} /> },
  { path: '/findings', label: 'Vulnerability Intelligence', icon: <Bug size={18} /> },
  { path: '/analyst', label: 'AI Security Analyst', icon: <Bot size={18} /> },
  { path: '/attack-paths', label: 'Attack Path Analysis', icon: <Share2 size={18} /> },
  { path: '/remediation', label: 'Remediation Center', icon: <Wrench size={18} /> },
  { path: '/reports', label: 'Reports', icon: <FileText size={18} /> },
  { path: '/agents', label: 'Agent Activity', icon: <Activity size={18} /> },
  { path: '/scope', label: 'Scope Management', icon: <Shield size={18} /> },
  { path: '/settings', label: 'Settings', icon: <Settings size={18} /> },
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const { user } = useSession();

  return (
    <aside
      className={clsx(
        'flex flex-col h-screen bg-navy-900 border-r border-cyber-blue/10 transition-all duration-300 relative z-20',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-cyber-blue/10 flex-shrink-0">
        <div className="relative flex-shrink-0">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyber-blue to-cyber-blue-dim flex items-center justify-center glow-blue">
            <Zap size={16} className="text-white" />
          </div>
          {/* Live indicator */}
          <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-cyber-green border-2 border-navy-900 animate-pulse" />
        </div>

        {!collapsed && (
          <div className="animate-fade-in overflow-hidden">
            <div className="text-sm font-bold text-slate-100 leading-none whitespace-nowrap">
              BugHawk AI
            </div>
            <div className="text-xs text-cyber-blue font-medium mt-0.5 whitespace-nowrap">
              v2.0 Platform
            </div>
          </div>
        )}
      </div>

      {/* Demo banner */}
      {!collapsed && (
        <div className="mx-3 mt-3 px-3 py-2 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center gap-2 animate-fade-in">
          <AlertTriangle size={12} className="text-purple-400 flex-shrink-0" />
          <span className="text-xs text-purple-400 font-medium">Illustrations are labeled on their pages</span>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 overflow-y-auto scroll-area space-y-0.5">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={clsx(
                'nav-item group relative',
                isActive && 'active'
              )}
              title={collapsed ? item.label : undefined}
            >
              <span className={clsx(
                'flex-shrink-0 transition-colors duration-200',
                isActive ? 'text-cyber-blue' : 'text-slate-500 group-hover:text-slate-300'
              )}>
                {item.icon}
              </span>

              {!collapsed && (
                <span className="flex-1 text-sm whitespace-nowrap overflow-hidden">
                  {item.label}
                </span>
              )}

              {!collapsed && item.badge && (
                <span className={clsx(
                  'ml-auto text-xs px-1.5 py-0.5 rounded font-bold',
                  item.badgeType === 'danger' && 'bg-red-500/20 text-red-400',
                  item.badgeType === 'warning' && 'bg-yellow-500/20 text-yellow-400',
                  item.badgeType === 'info' && 'bg-blue-500/20 text-blue-400',
                )}>
                  {item.badge}
                </span>
              )}

              {/* Tooltip for collapsed mode */}
              {collapsed && (
                <div className="absolute left-full ml-2 px-2 py-1 rounded bg-navy-700 border border-cyber-blue/20 text-xs text-slate-200 whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                  {item.label}
                </div>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Platform info */}
      {!collapsed && (
        <div className="px-4 py-3 border-t border-cyber-blue/10 animate-fade-in">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <div className="w-1.5 h-1.5 rounded-full bg-cyber-green" />
            <span>{user?.role === 'viewer' ? 'Signed in · read-only' : 'Signed in'}</span>
          </div>
          <div className="text-xs text-slate-600 mt-1 truncate">{user?.email || 'Account'}</div>
          {user?.role && user.role !== 'viewer' && (
            <div className="text-xs text-slate-600 mt-1 capitalize">{user.role}</div>
          )}
        </div>
      )}

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-20 w-6 h-6 rounded-full bg-navy-700 border border-cyber-blue/20 flex items-center justify-center text-slate-400 hover:text-cyber-blue hover:border-cyber-blue/40 transition-all duration-200 z-30"
        id="sidebar-toggle"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
      </button>
    </aside>
  );
}
