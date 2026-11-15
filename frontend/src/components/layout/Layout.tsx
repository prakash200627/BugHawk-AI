import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import { useLocation } from 'react-router-dom';

const PAGE_TITLES: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'Overview', subtitle: 'Security intelligence dashboard' },
  '/assets': { title: 'Asset Inventory', subtitle: 'Discovered and authorized assets' },
  '/scans': { title: 'Scan Management', subtitle: 'Configure and monitor security scans' },
  '/findings': { title: 'Vulnerability Intelligence', subtitle: 'Evidence-grounded security findings' },
  '/analyst': { title: 'AI Security Analyst', subtitle: 'AI-powered vulnerability analysis and Q&A' },
  '/attack-paths': { title: 'Attack Path Analysis', subtitle: 'Visualize vulnerability relationships' },
  '/remediation': { title: 'Remediation Center', subtitle: 'Actionable fix guidance' },
  '/reports': { title: 'Reports', subtitle: 'Generate professional security reports' },
  '/agents': { title: 'Agent Activity', subtitle: 'Multi-agent AI orchestration log' },
  '/scope': { title: 'Scope Management', subtitle: 'Authorized assessment targets' },
  '/settings': { title: 'Settings', subtitle: 'Platform configuration' },
};

export default function Layout() {
  const location = useLocation();
  const page = PAGE_TITLES[location.pathname] || { title: 'BugHawk AI 2.0', subtitle: '' };

  return (
    <div className="flex h-screen overflow-hidden bg-navy-950 cyber-grid-bg">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title={page.title} subtitle={page.subtitle} />
        <main className="flex-1 overflow-y-auto scroll-area p-6 animate-fade-in">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
