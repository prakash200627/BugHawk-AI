import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import { useLocation } from 'react-router-dom';

const PAGE_TITLES: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'Overview', subtitle: 'Security intelligence dashboard' },
  '/assets': { title: 'Asset Inventory', subtitle: 'Discovered and authorized assets' },
  '/scans': { title: 'Scan Management', subtitle: 'Scanners run in the worker. Semgrep waits for a source archive.' },
  '/findings': { title: 'Vulnerability Intelligence', subtitle: 'Findings stored for the selected project' },
  '/analyst': { title: 'AI Security Analyst', subtitle: 'Canned replies in demo mode. Otherwise unavailable.' },
  '/attack-paths': { title: 'Attack Path Analysis', subtitle: 'Illustration. Not loaded from this account.' },
  '/remediation': { title: 'Remediation Center', subtitle: 'Stored suggestions and status updates' },
  '/reports': { title: 'Reports', subtitle: 'JSON reports from stored records' },
  '/agents': { title: 'Agent Activity', subtitle: 'Illustration. Not an execution log.' },
  '/scope': { title: 'Scope Management', subtitle: 'Authorized assessment targets' },
  '/settings': { title: 'Settings', subtitle: 'Display only. Changes are not saved.' },
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
