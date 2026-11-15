import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import Layout from './components/layout/Layout';

// Lazy-loaded pages for optimal performance
const Overview       = lazy(() => import('./pages/Overview'));
const Assets         = lazy(() => import('./pages/Assets'));
const Scans          = lazy(() => import('./pages/Scans'));
const Findings       = lazy(() => import('./pages/Findings'));
const Analyst        = lazy(() => import('./pages/Analyst'));
const AttackPaths    = lazy(() => import('./pages/AttackPaths'));
const Remediation    = lazy(() => import('./pages/Remediation'));
const Reports        = lazy(() => import('./pages/Reports'));
const AgentActivity  = lazy(() => import('./pages/AgentActivity'));
const Scope          = lazy(() => import('./pages/Scope'));
const Settings       = lazy(() => import('./pages/Settings'));

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <Loader2 className="w-8 h-8 text-cyber-blue animate-spin mx-auto mb-3" />
        <p className="text-sm text-slate-400">Loading module...</p>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index          element={<Overview />} />
            <Route path="assets"       element={<Assets />} />
            <Route path="scans"        element={<Scans />} />
            <Route path="findings"     element={<Findings />} />
            <Route path="analyst"      element={<Analyst />} />
            <Route path="attack-paths" element={<AttackPaths />} />
            <Route path="remediation"  element={<Remediation />} />
            <Route path="reports"      element={<Reports />} />
            <Route path="agents"       element={<AgentActivity />} />
            <Route path="scope"        element={<Scope />} />
            <Route path="settings"     element={<Settings />} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
