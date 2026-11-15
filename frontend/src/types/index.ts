// BugHawk AI 2.0 — Shared TypeScript Types

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type ValidationStatus = 'pending' | 'confirmed' | 'false_positive' | 'needs_review' | 'duplicate';
export type ConfidenceLevel = 'high' | 'medium' | 'low' | 'unverified';
export type RemediationStatus = 'pending' | 'accepted' | 'in_progress' | 'completed' | 'wont_fix';
export type AssetStatus = 'live' | 'down' | 'unknown' | 'out_of_scope';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type AgentStatus = 'pending' | 'running' | 'completed' | 'failed' | 'waiting_human';

// ============================================================
// Health
// ============================================================

export interface HealthResponse {
  status: string;
  version: string;
  environment: string;
  database: string;
  demo_mode: boolean;
  timestamp: string;
}

// ============================================================
// Projects
// ============================================================

export interface Project {
  id: string;
  name: string;
  description?: string;
  is_demo: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  asset_count: number;
  finding_count: number;
  critical_count: number;
}

// ============================================================
// Scopes
// ============================================================

export interface AuthorizedScope {
  id: string;
  project_id: string;
  scope_value: string;
  is_wildcard: boolean;
  is_active: boolean;
  notes?: string;
  authorized_by?: string;
  created_at: string;
}

export interface ScopeValidationResult {
  target: string;
  normalized_host: string;
  decision: 'allowed' | 'denied' | 'invalid';
  matched_rule?: string;
  reason: string;
  is_allowed: boolean;
}

// ============================================================
// Assets
// ============================================================

export interface Asset {
  id: string;
  project_id: string;
  hostname: string;
  asset_type: string;
  status: AssetStatus;
  ip_addresses?: string[];
  technologies?: string[];
  http_status_code?: number;
  title?: string;
  discovery_source?: string;
  is_in_scope: boolean;
  is_demo: boolean;
  last_seen?: string;
  created_at: string;
}

// ============================================================
// Scans
// ============================================================

export interface ScanJob {
  id: string;
  project_id: string;
  name: string;
  target: string;
  modules: string[];
  status: ScanStatus;
  scope_validated: boolean;
  started_at?: string;
  completed_at?: string;
  findings_count: number;
  error_message?: string;
  is_demo: boolean;
  created_at: string;
}

// ============================================================
// Findings
// ============================================================

export interface SecurityFinding {
  id: string;
  project_id: string;
  asset_id?: string;
  scan_job_id?: string;
  title: string;
  vulnerability_type?: string;
  cve_id?: string;
  cwe_id?: string;
  cvss_score?: number;
  endpoint?: string;
  scanner_severity: Severity;
  ai_severity?: Severity;
  effective_severity: Severity;
  description?: string;
  impact?: string;
  remediation?: string;
  evidence?: Record<string, unknown>;
  confidence: ConfidenceLevel;
  validation_status: ValidationStatus;
  risk_score?: number;
  risk_factors?: Record<string, unknown>;
  source_tool?: string;
  is_demo: boolean;
  needs_human_review: boolean;
  ai_explanation?: string;
  ai_analyzed_at?: string;
  created_at: string;
}

// ============================================================
// AI Agents
// ============================================================

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface AgentChatResponse {
  response: string;
  finding_context?: Record<string, unknown>;
  agent_execution_id?: string;
  is_demo: boolean;
}

export interface AgentAnalyzeResponse {
  finding_id: string;
  execution_id: string;
  status: string;
  explanation?: string;
  severity_assessment?: string;
  confidence?: string;
  impact?: string;
  remediation_summary?: string;
  verification_steps?: string[];
  is_demo: boolean;
}

// ============================================================
// Remediation
// ============================================================

export interface RemediationSuggestion {
  id: string;
  finding_id: string;
  root_cause?: string;
  impact?: string;
  recommendation?: string;
  secure_code_example?: string;
  code_language?: string;
  verification_checklist?: string[];
  status: RemediationStatus;
  ai_generated: boolean;
  created_at: string;
}

// ============================================================
// Reports
// ============================================================

export interface SecurityReport {
  id: string;
  project_id: string;
  title: string;
  report_format: string;
  file_path?: string;
  file_size?: number;
  findings_count: number;
  is_demo: boolean;
  created_at: string;
}

// ============================================================
// Dashboard Stats
// ============================================================

export interface DashboardStats {
  total_assets: number;
  live_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  potential_duplicates: number;
  findings_pending_review: number;
  total_scans: number;
  active_scans: number;
}
