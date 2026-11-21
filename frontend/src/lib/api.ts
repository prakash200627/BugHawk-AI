// BugHawk AI 2.0 — Axios API Client
import axios from 'axios';

const configuredOrigin = import.meta.env.VITE_API_BASE_URL?.trim().replace(/\/$/, '');
const api = axios.create({
  baseURL: configuredOrigin ? `${configuredOrigin}/api` : '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor — attach auth token when available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('bughawk_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor — handle auth errors globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const path = String(error.config?.url || '');
    if (error.response?.status === 401 && !path.includes('/auth/login')) {
      localStorage.removeItem('bughawk_token');
      if (window.location.pathname !== '/login') window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// ============================================================
// API Functions
// ============================================================

export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),
  me: () => api.get('/auth/me'),
};

export const healthApi = {
  check: () => api.get('/health'),
};

export const projectsApi = {
  list: () => api.get('/projects'),
  get: (id: string) => api.get(`/projects/${id}`),
  create: (data: { name: string; description?: string }) => api.post('/projects', data),
  update: (id: string, data: object) => api.patch(`/projects/${id}`, data),
};

export const scopesApi = {
  list: (projectId: string) => api.get('/scopes', { params: { project_id: projectId } }),
  add: (projectId: string, data: { scope_value: string; notes?: string; authorized_by?: string }) =>
    api.post('/scopes', data, { params: { project_id: projectId } }),
  validate: (data: { target: string; project_id: string }) => api.post('/scopes/validate', data),
  delete: (scopeId: string) => api.delete(`/scopes/${scopeId}`),
};

export const assetsApi = {
  list: (projectId: string, params?: { status?: string; search?: string }) =>
    api.get('/assets', { params: { project_id: projectId, ...params } }),
  import: (data: { project_id: string; assets: object[] }) => api.post('/assets/import', data),
};

export const scansApi = {
  list: (projectId: string) => api.get('/scans', { params: { project_id: projectId } }),
  get: (id: string) => api.get(`/scans/${id}`),
  create: (data: { project_id: string; name: string; target: string; modules: string[] }) =>
    api.post('/scans', data),
};

export const findingsApi = {
  list: (projectId: string, params?: {
    severity?: string;
    validation_status?: string;
    source_tool?: string;
    search?: string;
  }) => api.get('/findings', { params: { project_id: projectId, ...params } }),
  get: (id: string) => api.get(`/findings/${id}`),
  stats: (projectId: string) => api.get(`/findings/stats/${projectId}`),
  import: (data: object) => api.post('/findings/import', data),
};

export const agentsApi = {
  chat: (data: { project_id: string; messages: object[]; finding_id?: string }) =>
    api.post('/agents/chat', data),
  analyze: (findingId: string, projectId: string) =>
    api.post(`/agents/analyze/${findingId}`, { project_id: projectId }),
};

export const remediationApi = {
  get: (findingId: string) => api.get(`/remediation/${findingId}`),
  updateStatus: (remediationId: string, status: string) =>
    api.patch(`/remediation/${remediationId}/status`, { status }),
};

export const reportsApi = {
  list: (projectId: string) => api.get('/reports', { params: { project_id: projectId } }),
  generate: (data: { project_id: string; title?: string; format?: string }) =>
    api.post('/reports/generate', data),
  download: (reportId: string) =>
    api.get(`/reports/${reportId}/download`, { responseType: 'blob' }),
};

export default api;
