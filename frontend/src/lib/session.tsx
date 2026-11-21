import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { authApi, projectsApi } from './api';

const TOKEN_KEY = 'bughawk_token';
const PROJECT_KEY = 'bughawk_project_id';

export interface SessionUser {
  id: string;
  email: string;
  role: string;
  full_name?: string | null;
}

export interface SessionProject {
  id: string;
  name: string;
}

interface SessionValue {
  user: SessionUser | null;
  token: string | null;
  projectId: string | null;
  projects: SessionProject[];
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  selectProject: (id: string) => void;
  refreshProjects: (preferId?: string) => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<SessionUser | null>(null);
  const [projects, setProjects] = useState<SessionProject[]>([]);
  const [projectId, setProjectId] = useState<string | null>(() => localStorage.getItem(PROJECT_KEY));
  const [loading, setLoading] = useState(Boolean(localStorage.getItem(TOKEN_KEY)));

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(PROJECT_KEY);
    setToken(null);
    setUser(null);
    setProjects([]);
    setProjectId(null);
    setLoading(false);
  }, []);

  const refreshProjects = useCallback(async (preferId?: string) => {
    const res = await projectsApi.list();
    const list = (res.data || []) as SessionProject[];
    setProjects(list);
    setProjectId((current) => {
      const preferred = preferId || current || localStorage.getItem(PROJECT_KEY);
      const next = list.some((item) => item.id === preferred) ? preferred : (list[0]?.id ?? null);
      if (next) localStorage.setItem(PROJECT_KEY, next);
      else localStorage.removeItem(PROJECT_KEY);
      return next;
    });
  }, []);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    authApi.me()
      .then((res) => {
        if (cancelled) return;
        setUser(res.data);
        return refreshProjects();
      })
      .catch(() => {
        if (!cancelled) logout();
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [token, logout, refreshProjects]);

  const login = async (email: string, password: string) => {
    const res = await authApi.login(email, password);
    localStorage.setItem(TOKEN_KEY, res.data.access_token);
    setUser({ id: res.data.user_id, email: res.data.email, role: res.data.role });
    setToken(res.data.access_token);
  };

  const selectProject = (id: string) => {
    localStorage.setItem(PROJECT_KEY, id);
    setProjectId(id);
  };

  return (
    <SessionContext.Provider
      value={{ user, token, projectId, projects, loading, login, logout, selectProject, refreshProjects }}
    >
      {children}
    </SessionContext.Provider>
  );
}

export function useSession() {
  const value = useContext(SessionContext);
  if (!value) throw new Error('useSession must be used within SessionProvider');
  return value;
}
