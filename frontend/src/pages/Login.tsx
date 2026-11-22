import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { apiErrorMessage } from '../lib/api';
import { useSession } from '../lib/session';

export default function LoginPage() {
  const { token, loading, login } = useSession();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (!loading && token) return <Navigate to="/" replace />;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await login(email.trim(), password);
    } catch (err: unknown) {
      setError(apiErrorMessage(err, 'Sign-in failed. Use an account that already exists.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-navy-950 flex items-center justify-center px-4">
      <form onSubmit={submit} className="card w-full max-w-md p-8 space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">BugHawk AI</h1>
          <p className="text-sm text-slate-400 mt-1">Sign in with a provisioned account. Public registration is closed.</p>
        </div>
        <label className="block text-sm text-slate-300">
          Email
          <input className="input mt-1 w-full" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label className="block text-sm text-slate-300">
          Password
          <input className="input mt-1 w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
        </label>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button className="btn-primary w-full" type="submit" disabled={submitting}>
          {submitting ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
