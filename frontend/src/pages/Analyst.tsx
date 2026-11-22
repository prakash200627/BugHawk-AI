import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  Bot, Send, User, Loader2, FlaskConical, Bug,
  AlertTriangle, Eye, ChevronDown, Zap, MessageCircle,
  RefreshCw, Info, CheckCircle, XCircle
} from 'lucide-react';
import { agentsApi, apiErrorMessage, findingsApi } from '../lib/api';
import { useSession } from '../lib/session';
import NoProject from '../components/NoProject';
import type { SecurityFinding, ChatMessage, AgentAnalyzeResponse } from '../types';
import clsx from 'clsx';


const SUGGESTED_QUESTIONS = [
  'Explain this vulnerability in simple terms.',
  'Why is this finding dangerous?',
  'What evidence supports this finding?',
  'Could this be a false positive?',
  'How can I fix this vulnerability?',
  'What should I investigate next?',
];

function MessageBubble({ message }: { message: ChatMessage & { is_demo?: boolean } }) {
  const isUser = message.role === 'user';
  return (
    <div className={clsx('flex gap-3', isUser ? 'justify-end' : 'justify-start')}>
      {!isUser && (
        <div className="w-7 h-7 rounded-lg bg-cyber-blue/20 border border-cyber-blue/30 flex items-center justify-center flex-shrink-0 mt-0.5">
          <Bot size={14} className="text-cyber-blue" />
        </div>
      )}
      <div
        className={clsx(
          'max-w-[80%] rounded-xl px-4 py-3 text-sm leading-relaxed',
          isUser
            ? 'bg-cyber-blue/20 text-slate-200 border border-cyber-blue/20'
            : 'bg-navy-700 text-slate-300 border border-cyber-blue/10'
        )}
      >
        <div className="whitespace-pre-wrap">{message.content}</div>
        {!isUser && (message as any).is_demo && (
          <div className="mt-2 pt-2 border-t border-purple-500/20 flex items-center gap-1 text-xs text-purple-400">
            <FlaskConical size={10} />
            Canned demo text. A live model was not called.
          </div>
        )}
      </div>
      {isUser && (
        <div className="w-7 h-7 rounded-lg bg-slate-600/30 border border-slate-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
          <User size={14} className="text-slate-400" />
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding, selected, onClick }: {
  finding: SecurityFinding;
  selected: boolean;
  onClick: () => void;
}) {
  const sevColor: Record<string, string> = {
    critical: 'border-l-red-500 bg-red-500/5',
    high: 'border-l-orange-500 bg-orange-500/5',
    medium: 'border-l-yellow-500 bg-yellow-500/5',
    low: 'border-l-blue-500 bg-blue-500/5',
    info: 'border-l-slate-500 bg-slate-500/5',
  };

  return (
    <button
      onClick={onClick}
      className={clsx(
        'w-full text-left px-3 py-2.5 rounded-lg border-l-2 border border-transparent transition-all duration-150',
        sevColor[finding.effective_severity] || 'border-l-slate-500',
        selected
          ? 'border-cyber-blue/40 bg-cyber-blue/10'
          : 'hover:bg-navy-700/50 hover:border-cyber-blue/20 border-navy-700'
      )}
      id={`finding-select-${finding.id.substring(0, 8)}`}
    >
      <div className="flex items-start gap-2">
        <Bug size={12} className="text-slate-500 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium text-slate-200 line-clamp-2 leading-snug">
            {finding.title}
          </div>
          <div className="text-xs text-slate-500 mt-0.5 uppercase">
            {finding.effective_severity}
          </div>
        </div>
        {finding.is_demo && <FlaskConical size={10} className="text-purple-400 flex-shrink-0 mt-0.5" />}
      </div>
    </button>
  );
}

function AnalysisPanel({ analysis }: { analysis: AgentAnalyzeResponse }) {
  return (
    <div className="card p-4 space-y-4 animate-fade-in">
      <div className="flex items-center gap-2">
        <Zap size={14} className="text-cyber-blue" />
        <h3 className="text-sm font-semibold text-slate-200">AI Analysis Report</h3>
        {analysis.is_demo && (
          <span className="badge badge-demo ml-auto flex items-center gap-1 text-xs">
            <FlaskConical size={10} /> Demo
          </span>
        )}
      </div>

      {[
        { label: 'Technical Explanation', content: analysis.explanation, icon: <Info size={12} className="text-cyber-blue" /> },
        { label: 'Severity Assessment', content: analysis.severity_assessment, icon: <AlertTriangle size={12} className="text-cyber-orange" /> },
        { label: 'Evidence Confidence', content: analysis.confidence, icon: <Eye size={12} className="text-yellow-400" /> },
        { label: 'Security Impact', content: analysis.impact, icon: <XCircle size={12} className="text-red-400" /> },
        { label: 'Remediation Summary', content: analysis.remediation_summary, icon: <CheckCircle size={12} className="text-cyber-green" /> },
      ].map(({ label, content, icon }) => content ? (
        <div key={label}>
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            {icon}
            {label}
          </div>
          <div className="bg-navy-900 rounded-lg p-3 text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
            {content}
          </div>
        </div>
      ) : null)}

      {analysis.verification_steps && analysis.verification_steps.length > 0 && (
        <div>
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            <CheckCircle size={12} className="text-cyber-green" />
            Verification Checklist
          </div>
          <div className="bg-navy-900 rounded-lg p-3 space-y-2">
            {analysis.verification_steps.map((step, i) => (
              <div key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <div className="w-4 h-4 rounded border border-cyber-green/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-xs text-cyber-green font-mono">{i + 1}</span>
                </div>
                {step}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AnalystPage() {
  const { projectId } = useSession();
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [messages, setMessages] = useState<(ChatMessage & { is_demo?: boolean })[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<AgentAnalyzeResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'chat' | 'analysis'>('chat');
  const [findingsState, setFindingsState] = useState<'loading' | 'ready' | 'error'>('loading');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!projectId) { setFindings([]); setFindingsState('ready'); return; }
    setFindingsState('loading');
    findingsApi.list(projectId, {}).then((res) => {
      setFindings(res.data);
      setFindingsState('ready');
    }).catch(() => {
      setFindings([]);
      setFindingsState('error');
    });
  }, [projectId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Welcome message
  useEffect(() => {
    setMessages([{
      role: 'assistant',
      content: (
        'Select a finding or send a question.\n\n' +
        'When the server is in demo mode, replies are canned text stored in the API. Otherwise the server reports that a live analyst is not connected.'
      ),
      is_demo: true,
    }]);
  }, []);

  const selectFinding = (finding: SecurityFinding) => {
    setSelectedFinding(finding);
    setAnalysis(null);
    setMessages(prev => [...prev, {
      role: 'assistant',
      content: (
        `I now have context for: **${finding.title}**\n\n` +
        `Severity: ${finding.effective_severity.toUpperCase()}\n` +
        `Confidence: ${finding.confidence.toUpperCase()}\n` +
        `Validation: ${finding.validation_status.replace('_', ' ')}\n` +
        (finding.endpoint ? `Endpoint: ${finding.endpoint}\n` : '') +
        '\nAsk a question, or request analysis. The server returns canned text in demo mode and an unavailable response otherwise.'
      ),
      is_demo: true,
    }]);
  };

  const sendMessage = async (content?: string) => {
    const text = content || input.trim();
    if (!text || sending) return;

    const userMsg: ChatMessage = { role: 'user', content: text };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setSending(true);

    try {
      const res = await agentsApi.chat({
        project_id: projectId!,
        messages: [...messages, userMsg].map(m => ({ role: m.role, content: m.content })),
        finding_id: selectedFinding?.id,
      });
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: res.data.response,
        is_demo: res.data.is_demo,
      }]);
    } catch (err: unknown) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: apiErrorMessage(err, 'The analyst did not return a reply.'),
        is_demo: false,
      }]);
    } finally {
      setSending(false);
    }
  };

  const runAnalysis = async () => {
    if (!selectedFinding || analyzing) return;
    setAnalyzing(true);
    setActiveTab('analysis');

    try {
      const res = await agentsApi.analyze(selectedFinding.id, projectId!);
      setAnalysis(res.data);
    } catch (err: unknown) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: apiErrorMessage(err, 'Analysis was not returned.'),
        is_demo: false,
      }]);
      setActiveTab('chat');
    } finally {
      setAnalyzing(false);
    }
  };

  if (!projectId) return <NoProject />;

  return (
    <div className="flex gap-4 h-[calc(100vh-10rem)] animate-fade-in">
      {/* Left panel: Finding selector */}
      <div className="w-64 flex-shrink-0 flex flex-col card">
        <div className="p-4 border-b border-cyber-blue/10">
          <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Bug size={14} className="text-cyber-orange" />
            Select Finding
          </h3>
          <p className="text-xs text-slate-500 mt-1">Context-aware analysis</p>
        </div>
        <div className="flex-1 overflow-y-auto scroll-area p-3 space-y-2">
          {findingsState === 'loading' ? (
            <div className="text-center py-8 text-xs text-slate-500">
              <Loader2 size={16} className="animate-spin mx-auto mb-2 text-slate-600" />
              Loading findings...
            </div>
          ) : findingsState === 'error' ? (
            <div className="text-center py-8 text-xs text-red-400">Findings could not be loaded.</div>
          ) : findings.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500">No findings are stored for this project.</div>
          ) : (
            findings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                selected={selectedFinding?.id === f.id}
                onClick={() => selectFinding(f)}
              />
            ))
          )}
        </div>
        {selectedFinding && (
          <div className="p-3 border-t border-cyber-blue/10">
            <button
              onClick={runAnalysis}
              disabled={analyzing}
              className="btn-primary w-full flex items-center justify-center gap-2 !text-xs !py-2"
              id="run-analysis-btn"
            >
              {analyzing ? (
                <><Loader2 size={12} className="animate-spin" /> Analyzing...</>
              ) : (
                <><Zap size={12} /> Run AI Analysis</>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Right panel: Chat + Analysis */}
      <div className="flex-1 flex flex-col card overflow-hidden">
        {/* Tabs */}
        <div className="flex border-b border-cyber-blue/10">
          <button
            onClick={() => setActiveTab('chat')}
            className={clsx(
              'flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors border-b-2',
              activeTab === 'chat'
                ? 'text-cyber-blue border-cyber-blue'
                : 'text-slate-400 border-transparent hover:text-slate-200'
            )}
            id="chat-tab"
          >
            <MessageCircle size={14} />
            Chat
          </button>
          <button
            onClick={() => setActiveTab('analysis')}
            className={clsx(
              'flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors border-b-2',
              activeTab === 'analysis'
                ? 'text-cyber-blue border-cyber-blue'
                : 'text-slate-400 border-transparent hover:text-slate-200'
            )}
            id="analysis-tab"
          >
            <Zap size={14} />
            Analysis Report
            {analysis && <span className="w-2 h-2 rounded-full bg-cyber-green" />}
          </button>
          <div className="ml-auto flex items-center pr-4">
            <span className="demo-banner">
              <FlaskConical size={10} />
              Server analyst. Not a live model unless demo text is returned.
            </span>
          </div>
        </div>

        {/* Chat tab */}
        {activeTab === 'chat' && (
          <>
            <div className="flex-1 overflow-y-auto scroll-area p-5 space-y-4">
              {messages.map((msg, i) => (
                <MessageBubble key={i} message={msg} />
              ))}
              {sending && (
                <div className="flex gap-3">
                  <div className="w-7 h-7 rounded-lg bg-cyber-blue/20 border border-cyber-blue/30 flex items-center justify-center flex-shrink-0">
                    <Bot size={14} className="text-cyber-blue" />
                  </div>
                  <div className="bg-navy-700 border border-cyber-blue/10 rounded-xl px-4 py-3">
                    <div className="flex gap-1">
                      {[0, 1, 2].map(i => (
                        <div
                          key={i}
                          className="w-1.5 h-1.5 bg-cyber-blue rounded-full animate-bounce"
                          style={{ animationDelay: `${i * 0.15}s` }}
                        />
                      ))}
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Suggested questions */}
            <div className="px-5 py-2 flex flex-wrap gap-2 border-t border-cyber-blue/8">
              {SUGGESTED_QUESTIONS.slice(0, 3).map((q) => (
                <button
                  key={q}
                  onClick={() => sendMessage(q)}
                  disabled={sending}
                  className="text-xs px-3 py-1 rounded-full bg-cyber-blue/10 border border-cyber-blue/20 text-cyber-blue-bright hover:bg-cyber-blue/20 transition-colors disabled:opacity-50"
                >
                  {q}
                </button>
              ))}
            </div>

            {/* Input */}
            <div className="p-4 border-t border-cyber-blue/10 flex gap-3">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                placeholder={selectedFinding ? `Ask about "${selectedFinding.title}"...` : 'Ask a security question...'}
                className="input flex-1 text-sm"
                id="analyst-chat-input"
                disabled={sending}
              />
              <button
                onClick={() => sendMessage()}
                disabled={sending || !input.trim()}
                className="btn-primary flex items-center gap-2 !px-4 !py-2"
                id="send-message-btn"
              >
                {sending ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
              </button>
            </div>
          </>
        )}

        {/* Analysis tab */}
        {activeTab === 'analysis' && (
          <div className="flex-1 overflow-y-auto scroll-area p-5">
            {analyzing ? (
              <div className="flex items-center justify-center h-48">
                <div className="text-center">
                  <Loader2 className="w-8 h-8 text-cyber-blue animate-spin mx-auto mb-3" />
                  <p className="text-sm text-slate-400">Requesting analysis from the server...</p>
                  <p className="text-xs text-slate-500 mt-1">Demo mode returns canned text. Otherwise the request is unavailable.</p>
                </div>
              </div>
            ) : analysis ? (
              <AnalysisPanel analysis={analysis} />
            ) : (
              <div className="flex items-center justify-center h-48">
                <div className="text-center">
                  <Bot size={32} className="text-slate-600 mx-auto mb-3" />
                  <p className="text-sm text-slate-400 mb-2">No analysis yet</p>
                  <p className="text-xs text-slate-500">Select a finding and click "Run AI Analysis"</p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
