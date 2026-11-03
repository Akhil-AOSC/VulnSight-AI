import React, { useEffect, useState, useRef } from 'react';
import { api, session, hasPermission, toast } from '../api.js';
import { PageHead } from '../components/Common.jsx';
import { Markdown } from '../components/Markdown.jsx';

export function AssistantView({ initialRepoId }) {
  const [repos, setRepos] = useState([]);
  const [settings, setSettings] = useState(null);
  const [selectedRepo, setSelectedRepo] = useState(initialRepoId || '');
  const [messages, setMessages] = useState([]);
  const [chatHistory, setChatHistory] = useState([]);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const chatRef = useRef(null);

  const canManageOrg = hasPermission(session.me, session.orgId, 'org:settings');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        setLoading(true);
        const [r, s] = await Promise.all([
          api.get(api.org('/repos')),
          api.get(api.org('/settings')),
        ]);
        if (!mounted) return;
        setRepos(r);
        setSettings(s);
        const firstId = initialRepoId && r.some((x) => x.id === initialRepoId)
          ? initialRepoId
          : r[0] && r[0].id;
        setSelectedRepo(firstId || '');
      } catch (err) {
        toast(err.message || 'Failed to load AI assistant', 'error');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, [session.orgId, initialRepoId]);

  useEffect(() => {
    if (!selectedRepo || !settings || !settings.aiEnabled) return;
    let mounted = true;
    async function loadRepoHistory() {
      try {
        const rows = await api.get(api.org(`/repos/${selectedRepo}/ai/history`)).catch(() => []);
        if (!mounted) return;
        const msgs = [];
        const hist = [];
        for (const r of [...rows].reverse().slice(-8)) {
          if (r.kind === 'question') {
            msgs.push({ role: 'user', text: r.question });
            msgs.push({
              role: 'assistant',
              text: r.answer,
              tag: `AI-generated (${r.provider || 'AI'})`,
            });
            hist.push({ role: 'user', content: r.question }, { role: 'assistant', content: r.answer });
          } else if (r.kind === 'summary') {
            msgs.push({
              role: 'assistant',
              text: r.answer,
              tag: 'AI Security Summary',
            });
          }
        }
        if (!msgs.length) {
          msgs.push({
            role: 'assistant',
            text: "Ask me about this repository's findings: what is most urgent, how to fix something, or what an upgrade could break.",
          });
        }
        setMessages(msgs);
        setChatHistory(hist);
      } catch {
        /* ignore */
      }
    }
    loadRepoHistory();
    return () => {
      mounted = false;
    };
  }, [selectedRepo, settings]);

  useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight;
    }
  }, [messages]);

  async function handleSummarize() {
    if (!selectedRepo) return;
    setBusy(true);
    setMessages((prev) => [
      ...prev,
      { role: 'user', text: "Summarize this repository's security posture." },
    ]);
    try {
      const r = await api.post(api.org(`/repos/${selectedRepo}/ai/summary`));
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: r.text,
          tag: `AI-generated - ${r.meta && r.meta.provider}`,
        },
      ]);
    } catch (err) {
      toast(err.message || 'Summary request failed', 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleAsk(e) {
    e.preventDefault();
    const q = question.trim();
    if (!q || !selectedRepo) return;
    setBusy(true);
    setQuestion('');
    setMessages((prev) => [...prev, { role: 'user', text: q }]);
    try {
      const r = await api.post(api.org(`/repos/${selectedRepo}/ai/ask`), {
        question: q,
        history: chatHistory,
      });
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: r.text,
          tag: `AI-generated - ${r.meta && r.meta.provider}`,
        },
      ]);
      if (r.warnings && r.warnings.length) {
        toast(r.warnings.join(' '), 'error');
      }
      setChatHistory((prev) => [
        ...prev,
        { role: 'user', content: q },
        { role: 'assistant', content: r.text },
      ]);
    } catch (err) {
      toast(err.message || 'AI request failed', 'error');
    } finally {
      setBusy(false);
    }
  }

  if (loading && !settings) return <p className="muted">Loading...</p>;
  if (!settings) return null;

  return (
    <>
      <PageHead
        title="AI security assistant"
        subtitle="Ask about your findings. Scanner results always stay the source of truth."
      />

      {!settings.aiEnabled ? (
        <div className="card">
          <h2>AI analysis is turned off</h2>
          <p>
            Your organisation has not enabled AI analysis. When enabled, finding metadata (titles,
            identifiers, package versions and file names) is sent to the configured AI provider.
            Source code is never sent unless you separately allow it.
          </p>
          {canManageOrg ? (
            <a className="btn primary" href="#/settings/organisation">
              Open organisation settings
            </a>
          ) : (
            <p className="muted">Ask an organisation admin to enable it.</p>
          )}
        </div>
      ) : !repos.length ? (
        <div className="card empty">Add and scan a repository first.</div>
      ) : (
        <section className="card">
          <div className="row">
            <label>
              Repository
              <select
                aria-label="Repository"
                value={selectedRepo}
                onChange={(e) => setSelectedRepo(e.target.value)}
              >
                {repos.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.fullName}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div ref={chatRef} className="chat" aria-live="polite">
            {messages.map((m, idx) => (
              <div key={idx} className={`msg ${m.role}`}>
                {m.tag && <div className="badge ai-label">{m.tag}</div>}
                {m.role === 'assistant' ? <Markdown text={m.text} /> : m.text}
              </div>
            ))}
          </div>

          <form className="stack" onSubmit={handleAsk}>
            <textarea
              aria-label="Your question"
              placeholder="For example: What should I fix first, and why?"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
            />
            <div className="row">
              <button className="primary" type="submit" disabled={busy}>
                Ask
              </button>
              <button type="button" onClick={handleSummarize} disabled={busy}>
                Summarize security posture
              </button>
            </div>
          </form>

          <p className="small muted">
            {settings.aiSendCode
              ? 'Code snippets from scanners may be shared with the AI provider (enabled by your admin). Secrets are never shared.'
              : 'Only finding metadata is shared with the AI provider. Code snippets are not sent.'}
          </p>
        </section>
      )}
    </>
  );
}
