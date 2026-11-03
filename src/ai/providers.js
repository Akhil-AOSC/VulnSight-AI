'use strict';

// Provider contract: { name, model, async complete({ system, messages, maxTokens }) -> string }
// messages = [{ role: 'user' | 'assistant', content: string }]

const DEFAULTS = {
  claude: { model: 'claude-sonnet-5-5', url: 'https://api.anthropic.com/v1/messages' },
  openai: { model: 'gpt-4.1', url: 'https://api.openai.com/v1/chat/completions' },
  groq: { model: 'openai/gpt-oss-20b', url: 'https://api.groq.com/openai/v1/chat/completions' },
};

async function postJson(fetchImpl, url, headers, body, timeoutMs) {
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  if (!res.ok) {
    // Never echo the response body: providers can include request details.
    throw new Error(`AI provider returned HTTP ${res.status}`);
  }
  return JSON.parse(text);
}

function createClaudeProvider({ apiKey, model = DEFAULTS.claude.model, fetchImpl = fetch, timeoutMs = 60000 } = {}) {
  if (!apiKey) throw new Error('A Claude API key is required');
  return {
    name: 'claude',
    model,
    async complete({ system, messages, maxTokens = 1024 }) {
      const data = await postJson(fetchImpl, DEFAULTS.claude.url,
        { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        { model, max_tokens: maxTokens, system, messages }, timeoutMs);
      return (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
    },
  };
}

function createOpenAiProvider({ apiKey, model = DEFAULTS.openai.model, fetchImpl = fetch, timeoutMs = 60000 } = {}) {
  if (!apiKey) throw new Error('An OpenAI API key is required');
  return {
    name: 'openai',
    model,
    async complete({ system, messages, maxTokens = 1024 }) {
      const data = await postJson(fetchImpl, DEFAULTS.openai.url,
        { authorization: `Bearer ${apiKey}` },
        { model, max_tokens: maxTokens, messages: [{ role: 'system', content: system }, ...messages] }, timeoutMs);
      return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
    },
  };
}

function createGroqProvider({ apiKey, model = DEFAULTS.groq.model, fetchImpl = fetch, timeoutMs = 60000 } = {}) {
  if (!apiKey) throw new Error('A Groq API key is required');
  return {
    name: 'groq',
    model,
    async complete({ system, messages, maxTokens = 1024 }) {
      const data = await postJson(fetchImpl, DEFAULTS.groq.url,
        { authorization: `Bearer ${apiKey}` },
        { model, max_tokens: maxTokens, messages: [{ role: 'system', content: system }, ...messages] }, timeoutMs);
      return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
    },
  };
}

// Deterministic provider for tests and offline demos.
function createMockProvider(reply = 'Mock analysis.') {
  const calls = [];
  return {
    name: 'mock',
    model: 'mock',
    calls,
    async complete(req) {
      calls.push(req);
      return typeof reply === 'function' ? reply(req) : reply;
    },
  };
}

// Picks a provider from env: VULNSIGHT_AI_PROVIDER = claude | openai | groq, with ANTHROPIC_API_KEY, OPENAI_API_KEY, or GROQ_API_KEY.
function providerFromEnv(env = process.env, opts = {}) {
  const wanted = (env.VULNSIGHT_AI_PROVIDER || (env.ANTHROPIC_API_KEY ? 'claude' : env.OPENAI_API_KEY ? 'openai' : env.GROQ_API_KEY ? 'groq' : '')).toLowerCase();
  if (wanted === 'claude') return createClaudeProvider({ apiKey: env.ANTHROPIC_API_KEY, model: env.VULNSIGHT_AI_MODEL || undefined, ...opts });
  if (wanted === 'openai') return createOpenAiProvider({ apiKey: env.OPENAI_API_KEY, model: env.VULNSIGHT_AI_MODEL || undefined, ...opts });
  if (wanted === 'groq') return createGroqProvider({ apiKey: env.GROQ_API_KEY, model: env.GROQ_MODEL || env.VULNSIGHT_AI_MODEL || undefined, ...opts });
  return null;
}

module.exports = { createClaudeProvider, createOpenAiProvider, createGroqProvider, createMockProvider, providerFromEnv };
