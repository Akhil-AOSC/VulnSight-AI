'use strict';

// Git hosting integrations. API base URLs are fixed constants: users supply tokens and
// repository names, never hosts, so these calls cannot be steered at internal services.
const FULL_NAME = /^[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+){1,5}$/;

async function getJson(fetchImpl, url, headers) {
  const res = await fetchImpl(url, { headers: { accept: 'application/json', 'user-agent': 'vulnsight-ai', ...headers }, signal: AbortSignal.timeout(15000) });
  if (res.status === 401 || res.status === 403) {
    const limited = res.headers && res.headers.get && res.headers.get('x-ratelimit-remaining') === '0';
    throw Object.assign(new Error(limited ? 'The Git provider rate limit was reached. Try again later' : 'The Git provider rejected the token'), { status: limited ? 429 : 400 });
  }
  if (res.status === 429) throw Object.assign(new Error('The Git provider rate limit was reached. Try again later'), { status: 429 });
  if (!res.ok) throw Object.assign(new Error(`The Git provider returned HTTP ${res.status}`), { status: 502 });
  return res.json();
}

const github = {
  host: 'github.com',
  cloneAuth: (token) => ({ username: 'x-access-token', token }),
  async validate(token, f) {
    const u = await getJson(f, 'https://api.github.com/user', { authorization: `Bearer ${token}` });
    return { account: u.login };
  },
  async listRepos(token, f) {
    const list = await getJson(f, 'https://api.github.com/user/repos?per_page=100&sort=updated', { authorization: `Bearer ${token}` });
    return list.map((r) => ({ fullName: r.full_name, cloneUrl: `https://github.com/${r.full_name}.git`, defaultBranch: r.default_branch, private: !!r.private }));
  },
  async listBranches(token, fullName, f) {
    assertFullName(fullName);
    const list = await getJson(f, `https://api.github.com/repos/${fullName}/branches?per_page=100`, { authorization: `Bearer ${token}` });
    return list.map((b) => b.name);
  },
};

const gitlab = {
  host: 'gitlab.com',
  cloneAuth: (token) => ({ username: 'oauth2', token }),
  async validate(token, f) {
    const u = await getJson(f, 'https://gitlab.com/api/v4/user', { authorization: `Bearer ${token}` });
    return { account: u.username };
  },
  async listRepos(token, f) {
    const list = await getJson(f, 'https://gitlab.com/api/v4/projects?membership=true&simple=true&per_page=100&order_by=last_activity_at', { authorization: `Bearer ${token}` });
    return list.map((r) => ({ fullName: r.path_with_namespace, cloneUrl: `https://gitlab.com/${r.path_with_namespace}.git`, defaultBranch: r.default_branch || 'main', private: r.visibility !== 'public', id: r.id }));
  },
  async listBranches(token, fullName, f) {
    assertFullName(fullName);
    const id = encodeURIComponent(fullName);
    const list = await getJson(f, `https://gitlab.com/api/v4/projects/${id}/repository/branches?per_page=100`, { authorization: `Bearer ${token}` });
    return list.map((b) => b.name);
  },
};

const bitbucket = {
  host: 'bitbucket.org',
  cloneAuth: (token) => ({ username: 'x-token-auth', token }),
  async validate(token, f) {
    const u = await getJson(f, 'https://api.bitbucket.org/2.0/user', { authorization: `Bearer ${token}` });
    return { account: u.nickname || u.username };
  },
  async listRepos(token, f) {
    const data = await getJson(f, 'https://api.bitbucket.org/2.0/repositories?role=member&pagelen=100', { authorization: `Bearer ${token}` });
    return (data.values || []).map((r) => ({ fullName: r.full_name, cloneUrl: `https://bitbucket.org/${r.full_name}.git`, defaultBranch: (r.mainbranch && r.mainbranch.name) || 'main', private: !!r.is_private }));
  },
  async listBranches(token, fullName, f) {
    assertFullName(fullName);
    const data = await getJson(f, `https://api.bitbucket.org/2.0/repositories/${fullName}/refs/branches?pagelen=100`, { authorization: `Bearer ${token}` });
    return (data.values || []).map((b) => b.name);
  },
};

function assertFullName(name) {
  if (!FULL_NAME.test(String(name)) || String(name).split('/').some((s) => s === '.' || s === '..')) {
    throw Object.assign(new Error('Invalid repository name'), { status: 400 });
  }
}

const PROVIDERS = { github, gitlab, bitbucket };
const providerForHost = (host) => Object.keys(PROVIDERS).find((k) => PROVIDERS[k].host === host) || null;

module.exports = { PROVIDERS, providerForHost, assertFullName };
