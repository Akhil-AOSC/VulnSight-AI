'use strict';

const DEFAULT_GROQ_API = 'https://api.groq.com/openai/v1';
const DEFAULT_MODEL = 'openai/gpt-oss-20b';
const TIMEOUT_MS = 25000;

function cleanJsonString(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .trim()
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
}

async function generateAiAnalysis(report, {
  apiKey = process.env.GROQ_API_KEY,
  model = process.env.GROQ_MODEL || DEFAULT_MODEL,
  apiUrl = DEFAULT_GROQ_API,
} = {}) {
  if (!apiKey || !apiKey.trim()) {
    return null;
  }

  // If no vulnerabilities found, return a clean report
  if (!report.summary || report.summary.issues === 0) {
    return {
      provider: 'Groq (Open-Source LLM)',
      model,
      riskLevel: 'None',
      executiveSummary: 'No known security vulnerabilities were detected in your scanned dependencies. Your software composition is currently clean and secure.',
      impactAnalysis: 'All analyzed packages match known secure versions with no active advisories in OSV.dev.',
      keyRecommendations: [
        'Maintain lockfile integrity using reproducible install commands (e.g., npm ci or poetry install).',
        'Incorporate automated dependency scanning in your CI/CD pipelines to monitor new advisories as they are published.',
      ],
      packageExplanations: {},
    };
  }

  // Build a concise summary of the findings to keep prompt size optimal
  const topIssues = [];
  const seenPkgs = new Set();

  for (const project of report.projects || []) {
    for (const v of project.vulnerabilities || []) {
      const key = `${v.package}@${v.version}`;
      if (!seenPkgs.has(key)) {
        seenPkgs.add(key);
        topIssues.push({
          package: v.package,
          version: v.version,
          severity: v.severity,
          title: v.title,
          cve: v.aliases ? v.aliases.find((a) => a.startsWith('CVE-')) || v.id : v.id,
          fixVersion: v.fixedIn || null,
        });
        if (topIssues.length >= 15) break;
      }
    }
    if (topIssues.length >= 15) break;
  }

  const promptPayload = {
    totalIssues: report.summary.issues,
    severities: {
      critical: report.summary.critical || 0,
      high: report.summary.high || 0,
      medium: report.summary.medium || 0,
      low: report.summary.low || 0,
    },
    projectsCount: (report.projects || []).length,
    vulnerabilitiesSample: topIssues,
  };

  const systemPrompt = `You are a Senior Application Security & Vulnerability Intelligence AI.
Analyze the provided dependency vulnerability report (sourced from OSV.dev) and generate a high-level, human-readable executive briefing for developers and stakeholders.

You MUST respond ONLY with a valid JSON object matching this exact schema:
{
  "riskLevel": "Critical" | "High" | "Medium" | "Low",
  "executiveSummary": "A 2-3 sentence high-level overview explaining the overall security posture and risk in plain, non-academic language.",
  "impactAnalysis": "A 2-3 sentence explanation of real-world attack vectors (e.g. RCE, prototype pollution, SQL injection, Denial of Service) and what an attacker could achieve if exploited.",
  "keyRecommendations": [
    "Concrete, prioritized developer remediation action 1",
    "Concrete, prioritized developer remediation action 2",
    "Concrete, prioritized developer remediation action 3"
  ],
  "packageExplanations": {
    "<package_name>": "A 1-2 sentence explanation of why this specific package vulnerability matters and what threat it poses."
  }
}`;

  try {
    const res = await fetch(`${apiUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey.trim()}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: JSON.stringify(promptPayload) },
        ],
        temperature: 0.15,
        max_tokens: 1500,
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      console.warn(`[Groq AI Warning] Request failed with HTTP ${res.status}:`, errBody.error ? errBody.error.message : res.statusText);
      return null;
    }

    const data = await res.json();
    const rawContent = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
    if (!rawContent) return null;

    const parsed = JSON.parse(cleanJsonString(rawContent));
    return {
      provider: 'Groq (Open-Source LLM)',
      model,
      riskLevel: parsed.riskLevel || 'Medium',
      executiveSummary: parsed.executiveSummary || 'Vulnerabilities detected across dependencies. Remediation recommended.',
      impactAnalysis: parsed.impactAnalysis || '',
      keyRecommendations: Array.isArray(parsed.keyRecommendations) ? parsed.keyRecommendations : [],
      packageExplanations: parsed.packageExplanations || {},
    };
  } catch (err) {
    console.warn('[Groq AI Warning] Could not generate AI analysis:', err.message);
    return null;
  }
}

module.exports = { generateAiAnalysis, cleanJsonString };

