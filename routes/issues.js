'use strict';

/**
 * Per-issue AI explanation (on-demand, cached) and AI-suggested fix
 * (suggest-only — never writes to disk itself; the one write path is PUT
 * /api/pipeline/:jobId/studio/file, which the caller applies the suggestion
 * to). Phase F of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance (getCachedIssueExplanation/cacheIssueExplanation)
 * @param {Function} deps.llmAvailableCached - lib/llm-client.js's createLlmClient() result
 * @param {Function} deps.llmComplete - lib/llm-client.js's createLlmClient() result
 */
function mountIssuesRoutes(app, { store, llmAvailableCached, llmComplete }) {
  const crypto = require('crypto');

  // Shared by /api/issues/explain and /api/issues/suggest-fix — both accept
  // the same client-supplied issue shape (category/severity/file/line/summary
  // + optional snippet) and need it validated/trimmed the same way.
  function parseIssueFromBody(body) {
    const category = String(body.category || '').trim();
    const summary = String(body.summary || '').trim();
    if (!category || !summary) return null;
    return {
      category,
      severity: ['error', 'warning'].includes(body.severity) ? body.severity : 'warning',
      file: body.file ? String(body.file).slice(0, 500) : null,
      line: Number.isInteger(body.line) ? body.line : null,
      summary: summary.slice(0, 500),
      snippet: body.snippet && typeof body.snippet === 'object' && Array.isArray(body.snippet.lines)
        ? body.snippet
        : null,
    };
  }

  const ISSUE_EXPLAIN_PROMPT = `You are explaining one single flagged code issue to a non-technical reader (e.g. a project manager), using the exact code snippet shown.
Write 2-4 sentences in plain language with no jargon: what is concretely wrong in THIS snippet, why it matters in the real world, and what should change. Do not just restate the technical summary you were given — actually explain it. Do not discuss anything beyond this one issue.`;

  // Cached in the DB by a stable hash of the issue's identity, so opening
  // the same finding again — even in a different run — never re-triggers
  // the LLM call.
  function issueExplanationHash({ category, file, line, summary }) {
    return crypto.createHash('sha256')
      .update(`${category}|${file || ''}|${line || 0}|${summary}`)
      .digest('hex');
  }

  async function explainIssueForHuman(issue) {
    const codeBlock = Array.isArray(issue.snippet?.lines)
      ? issue.snippet.lines.map((l) => `${l.number}: ${l.text}`).join('\n').slice(0, 4000)
      : '(no code snippet available)';
    const user = `Category: ${issue.category}\nSeverity: ${issue.severity}\nLocation: ${issue.file || 'unknown'}${issue.line ? ':' + issue.line : ''}\nTechnical summary: ${issue.summary}\n\nCode:\n${codeBlock}`;
    return await llmComplete(ISSUE_EXPLAIN_PROMPT, user, { temperature: 0.3, timeoutMs: 60_000, label: `issue-explain ${issue.category}:${issue.file || '?'}:${issue.line || 0}` });
  }

  // A JSON-object response schema (as originally used here) forces the model
  // to escape every quote inside the replacement code as a JSON string — for
  // multi-line snippets full of string literals (Python dict/f-string code,
  // JSX, etc.) local models reliably get that escaping wrong (e.g. escaping
  // the quotes around an f-string but not the ones around a dict key),
  // producing JSON that *looks* almost valid but isn't recoverable by brace-
  // matching alone. A plain delimited text format sidesteps the problem
  // entirely: the replacement code is copied verbatim, no escaping required.
  const ISSUE_SUGGEST_FIX_PROMPT = `You are a senior software engineer proposing a concrete fix for one single flagged code issue, using the exact numbered code snippet shown.
Propose a corrected replacement for ONLY the exact line range shown in the snippet (from its first to its last numbered line) — do not rewrite the whole file, do not renumber lines, do not add lines outside that range.
Respond in EXACTLY this plain-text format and nothing else — no JSON, no code fences, no text before or after:
EXPLANATION: <1-3 sentences: what changed and why it fixes the issue>
REPLACEMENT:
<the corrected text for that exact line range, copied verbatim with no escaping, newline-separated, no line-number prefixes>
If you cannot safely propose a fix from the snippet alone, respond:
EXPLANATION: <why not>
REPLACEMENT: NONE`;

  function stripCodeFence(text) {
    const trimmed = text.trim();
    const fenced = trimmed.match(/^```(?:\w+)?\s*([\s\S]*?)\s*```$/);
    return fenced ? fenced[1] : trimmed;
  }

  // Trims fully-blank leading/trailing lines without disturbing the
  // indentation of the code itself.
  function trimBlockLines(raw) {
    const lines = raw.replace(/\r\n/g, '\n').split('\n');
    while (lines.length && lines[0].trim() === '') lines.shift();
    while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
    return lines.join('\n');
  }

  function parseSuggestFixResponse(text) {
    const trimmed = stripCodeFence(text);
    const match = trimmed.match(/EXPLANATION:\s*([\s\S]*?)\n\s*REPLACEMENT:\s*([\s\S]*)$/i);
    if (!match) {
      const err = new Error('The AI response did not match the expected fix format.');
      err.code = 'invalid_response';
      throw err;
    }
    const explanation = match[1].trim();
    const replacementBlock = trimBlockLines(stripCodeFence(match[2]));
    const replacement = replacementBlock.toUpperCase() === 'NONE' ? null : replacementBlock;
    return { explanation, replacement };
  }

  // Distinguishes "the LLM call itself failed" (llmComplete's thrown
  // err.code — timeout/network_error/http_error/empty_response) from "the
  // LLM responded but not in the shape we asked for" (invalid_response,
  // thrown here) — both were previously indistinguishable from a genuine
  // "no fix" decline once they reached the client, all collapsing into the
  // same generic fallback text.
  function friendlyLlmErrorMessage(e) {
    switch (e.code) {
      case 'timeout':
        return `The AI took too long to respond (over ${Math.round((e.timeoutMs || 60_000) / 1000)}s) and the request was cancelled. Try again, or check whether the local LLM is overloaded.`;
      case 'network_error':
        return `Could not reach the AI service: ${e.message}`;
      case 'http_error':
        return `The AI service returned an error (HTTP ${e.status}).`;
      case 'empty_response':
        return 'The AI returned an empty response.';
      case 'invalid_response':
        return e.message;
      default:
        return e.message;
    }
  }

  async function suggestFixForIssue(issue) {
    if (!Array.isArray(issue.snippet?.lines) || issue.snippet.lines.length === 0) return null;
    const codeBlock = issue.snippet.lines.map((l) => `${l.number}: ${l.text}`).join('\n').slice(0, 4000);
    const user = `Category: ${issue.category}\nSeverity: ${issue.severity}\nLocation: ${issue.file || 'unknown'}${issue.line ? ':' + issue.line : ''}\nTechnical summary: ${issue.summary}\n\nCode:\n${codeBlock}`;
    const text = await llmComplete(ISSUE_SUGGEST_FIX_PROMPT, user, { temperature: 0.2, timeoutMs: 60_000, label: `issue-suggest-fix ${issue.category}:${issue.file || '?'}:${issue.line || 0}` });
    const parsed = parseSuggestFixResponse(text);
    return {
      explanation: parsed.explanation,
      replacement: parsed.replacement,
      startLine: issue.snippet.startLine,
      endLine: issue.snippet.startLine + issue.snippet.lines.length - 1,
    };
  }

  app.post('/api/issues/explain', async (req, res) => {
    const issue = parseIssueFromBody(req.body || {});
    if (!issue) return res.status(400).json({ error: 'category and summary are required.' });

    const hash = issueExplanationHash(issue);
    const cached = store.getCachedIssueExplanation(hash);
    if (cached) return res.json({ ok: true, explanation: cached, cached: true });

    if (!(await llmAvailableCached())) {
      return res.json({ ok: true, explanation: null, cached: false, reason: 'AI explanation service unavailable.' });
    }
    try {
      const explanation = await explainIssueForHuman(issue);
      if (explanation) store.cacheIssueExplanation(hash, explanation);
      res.json({ ok: true, explanation, cached: false });
    } catch (e) {
      res.status(502).json({ ok: false, error: friendlyLlmErrorMessage(e) });
    }
  });

  app.post('/api/issues/suggest-fix', async (req, res) => {
    const issue = parseIssueFromBody(req.body || {});
    if (!issue) return res.status(400).json({ error: 'category and summary are required.' });
    if (!issue.snippet) return res.status(400).json({ error: 'A code snippet is required to suggest a fix.' });

    if (!(await llmAvailableCached())) {
      return res.json({ ok: true, suggestion: null, reason: 'AI fix suggestion service unavailable.' });
    }
    try {
      const suggestion = await suggestFixForIssue(issue);
      res.json({ ok: true, suggestion });
    } catch (e) {
      res.status(502).json({ ok: false, error: friendlyLlmErrorMessage(e) });
    }
  });
}

module.exports = { mountIssuesRoutes };
