'use strict';

const fs = require('fs');
const path = require('path');

// Full request/response bodies (not just the size summary traceLlmCall logs
// to stdout) go here for debugging local-model non-JSON-compliance issues —
// gitignored via the blanket **/*.log rule, never committed.
const LLM_LOG_PATH = path.join(__dirname, '..', 'llm-debug.log');
function logLlmExchange(label, payload, responseText, err) {
  try {
    const entry = {
      ts: new Date().toISOString(),
      label,
      request: payload,
      responseText: responseText ?? null,
      error: err ? { message: err.message, code: err.code } : null,
    };
    fs.appendFileSync(LLM_LOG_PATH, JSON.stringify(entry) + '\n');
  } catch {
    // best-effort debug logging only — never let it break the actual call
  }
}

/**
 * Shared local-LLM/OpenAI chat-completions client — used by
 * checks/llm-deep-scan.js and by the unrelated AI-explain/AI-suggest-fix
 * Studio features (issue explanations, override-gate rejection summaries),
 * which is why this is its own lib rather than living inside the deep-scan
 * check. Phase D of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} config
 * @param {string} config.provider - 'local' | 'openai'
 * @param {object} config.openai - { apiKey, baseUrl, model }
 * @param {string} config.scanUrl - local (llama.cpp-compatible) endpoint base URL
 * @param {string} config.scanModel - local endpoint model name
 */
function createLlmClient({ provider, openai, scanUrl, scanModel }) {
  const LLM_PROVIDER = provider;
  const openaiApiKeyValue = openai?.apiKey || '';
  const OPENAI_BASE_URL = String(openai?.baseUrl || '').replace(/\/+$/, '');
  const OPENAI_MODEL = openai?.model || '';
  const LLM_SCAN_URL = scanUrl;
  const LLM_SCAN_MODEL = scanModel;

  // Resolves the effective chat-completions endpoint/model/auth for whichever
  // provider is configured, so llmChat/llmComplete/llmAvailable don't need to
  // know which backend they're talking to.
  function llmTarget() {
    if (LLM_PROVIDER === 'openai') {
      return {
        url: `${OPENAI_BASE_URL}/chat/completions`,
        model: OPENAI_MODEL,
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${openaiApiKeyValue}` },
      };
    }
    return {
      url: `${LLM_SCAN_URL}/v1/chat/completions`,
      model: LLM_SCAN_MODEL,
      headers: { 'Content-Type': 'application/json' },
    };
  }

  // Logs every request/response exchanged with the local LLM to stdout (and,
  // when a phase `log` callback is given, into the UI's live log too) — so a
  // timeout can be traced to the exact call, payload size, and elapsed time.
  function traceLlmCall(label, { url, model, timeoutMs, chars }, log) {
    const line = `[llm] → ${label} POST ${url} model=${model} timeout=${timeoutMs}ms payload=${chars} chars`;
    console.log(line);
    if (log) log(line);
    const startedAt = Date.now();
    return (outcome, detail = '') => {
      const elapsed = Date.now() - startedAt;
      const result = `[llm] ← ${label} ${outcome} in ${elapsed}ms${detail ? ' — ' + detail : ''}`;
      console.log(result);
      if (log) log(result);
    };
  }

  async function llmChat(sourceBlock, systemPrompt, log, label = 'chat') {
    const timeoutMs = 300_000;
    const { url, model, headers } = llmTarget();
    const finish = traceLlmCall(`${label} [${LLM_PROVIDER}]`, { url, model, timeoutMs, chars: sourceBlock.length }, log);
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers,
        signal: AbortSignal.timeout(timeoutMs),
        body: JSON.stringify({
          model,
          stream: false,
          temperature: 0,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: sourceBlock },
          ],
        }),
      });
    } catch (e) {
      finish(e.name === 'TimeoutError' ? 'TIMED OUT' : 'FAILED', e.message);
      throw e;
    }
    if (!res.ok) {
      finish('HTTP ERROR', String(res.status));
      throw new Error(`LLM endpoint returned HTTP ${res.status}`);
    }
    const data = await res.json();
    const text = data.choices?.[0]?.message?.content ?? '';
    finish('OK', `${text.length} chars returned`);
    try {
      const parsed = JSON.parse(text);
      return Array.isArray(parsed.findings) ? parsed.findings : [];
    } catch {
      throw new Error('LLM returned non-JSON output; skipping chunk.');
    }
  }

  async function llmAvailable() {
    if (LLM_PROVIDER === 'openai') return !!openaiApiKeyValue;
    try {
      const probe = await fetch(`${LLM_SCAN_URL}/health`, { signal: AbortSignal.timeout(3000) });
      return probe.ok;
    } catch {
      return false;
    }
  }

  // Short-TTL cache around llmAvailable() — callers (GET /api/config on every
  // page load, plus the AI-explain/AI-fix endpoints) don't need a fresh
  // health-probe on every single call; a stale-for-at-most-15s "available"
  // verdict is harmless since checkLlmDeepScan's own inline health-probe is
  // still the actual gate at scan time.
  let llmAvailableCache = { value: null, expiresAt: 0 };
  async function llmAvailableCached() {
    if (llmAvailableCache.value !== null && Date.now() < llmAvailableCache.expiresAt) {
      return llmAvailableCache.value;
    }
    const value = await llmAvailable();
    llmAvailableCache = { value, expiresAt: Date.now() + 15_000 };
    return value;
  }

  // Throws a typed Error (err.code: 'timeout'|'network_error'|'http_error'|
  // 'empty_response') on any failure instead of swallowing it into a bare
  // `null` return — a timeout, a dead endpoint, and the model legitimately
  // returning nothing are three different situations, and callers that
  // want to tell a user *why* their AI request failed (Studio's per-issue
  // "Explain"/"Suggest fix" buttons) need that distinction. Callers that
  // only ever wanted best-effort/optional behavior (generateFailureInsight)
  // already wrap their call in try/catch treating any throw as "unavailable"
  // — same effective behavior as the old null return, just explicit now.
  function llmError(message, code, extra) {
    const err = new Error(message);
    err.code = code;
    if (extra) Object.assign(err, extra);
    return err;
  }

  async function llmComplete(systemPrompt, userContent, { temperature = 0.2, timeoutMs = 120_000, label = 'complete' } = {}) {
    const { url, model, headers } = llmTarget();
    const finish = traceLlmCall(`${label} [${LLM_PROVIDER}]`, { url, model, timeoutMs, chars: userContent.length });
    const payload = {
      model,
      stream: false,
      temperature,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userContent },
      ],
    };
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers,
        signal: AbortSignal.timeout(timeoutMs),
        body: JSON.stringify(payload),
      });
    } catch (e) {
      const timedOut = e.name === 'TimeoutError';
      finish(timedOut ? 'TIMED OUT' : 'FAILED', e.message);
      const err = timedOut
        ? llmError(`LLM request timed out after ${timeoutMs}ms`, 'timeout', { timeoutMs })
        : llmError(`Could not reach the LLM endpoint: ${e.message}`, 'network_error');
      logLlmExchange(label, payload, null, err);
      throw err;
    }
    if (!res.ok) {
      finish('HTTP ERROR', String(res.status));
      const err = llmError(`LLM endpoint returned HTTP ${res.status}`, 'http_error', { status: res.status });
      logLlmExchange(label, payload, null, err);
      throw err;
    }
    const data = await res.json();
    const text = (data.choices?.[0]?.message?.content || '').trim();
    finish('OK', `${text.length} chars returned`);
    if (!text) {
      const err = llmError('LLM returned an empty response', 'empty_response');
      logLlmExchange(label, payload, null, err);
      throw err;
    }
    logLlmExchange(label, payload, text, null);
    return text;
  }

  return { llmTarget, traceLlmCall, llmChat, llmAvailable, llmAvailableCached, llmComplete };
}

module.exports = { createLlmClient };
