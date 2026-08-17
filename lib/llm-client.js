'use strict';

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
  const OPENAI_API_KEY = openai?.apiKey || '';
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
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${OPENAI_API_KEY}` },
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
    if (LLM_PROVIDER === 'openai') return !!OPENAI_API_KEY;
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

  async function llmComplete(systemPrompt, userContent, { temperature = 0.2, timeoutMs = 120_000, label = 'complete' } = {}) {
    const { url, model, headers } = llmTarget();
    const finish = traceLlmCall(`${label} [${LLM_PROVIDER}]`, { url, model, timeoutMs, chars: userContent.length });
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers,
        signal: AbortSignal.timeout(timeoutMs),
        body: JSON.stringify({
          model,
          stream: false,
          temperature,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userContent },
          ],
        }),
      });
    } catch (e) {
      finish(e.name === 'TimeoutError' ? 'TIMED OUT' : 'FAILED', e.message);
      return null;
    }
    if (!res.ok) {
      finish('HTTP ERROR', String(res.status));
      return null;
    }
    const data = await res.json();
    const text = (data.choices?.[0]?.message?.content || '').trim();
    finish('OK', `${text.length} chars returned`);
    return text || null;
  }

  return { llmTarget, traceLlmCall, llmChat, llmAvailable, llmAvailableCached, llmComplete };
}

module.exports = { createLlmClient };
