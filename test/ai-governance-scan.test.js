'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { withServerEnv, makeTempProject } = require('./helpers');

test('checkAiGovernance: flags an ungoverned LangChain agent invocation', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'agent.py': [
      'from langchain.agents import AgentExecutor',
      'executor = AgentExecutor(agent=agent, tools=tools)',
      'result = executor.invoke({"input": query})',
      '',
    ].join('\n'),
  });
  const { findings } = await mod.checkAiGovernance(dir, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'agent.py');
}));

test('checkAiGovernance: a LangGraph app with recursion_limit set is compliant', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'graph.py': [
      'from langgraph.graph import StateGraph',
      'app = StateGraph(...).compile()',
      'result = app.invoke(state, config={"recursion_limit": 25})',
      '',
    ].join('\n'),
  });
  const { findings } = await mod.checkAiGovernance(dir, null);
  assert.deepEqual(findings, []);
}));

// Regression test for a real false positive reported against a project's
// pytest suite: an httpx AsyncClient's .stream() (an HTTP call, nothing to
// do with LangChain/LangGraph) inside a test file was flagged as an
// "ungoverned AI invocation" purely because the bare method name matched.
test('checkAiGovernance: an httpx client.stream() call is not flagged (not an agent framework)', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'app.py': [
      'import httpx',
      'async def call_api(client):',
      '    async with client.stream("POST", "/api/v1/assistant/chat/stream", json={"messages": []}) as r:',
      '        return await r.aread()',
      '',
    ].join('\n'),
  });
  const { findings } = await mod.checkAiGovernance(dir, null);
  assert.deepEqual(findings, []);
}));

// Regression test for a second real false positive against the same
// project, in a production (non-test) file: a hand-rolled OpenAI-compatible
// streaming client using httpx, where the file happens to reference
// LangChain elsewhere (a different function/comment) so the file-wide
// framework hint alone wasn't enough to rule it out — the receiver of
// .stream() here is httpx.AsyncClient's `client`, not an agent/chain.
test('checkAiGovernance: client.stream() on an httpx client is not flagged even in a file that mentions langchain elsewhere', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'assistant.py': [
      '# See docs/langchain-migration.md for why this hand-rolled client exists',
      'import httpx',
      'async def _chat_completion_stream(settings, messages):',
      '    async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:',
      '        async with client.stream("POST", url, json=payload) as resp:',
      '            resp.raise_for_status()',
      '',
    ].join('\n'),
  });
  const { findings } = await mod.checkAiGovernance(dir, null);
  assert.deepEqual(findings, []);
}));

test('checkAiGovernance: a LangChain call inside a test file is not flagged (production-runtime concern, not testing)', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'tests/test_assistant.py': [
      'from langchain.chains import LLMChain',
      'async def test_chat_stream(monkeypatch, client):',
      '    monkeypatch.setattr(assistant_svc, "_chat_completion_stream", fake_stream)',
      '    async with client.stream("POST", "/api/v1/assistant/chat/stream", json={}) as r:',
      '        assert r.status_code == 200',
      '',
    ].join('\n'),
  });
  const { findings } = await mod.checkAiGovernance(dir, null);
  assert.deepEqual(findings, []);
}));
