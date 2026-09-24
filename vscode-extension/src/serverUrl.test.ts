import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeBaseUrl, cleanApiKey, maskApiKey } from './serverUrl';

test('normalizeBaseUrl adds a missing scheme and strips trailing slashes', () => {
  assert.deepEqual(normalizeBaseUrl('localhost:51337/'), { ok: true, url: 'http://localhost:51337' });
  assert.deepEqual(normalizeBaseUrl('  https://ignite.example.com///  '), { ok: true, url: 'https://ignite.example.com' });
});

test('normalizeBaseUrl keeps a reverse-proxy path prefix', () => {
  assert.deepEqual(normalizeBaseUrl('https://tools.example.com/ignite/'), { ok: true, url: 'https://tools.example.com/ignite' });
});

test('normalizeBaseUrl rejects empty, non-http, query, fragment and credential URLs', () => {
  for (const bad of ['', '   ', 'ftp://host', 'http://host?x=1', 'http://host#top', 'http://user:pw@host', 'http://']) {
    const result = normalizeBaseUrl(bad);
    assert.equal(result.ok, false, `expected "${bad}" to be rejected`);
  }
});

test('cleanApiKey tolerates a pasted Bearer prefix', () => {
  assert.equal(cleanApiKey('  Bearer ignite_abc  '), 'ignite_abc');
  assert.equal(cleanApiKey('ignite_abc'), 'ignite_abc');
  assert.equal(cleanApiKey('   '), '');
});

test('maskApiKey never returns the whole key', () => {
  const key = 'ignite_0123456789abcdef';
  const masked = maskApiKey(key);
  assert.ok(!masked.includes('0123456789ab'));
  assert.ok(masked.startsWith('ignite_') && masked.endsWith('cdef'));
  assert.equal(maskApiKey('short'), '•••••');
  assert.equal(maskApiKey(''), '');
});
