import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from 'node:test';

const execFileAsync = promisify(execFile);

test('Telegram adapter works without URL, Headers, AbortController, or global fetch', async () => {
  // A separate process imports the unchanged ESM module after removing the
  // globals absent from Telegram. This also catches future module-load uses.
  const moduleUrl = new URL('../runtime/secret-fetch.js', import.meta.url).href;
  const source = `
    import assert from 'node:assert/strict';
    const NativeURL = URL;
    for (const name of ['URL', 'Headers', 'AbortController', 'fetch']) delete globalThis[name];
    const { createTelegramSecretFetch, MAX_CLIENT_REQUEST_BYTES } = await import(${JSON.stringify(moduleUrl)});
    const capability = 'tgscap_synthetic_compatibility_probe';
    const accepted = [
      ['https://broker.example.com', 'https://broker.example.com'],
      ['HTTPS://BROKER.EXAMPLE.COM:443/', 'https://broker.example.com'],
      ['https://broker.example.com:8443/', 'https://broker.example.com:8443'],
      ['https://xn--bcher-kva.example', 'https://xn--bcher-kva.example'],
      ['https://203.0.113.1', 'https://203.0.113.1'],
      ['https://[2001:db8::1]:8443', 'https://[2001:db8::1]:8443'],
      ['http://localhost:8787', 'http://localhost:8787'],
      ['http://127.0.0.1:8787', 'http://127.0.0.1:8787'],
      ['http://127.0.0.2:8787', 'http://127.0.0.2:8787'],
      ['http://[::1]:8787', 'http://[::1]:8787'],
    ];
    for (const [endpoint, origin] of accepted) {
      const calls = [];
      const expected = { ok: true, status: 200 };
      const send = createTelegramSecretFetch({ endpoint, capability, fetch: async (url, options) => {
        calls.push({ url, options });
        return expected;
      } });
      assert.equal(await send('/probe#fragment', { method: 'POST', body: { probe: 'telegram-serverless' } }), expected);
      assert.equal(calls[0].url, origin + '/v1/fetch');
      assert.equal(new NativeURL(calls[0].url).origin, new NativeURL(endpoint).origin);
      assert.equal(calls[0].options.headers['x-tgcloud-capability'], capability);
      assert.equal(calls[0].options.redirect, 'error');
      const payload = JSON.parse(calls[0].options.body);
      assert.equal(payload.path, '/probe');
      assert.equal(payload.method, 'POST');
      assert.equal(payload.headers['content-type'], 'application/json');
      assert.deepEqual(JSON.parse(payload.body), { probe: 'telegram-serverless' });
      await assert.rejects(() => send('/probe', { body: 'x'.repeat(MAX_CLIENT_REQUEST_BYTES) }), /too large/);
      await assert.rejects(() => send('//evil.example/path'), /absolute path/);
      await assert.rejects(() => send('/probe', { headers: { authorization: 'value\\r\\nInjected: yes' } }), /unsafe/);
      assert.equal(calls.length, 1);
    }
    const rejected = [
      'http://broker.example.com', 'http://10.0.0.1', 'http://[::2]',
      'http://127.evil.example', 'http://localhost.evil.example',
      'http://127.1', 'http://127.000.000.001', 'http://0x7f000001', 'http://2130706433',
      'https://user:password@broker.example.com', 'https://broker.example.com/path',
      'https://broker.example.com/..', 'https://broker.example.com?query',
      'https://broker.example.com#fragment', 'https://broker.example.com?',
      'https://broker.example.com#', 'https://broker.example.com:65536',
      'https://broker.example.com:', 'https://broker..example',
      'https://-broker.example', 'https://broker_.example',
      'https://%62roker.example', 'https://broker.example.com\\\\@evil.example',
      'https://broker.example.com\\n', 'https://[::::]', 'https://[1:2:3]',
      'https://[1:2:3:4:5:6:7:8:9]', 'https://[1:2:3:4:5:6:7:8::]',
      'https://[1::2::3]', 'ftp://broker.example.com',
    ];
    for (const control of [0, 9, 10, 13, 127, 0x2028, 0x2029]) {
      rejected.push('https://broker.example.com' + String.fromCharCode(control));
    }
    let called = false;
    for (const endpoint of rejected) {
      assert.throws(() => createTelegramSecretFetch({ endpoint, capability, fetch: async () => { called = true; } }), endpoint);
    }
    assert.equal(called, false);
    console.log('Telegram runtime regression checks passed');
  `;
  const { stdout } = await execFileAsync(process.execPath, ['--input-type=module', '-e', source], { timeout: 30_000 });
  assert.match(stdout, /Telegram runtime regression checks passed/);
});
