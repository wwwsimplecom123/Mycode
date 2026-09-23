const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { page, gmail, webcrypto } = require('./helpers.cjs');
const code = fs.readFileSync(path.join(__dirname, '../../extension/content.js'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
async function setup() {
  const dom = page('mail.google.com', gmail());
  const w = dom.window;
  Object.defineProperty(w, 'crypto', { value: webcrypto });
  w.TextEncoder = TextEncoder;
  let tick, changed;
  const requests = [], timers = new Map();
  let nextTimer = 1;
  w.setInterval = callback => { tick = callback; return 1; };
  w.setTimeout = callback => { const id = nextTimer++; timers.set(id, callback); return id; };
  w.clearTimeout = id => timers.delete(id);
  w.chrome = {
    storage: { local: { get: (_keys, callback) => callback({ shielddomeApiBase: 'https://shield.example', shielddomePluginToken: 'sdp_test' }) }, onChanged: { addListener: callback => { changed = callback; } } },
    runtime: { sendMessage: message => new Promise(resolve => requests.push({ message, resolve })) },
  };
  w.eval(code);
  const step = async () => { await tick(); await flush(); };
  await step();
  return { w, requests, step, timers, changed };
}
test('unchanged mail submits once; switching invalidates a late quick result', async () => {
  const { w, requests, step } = await setup();
  assert.equal(requests.length, 1);
  assert.match(requests[0].message.payload.message_id, /^browser-[a-f0-9]{64}$/);
  await step(); await step();
  assert.equal(requests.length, 1);
  w.document.body.innerHTML = gmail('第二封', '新的正文');
  await step();
  requests[0].resolve({ ok: true, data: { risk_level: 'high', reason: '旧邮件结论', deep_scan_required: true } });
  await flush();
  assert.equal(w.document.querySelector('#shielddome-risk-banner'), null);
  await step();
  assert.equal(requests.length, 2);
  assert.notEqual(requests[0].message.payload.message_id, requests[1].message.payload.message_id);
  requests[1].resolve({ ok: true, data: { risk_level: 'low', reason: '新邮件结论' } });
  await flush();
  assert.match(w.document.querySelector('#shielddome-risk-banner').textContent, /新邮件结论/);
});
test('returning to inbox cancels polling and removes the old result', async () => {
  const { w, requests, step, timers } = await setup();
  requests[0].resolve({ ok: true, data: { analysis_id: 'a', risk_level: 'low', deep_scan_required: true } });
  await flush();
  assert.equal(timers.size, 1);
  const poll = [...timers.values()][0]; timers.clear();
  const pending = poll();
  assert.equal(requests.length, 2);
  w.document.body.innerHTML = '<p>收件箱</p>';
  await step();
  requests[1].resolve({ ok: true, data: { deep_status: 'completed', deep_result: { reason: '过期深度结果' } } });
  await pending;
  assert.equal(w.document.querySelector('#shielddome-risk-banner'), null);
  assert.equal(timers.size, 0);
});
test('mail loaded after initial inbox and changed settings trigger detection', async () => {
  const { w, requests, step, changed } = await setup();
  w.document.body.innerHTML = '';
  await step();
  w.document.body.innerHTML = gmail('异步邮件');
  await step(); await step();
  assert.equal(requests.length, 2);
  changed({}, 'local');
  await step();
  assert.equal(requests.length, 3);
});
test('response arriving before the next page sample cannot paint a different mail', async () => {
  const { w, requests } = await setup();
  w.document.body.innerHTML = gmail('刚切换的邮件');
  requests[0].resolve({ ok: true, data: { risk_level: 'high', reason: '上一封结论' } });
  await flush();
  assert.doesNotMatch(w.document.querySelector('#shielddome-risk-banner')?.textContent || '', /上一封结论/);
});
test('identical content at a different message route is detected separately', async () => {
  const { w, requests, step } = await setup();
  w.location.hash = 'message-2';
  await step(); await step();
  assert.equal(requests.length, 2);
  assert.notEqual(requests[0].message.payload.message_id, requests[1].message.payload.message_id);
  assert.ok(!JSON.stringify(requests[1].message.payload).includes('secret'));
});
