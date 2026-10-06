import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../tools/token/auth.js', import.meta.url), 'utf8').catch((error) => {
  if (error.code === 'ENOENT') return '';
  throw error;
});
const auth = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const jwt = (claims) => `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;

test('creates a browser authorization request for darkalley and this app callback', () => {
  assert.equal(typeof auth.authorizeUrl, 'function', 'browser authorization builder is missing');
  const url = new URL(auth.authorizeUrl('https://main--token-poc--ben-there-done-that.aem.live', 'nonce'));
  assert.equal(url.origin, 'https://ims-na1.adobelogin.com');
  assert.equal(url.pathname, '/ims/authorize/v2');
  assert.equal(url.searchParams.get('client_id'), 'darkalley');
  assert.equal(url.searchParams.get('response_type'), 'token');
  assert.equal(url.searchParams.get('state'), 'nonce');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://main--token-poc--ben-there-done-that.aem.live/tools/token/callback.html');
  assert.ok(url.searchParams.get('scope').split(',').includes('aem.frontend.all'));
});

test('rejects missing and mismatched OAuth state before accepting any token', () => {
  assert.equal(typeof auth.acceptOAuthResult, 'function', 'OAuth state validator is missing');
  assert.throws(() => auth.acceptOAuthResult('#access_token=synthetic&state=wrong', 'nonce'), /state/i);
  assert.throws(() => auth.acceptOAuthResult('#access_token=synthetic', null), /state/i);
});

test('accepts a state-bound callback and reports OAuth errors without leaking parameters', () => {
  assert.equal(typeof auth.acceptOAuthResult, 'function', 'OAuth callback parser is missing');
  assert.deepEqual(auth.acceptOAuthResult('#access_token=synthetic&state=nonce&expires_in=3600', 'nonce'), { token: 'synthetic', expiresIn: 3600 });
  assert.throws(() => auth.acceptOAuthResult('#error=invalid_redirect_uri&state=nonce', 'nonce'), /invalid_redirect_uri/);
});

test('only permits same-origin messages from the actual login popup with matching state', () => {
  assert.equal(typeof auth.isOAuthMessage, 'function', 'popup message validation is missing');
  const popup = {};
  const event = { origin: 'https://app.example', source: popup, data: { type: 'token-poc-oauth', state: 'nonce' } };
  assert.equal(auth.isOAuthMessage(event, 'https://app.example', popup, 'nonce'), true);
  assert.equal(auth.isOAuthMessage({ ...event, origin: 'https://evil.example' }, 'https://app.example', popup, 'nonce'), false);
  assert.equal(auth.isOAuthMessage({ ...event, source: {} }, 'https://app.example', popup, 'nonce'), false);
  assert.equal(auth.isOAuthMessage({ ...event, data: { ...event.data, state: 'wrong' } }, 'https://app.example', popup, 'nonce'), false);
  assert.equal(auth.isOAuthMessage(event, 'https://app.example', null, 'nonce'), false);
});

test('exposes only non-secret token metadata, never token or user profile claims', () => {
  assert.equal(typeof auth.tokenSummary, 'function', 'safe token summarizer is missing');
  const token = jwt({ client_id: 'darkalley', scope: 'AdobeID,aem.frontend.all', exp: 1900000000, iat: 1800000000, user_id: 'private-user', email: 'private@example.com' });
  const summary = auth.tokenSummary(token);
  assert.deepEqual(summary, { clientId: 'darkalley', scopes: ['AdobeID', 'aem.frontend.all'], issuedAt: 1800000000, expiresAt: 1900000000 });
  assert.ok(!JSON.stringify(summary).includes('private'));
  assert.ok(!JSON.stringify(summary).includes(token));
  assert.deepEqual(auth.tokenSummary('opaque-token'), { clientId: null, scopes: [], issuedAt: null, expiresAt: null });
});

test('reads only this PoC DA source using the freshly minted token, not SDK fetch helpers', async () => {
  assert.equal(typeof auth.verifyDaRead, 'function', 'fresh-token DA read is missing');
  let request;
  const fetcher = async (url, options) => {
    request = { url, options };
    return { status: 200, ok: true };
  };
  assert.deepEqual(await auth.verifyDaRead('synthetic-fresh-token', fetcher), { status: 200, ok: true });
  assert.equal(request.url, 'https://admin.da.live/source/ben-there-done-that/token-poc/index.html');
  assert.equal(request.options.headers.Authorization, 'Bearer synthetic-fresh-token');
  assert.equal(request.options.credentials, 'omit');
});

test('DA initialization records presence only and cannot return the supplied token', () => {
  assert.equal(typeof auth.daContextSummary, 'function', 'token-ignoring DA handshake is missing');
  const summary = auth.daContextSummary({ ready: true, token: 'synthetic-sdk-token', context: { org: 'ben-there-done-that', repo: 'token-poc' } });
  assert.deepEqual(summary, { initialized: true, sdkTokenReceived: true, sdkTokenUsed: false });
  assert.ok(!JSON.stringify(summary).includes('synthetic-sdk-token'));
});

test('the app starts its own browser sign-in when its IMS instance initializes anonymously', async () => {
  const app = await readFile(new URL('../tools/token/app.js', import.meta.url), 'utf8');
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
  const listeners = {};
  const elements = new Map();
  const element = (selector) => {
    if (!elements.has(selector)) elements.set(selector, {
      textContent: '',
      addEventListener: (type, callback) => { listeners[`${selector}:${type}`] = callback; },
    });
    return elements.get(selector);
  };
  let signIns = 0;
  const saved = { window: globalThis.window, document: globalThis.document };
  globalThis.window = {
    location: { origin: 'https://app.example' },
    addEventListener() {},
    adobeIMS: { getAccessToken: () => null, signIn: () => { signIns += 1; } },
  };
  globalThis.window.parent = globalThis.window;
  globalThis.document = {
    querySelector: element,
    createElement: () => ({}),
    head: { append: () => globalThis.window.adobeid.onReady() },
  };
  try {
    const appSource = app.replace("'./auth.js'", JSON.stringify(moduleUrl));
    await import(`data:text/javascript;base64,${Buffer.from(appSource).toString('base64')}`);
    listeners['#imslib:click']();
    assert.equal(signIns, 1, 'an anonymous independent IMS instance must open browser sign-in');
    const evidence = JSON.parse(element('#evidence').textContent);
    assert.equal(evidence.attempts[0].status, 'pending');
    assert.equal(evidence.sdkTokenUsed, false);
  } finally {
    Object.assign(globalThis, saved);
  }
});
