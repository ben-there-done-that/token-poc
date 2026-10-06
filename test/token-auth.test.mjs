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
      value: '',
      addEventListener: (type, callback) => { listeners[`${selector}:${type}`] = callback; },
    });
    return elements.get(selector);
  };
  let signIns = 0;
  let timeout;
  let timeoutMs;
  const saved = {
    window: globalThis.window,
    document: globalThis.document,
    sessionStorage: globalThis.sessionStorage,
  };
  globalThis.sessionStorage = { setItem() {}, removeItem() {} };
  globalThis.window = {
    location: { origin: 'https://app.example' },
    addEventListener() {},
    setTimeout: (callback, milliseconds) => { timeout = callback; timeoutMs = milliseconds; },
    open: () => ({ location: {} }),
    adobeIMS: { getAccessToken: () => null, signIn: () => { signIns += 1; } },
  };
  globalThis.window.parent = globalThis.window;
  globalThis.document = {
    querySelector: element,
    createElement: () => ({}),
    head: {
      append: () => {
        globalThis.window.adobeid.onError({ name: 'check-token-failed' });
        globalThis.window.adobeid.onReady();
      },
    },
  };
  try {
    const appSource = app.replace("'./auth.js'", JSON.stringify(moduleUrl));
    await import(`data:text/javascript;base64,${Buffer.from(appSource).toString('base64')}`);
    listeners['#imslib:click']();
    assert.equal(signIns, 1, 'an anonymous independent IMS instance must open browser sign-in');
    const evidence = JSON.parse(element('#evidence').textContent);
    assert.equal(evidence.attempts[0].status, 'pending');
    assert.equal(evidence.sdkTokenUsed, false);
    assert.equal(typeof timeout, 'function', 'browser authorization needs a bounded callback wait');
    timeout();
    assert.equal(JSON.parse(element('#evidence').textContent).attempts[0].status, 'no-callback');
    await listeners['#pkce:click']();
    assert.equal(timeoutMs, 300000, 'interactive PKCE must allow time for user consent');
  } finally {
    Object.assign(globalThis, saved);
  }
});

test('reports only a safe IMS error code, not arbitrary messages or token-bearing payloads', () => {
  assert.equal(typeof auth.imsErrorCode, 'function', 'safe IMS error-code helper is missing');
  assert.equal(auth.imsErrorCode({ error: 'networkError', message: 'synthetic-token-bearing-message' }), 'networkError');
  assert.equal(auth.imsErrorCode({ name: 'Error', message: 'synthetic-token-bearing-message' }), 'Error');
  assert.equal(auth.imsErrorCode({ error: 'unexpected https://example.com?access_token=synthetic' }), 'IMS error');
  assert.equal(auth.imsErrorCode('raw-sensitive-message'), 'IMS error');
});

test('generates the RFC 7636 S256 challenge and an unpredictable public-client verifier', async () => {
  assert.equal(typeof auth.pkceChallenge, 'function', 'PKCE challenge generation is missing');
  assert.equal(await auth.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  const first = await auth.createPkce();
  const second = await auth.createPkce();
  assert.match(first.verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first.verifier, second.verifier);
  assert.equal(first.challenge, await auth.pkceChallenge(first.verifier));
});

test('requests a PKCE code for darkalley or an explicit independently registered SPA client', () => {
  assert.equal(typeof auth.codeAuthorizeUrl, 'function', 'PKCE authorization URL builder is missing');
  for (const clientId of ['darkalley', 'synthetic-spa-client']) {
    const url = new URL(auth.codeAuthorizeUrl('https://app.example', 'nonce', 'challenge', { clientId, scope: 'openid,AdobeID' }));
    assert.equal(url.searchParams.get('client_id'), clientId);
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.equal(url.searchParams.get('response_mode'), 'fragment');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('code_challenge'), 'challenge');
    assert.equal(url.searchParams.get('redirect_uri'), 'https://app.example/tools/token/callback.html');
    assert.equal(url.searchParams.get('state'), 'nonce');
    assert.equal(url.searchParams.get('scope'), 'openid,AdobeID');
    assert.equal(url.searchParams.has('client_secret'), false);
  }
});

test('accepts only state-bound authorization codes and sanitizes callback errors', () => {
  assert.equal(typeof auth.acceptCodeResult, 'function', 'code callback validation is missing');
  assert.deepEqual(auth.acceptCodeResult('#code=synthetic-code&state=nonce', 'nonce'), { code: 'synthetic-code' });
  assert.throws(() => auth.acceptCodeResult('?code=synthetic-code&state=other', 'nonce'), /state/i);
  assert.throws(() => auth.acceptCodeResult('?code=synthetic-code', null), /state/i);
  assert.throws(() => auth.acceptCodeResult('#error=invalid_client&state=nonce', 'nonce'), /invalid_client/);
  assert.throws(() => auth.acceptCodeResult('#state=nonce', 'nonce'), /no authorization code/i);
});

test('exchanges a code in the browser using PKCE without a client secret or the SDK token', async () => {
  assert.equal(typeof auth.exchangeCode, 'function', 'public-client code exchange is missing');
  let request;
  const fetcher = async (url, options) => {
    request = { url, options };
    return { ok: true, status: 200, json: async () => ({ access_token: 'synthetic-new-token', expires_in: 3600, refresh_token: 'synthetic-discarded-refresh' }) };
  };
  assert.deepEqual(await auth.exchangeCode('synthetic-spa-client', 'synthetic-code', 'synthetic-verifier', fetcher), { token: 'synthetic-new-token', expiresIn: 3600 });
  const url = new URL(request.url);
  assert.equal(url.pathname, '/ims/token/v3');
  assert.equal(url.searchParams.get('client_id'), 'synthetic-spa-client');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.credentials, 'omit');
  const body = new URLSearchParams(request.options.body);
  assert.equal(body.get('grant_type'), 'authorization_code');
  assert.equal(body.get('code'), 'synthetic-code');
  assert.equal(body.get('code_verifier'), 'synthetic-verifier');
  assert.equal(body.has('client_secret'), false);
  assert.equal(request.options.headers.Authorization, undefined);
  assert.equal(url.searchParams.has('code'), false);
});

test('code-exchange failures never include codes, verifiers, or arbitrary IMS response text', async () => {
  assert.equal(typeof auth.exchangeCode, 'function', 'public-client code exchange is missing');
  const fetcher = async () => ({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant', error_description: 'synthetic-sensitive-code' }) });
  await assert.rejects(auth.exchangeCode('client', 'synthetic-code', 'synthetic-verifier', fetcher), error => {
    assert.match(error.message, /400.*invalid_grant/);
    assert.ok(!/synthetic/.test(error.message));
    return true;
  });
});

test('invalid token-endpoint JSON is reported without exposing response fragments', async () => {
  const fetcher = async () => ({
    ok: false,
    status: 502,
    json: async () => { throw new SyntaxError('synthetic-sensitive-response'); },
  });
  await assert.rejects(auth.exchangeCode('client', 'synthetic-code', 'synthetic-verifier', fetcher), error => {
    assert.match(error.message, /invalid JSON/);
    assert.ok(!error.message.includes('synthetic'));
    return true;
  });
});

test('the deployed app defaults to the registered public SPA client and identity-only scopes', async () => {
  const html = await readFile(new URL('../tools/token/index.html', import.meta.url), 'utf8');
  assert.match(html, /id="client-id" value="70d42326a3344517a75310c36b9b4f2b"/);
  assert.match(html, /id="scope" value="openid,AdobeID,profile,email,org.read"/);
  assert.ok(!html.includes('client_secret'));
});
