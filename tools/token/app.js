import {
  CLIENT_ID, SCOPE, authorizeUrl, isOAuthMessage, tokenSummary, verifyDaRead, daContextSummary,
  imsErrorCode, createPkce, codeAuthorizeUrl, exchangeCode,
} from './auth.js';

const evidence = {
  appOrigin: window.location.origin,
  embedded: window.parent !== window,
  sdkTokenUsed: false,
  sdkTokenReceived: false,
  attempts: [],
};
const output = document.querySelector('#evidence');
const status = document.querySelector('#status');
let popup;
let state;
let imslibLoaded = false;
let currentAttempt;
let pkce;

function render(message) {
  if (message) status.textContent = message;
  output.textContent = JSON.stringify(evidence, null, 2);
}

function begin(method) {
  state = null;
  popup = null;
  pkce = null;
  currentAttempt = { method, startedAt: new Date().toISOString(), status: 'pending' };
  const attempt = currentAttempt;
  evidence.attempts.push(attempt);
  window.setTimeout(() => {
    if (attempt.status !== 'pending') return;
    attempt.status = 'no-callback';
    render('IMS did not return a token to this app within 30 seconds. See sanitized evidence.');
  }, 30000);
  render('Waiting for IMS. Any DA-supplied token is ignored.');
  return currentAttempt;
}

async function verify(token, attempt) {
  if (!token || attempt.status !== 'pending') return;
  attempt.status = 'minted';
  attempt.token = tokenSummary(token);
  attempt.receivedAt = new Date().toISOString();
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  attempt.fingerprint = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  render('An independently obtained token is available. Checking a read-only DA request.');
  try {
    attempt.daRead = await verifyDaRead(token);
  } catch (error) {
    attempt.daRead = { ok: false, error: error.name };
  }
  render(attempt.daRead.ok ? 'Success: own IMS token accepted by DA (HTTP 200).' : 'Token obtained; DA read did not succeed. See sanitized evidence.');
}

window.addEventListener('message', async (event) => {
  if (event.source === window.parent && event.origin === 'https://da.live' && event.data?.ready && event.ports.length) {
    Object.assign(evidence, daContextSummary(event.data));
    event.ports[0].postMessage({ action: 'setTitle', details: document.title });
    render('DA initialized this app. Its supplied token was ignored.');
  }
  if (!isOAuthMessage(event, window.location.origin, popup, state)) return;
  const attempt = currentAttempt;
  if (attempt.status !== 'pending') return;
  sessionStorage.removeItem('token-poc-state');
  sessionStorage.removeItem('token-poc-flow');
  state = null;
  if (event.data.error) {
    attempt.status = 'error';
    attempt.error = event.data.error;
    render('IMS rejected this authorization request.');
    return;
  }
  if (event.data.code && pkce) {
    attempt.authorizationCodeReceived = true;
    render('Authorization code received. Exchanging it using this app’s PKCE verifier.');
    try {
      const result = await exchangeCode(attempt.clientId, event.data.code, pkce.verifier);
      pkce = null;
      await verify(result.token, attempt);
    } catch (error) {
      pkce = null;
      attempt.status = 'error';
      attempt.error = error.name === 'TypeError' ? 'Token endpoint network/CORS failure' : error.message;
      render('PKCE token exchange failed. See sanitized evidence.');
    }
  } else {
    verify(event.data.token, attempt);
  }
});

document.querySelector('#oauth').addEventListener('click', () => {
  if (currentAttempt?.status === 'pending') return;
  const attempt = begin('direct-browser-oauth');
  state = crypto.randomUUID();
  sessionStorage.setItem('token-poc-state', state);
  sessionStorage.setItem('token-poc-flow', 'token');
  popup = window.open(authorizeUrl(window.location.origin, state), 'token-poc-login', 'popup,width=650,height=760');
  if (!popup) {
    attempt.status = 'blocked';
    render('Popup blocked. Allow this app to open its login popup.');
  }
});

document.querySelector('#pkce').addEventListener('click', async () => {
  if (currentAttempt?.status === 'pending') return;
  const attempt = begin('authorization-code-pkce');
  attempt.clientId = document.querySelector('#client-id').value.trim() || CLIENT_ID;
  attempt.scope = document.querySelector('#scope').value.trim() || SCOPE;
  attempt.authorizationCodeReceived = false;
  state = crypto.randomUUID();
  sessionStorage.setItem('token-poc-state', state);
  sessionStorage.setItem('token-poc-flow', 'code');
  popup = window.open('about:blank', 'token-poc-login', 'popup,width=650,height=760');
  if (!popup) {
    attempt.status = 'blocked';
    render('Popup blocked. Allow this app to open its login popup.');
    return;
  }
  pkce = await createPkce();
  attempt.challengeMethod = 'S256';
  popup.location.href = codeAuthorizeUrl(window.location.origin, state, pkce.challenge, attempt);
});

document.querySelector('#imslib').addEventListener('click', () => {
  if (currentAttempt?.status === 'pending') return;
  const attempt = begin('own-imslib-instance');
  if (imslibLoaded) {
    attempt.status = 'skipped';
    render('Reload before testing IMS library again; this avoids reusing its cached token.');
    return;
  }
  imslibLoaded = true;
  window.adobeid = {
    client_id: CLIENT_ID,
    scope: SCOPE,
    environment: 'prod',
    useLocalStorage: false,
    ignoreUrlToken: true,
    alwaysRemoveTokenFromUrl: true,
    autoValidateToken: true,
    modalMode: true,
    modalSettings: { allowedOrigin: window.location.origin },
    onAccessToken: (result) => verify(result?.token, attempt),
    onReady: () => {
      const result = window.adobeIMS.getAccessToken();
      if (result?.token) verify(result.token, attempt);
      else {
        attempt.status = 'pending';
        delete attempt.error;
        window.adobeIMS.signIn();
        render('Own IMS instance opened browser sign-in. Any DA-supplied token is ignored.');
      }
    },
    onError: (error) => {
      attempt.status = 'error';
      attempt.error = imsErrorCode(error);
      render('Own IMS library could not mint a token.');
    },
  };
  const script = document.createElement('script');
  script.src = 'https://auth.services.adobe.com/imslib/imslib.min.js';
  script.onerror = () => {
    attempt.status = 'error';
    attempt.error = 'IMS library load failed';
    render(attempt.error);
  };
  document.head.append(script);
});

document.querySelector('#download').addEventListener('click', () => {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(evidence, null, 2)], { type: 'application/json' }));
  link.download = 'token-poc-evidence.json';
  link.click();
  URL.revokeObjectURL(link.href);
});

render('Ready. No DA SDK is imported; no supplied token is used.');
