export const CLIENT_ID = 'darkalley';
export const SCOPE = 'ab.manage,AdobeID,gnav,openid,org.read,read_organizations,session,aem.frontend.all,additional_info.ownerOrg,additional_info.projectedProductContext,account_cluster.read';

export function authorizeUrl(origin, state) {
  const url = new URL('https://ims-na1.adobelogin.com/ims/authorize/v2');
  url.search = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'token',
    scope: SCOPE,
    redirect_uri: `${origin}/tools/token/callback.html`,
    state,
  });
  return url.href;
}

export function acceptOAuthResult(hash, expectedState) {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  if (!expectedState || params.get('state') !== expectedState) throw new Error('OAuth state mismatch');
  if (params.has('error')) throw new Error(`IMS error: ${params.get('error')}`);
  const token = params.get('access_token');
  if (!token) throw new Error('IMS returned no access token');
  return { token, expiresIn: Number(params.get('expires_in')) || null };
}

export function isOAuthMessage(event, origin, popup, state) {
  return Boolean(popup && state && event.origin === origin && event.source === popup
    && event.data?.type === 'token-poc-oauth' && event.data.state === state);
}

export function tokenSummary(token) {
  let claims = {};
  try {
    const encoded = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    claims = JSON.parse(atob(encoded));
  } catch { /* Opaque tokens have no inspectable claims. */ }
  const scope = claims.scope || claims.scopes || [];
  return {
    clientId: claims.client_id || null,
    scopes: Array.isArray(scope) ? scope : scope.split(/[ ,]+/).filter(Boolean),
    issuedAt: claims.iat || claims.created_at || null,
    expiresAt: claims.exp || null,
  };
}

export async function verifyDaRead(token, fetcher = fetch) {
  const response = await fetcher('https://admin.da.live/source/ben-there-done-that/token-poc/index.html', {
    headers: { Authorization: `Bearer ${token}` },
    credentials: 'omit',
    cache: 'no-store',
    signal: AbortSignal.timeout(15000),
  });
  return { status: response.status, ok: response.ok };
}

export function daContextSummary(message) {
  return {
    initialized: Boolean(message.ready),
    sdkTokenReceived: Boolean(message.token),
    sdkTokenUsed: false,
  };
}

export function imsErrorCode(error) {
  const code = error?.error || error?.code || error?.name;
  return typeof code === 'string' && /^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$/.test(code)
    ? code : 'IMS error';
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

export async function createPkce() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  return { verifier, challenge: await pkceChallenge(verifier) };
}

export function codeAuthorizeUrl(origin, state, challenge, {
  clientId = CLIENT_ID, scope = SCOPE,
} = {}) {
  const url = new URL(authorizeUrl(origin, state));
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('scope', scope);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('response_mode', 'fragment');
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('code_challenge', challenge);
  return url.href;
}

export function acceptCodeResult(parameters, expectedState) {
  const params = new URLSearchParams(parameters.replace(/^[#?]/, ''));
  if (!expectedState || params.get('state') !== expectedState) throw new Error('OAuth state mismatch');
  if (params.has('error')) throw new Error(`IMS error: ${imsErrorCode({ error: params.get('error') })}`);
  const code = params.get('code');
  if (!code) throw new Error('IMS returned no authorization code');
  return { code };
}

export async function exchangeCode(clientId, code, verifier, fetcher = fetch) {
  const url = new URL('https://ims-na1.adobelogin.com/ims/token/v3');
  url.searchParams.set('client_id', clientId);
  const response = await fetcher(url.href, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier }),
    credentials: 'omit',
    signal: AbortSignal.timeout(15000),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(`IMS token exchange HTTP ${response.status}: ${imsErrorCode(result)}`);
  if (!result.access_token) throw new Error('IMS token exchange returned no access token');
  return { token: result.access_token, expiresIn: Number(result.expires_in) || null };
}
