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
