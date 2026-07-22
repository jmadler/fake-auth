/**
 * Generate a random string for OAuth state.
 */
function randomState() {
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate PKCE code verifier (43-128 chars, unreserved).
 */
function generateCodeVerifier() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const bytes = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  let verifier = '';
  for (let i = 0; i < 43; i++) {
    verifier += chars[bytes[i % bytes.length] % chars.length];
  }
  return verifier;
}

/**
 * Generate S256 code challenge from verifier.
 * @param {string} verifier
 * @returns {Promise<string>}
 */
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Build auth2 authorize URL.
 * @param {object} opts
 * @param {string} opts.baseUrl - auth2 issuer URL (e.g. http://localhost:9092)
 * @param {string} opts.clientId
 * @param {string} opts.redirectUri
 * @param {string} [opts.scope='openid profile email']
 * @param {string} [opts.state]
 * @param {string} [opts.responseType='code']
 * @param {string} [opts.codeChallenge]
 * @param {string} [opts.codeChallengeMethod='S256']
 * @param {string} [opts.audience]
 * @returns {Promise<{url: string, codeVerifier?: string}>}
 */
async function buildAuthorizeUrl(opts) {
  const baseUrl = (opts.baseUrl || opts.baseURL || '').replace(/\/$/, '');
  const clientId = opts.clientId || opts.client_id || 'e2e-test';
  const redirectUri = opts.redirectUri || opts.redirect_uri;
  const scope = opts.scope || 'openid profile email';
  const responseType = opts.responseType || opts.response_type || 'code';
  const state = opts.state || randomState();

  const params = new URLSearchParams({
    response_type: responseType,
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    state,
  });

  if (opts.audience) params.set('audience', opts.audience);

  let codeVerifier;
  if (responseType === 'code') {
    codeVerifier = opts.codeVerifier || generateCodeVerifier();
    const codeChallenge = opts.codeChallenge || (await generateCodeChallenge(codeVerifier));
    params.set('code_challenge', codeChallenge);
    params.set('code_challenge_method', opts.codeChallengeMethod || 'S256');
  }

  const url = `${baseUrl}/authorize?${params.toString()}`;
  return { url, codeVerifier };
}

/**
 * Default selectors for auth2 login form.
 */
const LOGIN_SELECTORS = {
  email: 'input[name="username"]',
  password: 'input[name="password"]',
  submit: 'button[type="submit"]',
  form: 'form[action="/login"]',
};

module.exports = {
  randomState,
  generateCodeVerifier,
  generateCodeChallenge,
  buildAuthorizeUrl,
  LOGIN_SELECTORS,
};
