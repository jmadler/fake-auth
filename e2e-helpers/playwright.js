/**
 * auth2 E2E helpers for Playwright
 * @module auth2-e2e-helpers/playwright
 */

const {
  buildAuthorizeUrl,
  LOGIN_SELECTORS,
} = require('./utils');

/**
 * Log in to auth2 by navigating to the login page, filling credentials, and submitting.
 * Use when you want to log in without going through the full OAuth redirect flow.
 *
 * @param {import('playwright').Page} page - Playwright page
 * @param {object} options
 * @param {string} options.email - User email
 * @param {string} options.password - User password
 * @param {string} [options.baseUrl] - auth2 issuer URL (e.g. http://localhost:9092)
 * @param {string} [options.clientId] - OAuth client ID
 * @param {string} [options.redirectUri] - Required for OAuth; e.g. http://localhost:3000/callback
 * @param {string} [options.scope='openid profile email']
 * @param {string} [options.emailSelector] - Override email input selector
 * @param {string} [options.passwordSelector] - Override password input selector
 * @param {string} [options.submitSelector] - Override submit button selector
 * @returns {Promise<void>}
 */
async function auth2Login(page, options = {}) {
  const {
    email,
    password,
    baseUrl = 'http://localhost:9092',
    clientId = 'e2e-test',
    redirectUri = baseUrl + '/callback',
    scope = 'openid profile email',
    emailSelector = LOGIN_SELECTORS.email,
    passwordSelector = LOGIN_SELECTORS.password,
    submitSelector = LOGIN_SELECTORS.submit,
  } = options;

  if (!email || !password) {
    throw new Error('auth2Login: email and password are required');
  }

  const base = baseUrl.replace(/\/$/, '');
  const loginUrl = `${base}/login?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=test&response_type=code`;

  await page.goto(loginUrl, { waitUntil: 'networkidle' });

  await page.locator(emailSelector).fill(email);
  await page.locator(passwordSelector).fill(password);
  await page.locator(submitSelector).click();

  await page.waitForURL((url) => url.toString().startsWith(redirectUri) || url.toString().includes('code='), {
    timeout: 10000,
  }).catch(() => {
    // May have navigated; continue
  });
}

/**
 * Perform full auth2 login with redirect: visit authorize URL, fill login, handle callback.
 * Use when testing the complete OAuth authorization code flow.
 *
 * @param {import('playwright').Page} page - Playwright page
 * @param {object} options
 * @param {string} options.baseUrl - auth2 issuer URL
 * @param {string} options.clientId - OAuth client ID
 * @param {string} options.redirectUri - Callback URL (must be registered for client)
 * @param {string} options.email - User email
 * @param {string} options.password - User password
 * @param {string} [options.scope='openid profile email']
 * @param {number} [options.timeout=10000] - Wait timeout for redirect (ms)
 * @returns {Promise<{url: string, code?: string, codeVerifier?: string}>} - Final URL and extracted code/codeVerifier if applicable
 */
async function auth2LoginWithRedirect(page, options = {}) {
  const {
    baseUrl = 'http://localhost:9092',
    clientId = 'e2e-test',
    redirectUri,
    email,
    password,
    scope = 'openid profile email',
    timeout = 10000,
    emailSelector = LOGIN_SELECTORS.email,
    passwordSelector = LOGIN_SELECTORS.password,
    submitSelector = LOGIN_SELECTORS.submit,
  } = options;

  if (!baseUrl || !clientId || !redirectUri || !email || !password) {
    throw new Error('auth2LoginWithRedirect: baseUrl, clientId, redirectUri, email, and password are required');
  }

  const { url: authorizeUrl, codeVerifier } = await buildAuthorizeUrl({
    baseUrl,
    clientId,
    redirectUri,
    scope,
    responseType: 'code',
  });

  await page.goto(authorizeUrl, { waitUntil: 'networkidle' });

  await page.locator(emailSelector).fill(email);
  await page.locator(passwordSelector).fill(password);
  await page.locator(submitSelector).click();

  const finalUrl = await page.waitForURL(
    (url) => {
      try {
        return url.toString().startsWith(redirectUri);
      } catch {
        return false;
      }
    },
    { timeout }
  ).then((r) => r.url()).catch(async () => page.url());

  const parsed = new URL(finalUrl);
  const code = parsed.searchParams.get('code');

  return { url: finalUrl, code, codeVerifier };
}

/**
 * Simple login helper with flat options.
 * Alias for auth2Login with { email, password, ...options }.
 *
 * @param {import('playwright').Page} page
 * @param {string} email
 * @param {string} password
 * @param {object} [options] - Same as auth2Login options
 */
async function login(page, email, password, options = {}) {
  return auth2Login(page, { ...options, email, password });
}

module.exports = {
  auth2Login,
  auth2LoginWithRedirect,
  login,
};
