/**
 * Unit tests for auth2-e2e-helpers utils (PKCE, authorize URL builders).
 * Run: node utils.test.js
 */
const assert = require('node:assert');

const {
  randomState,
  generateCodeVerifier,
  generateCodeChallenge,
  buildAuthorizeUrl,
  LOGIN_SELECTORS,
} = require('./utils');

async function runTests() {
  let pass = 0;
  let fail = 0;

  function ok(name, fn) {
    return (async () => {
      try {
        await fn();
        pass++;
        console.log(`  ✓ ${name}`);
      } catch (e) {
        fail++;
        console.error(`  ✗ ${name}`);
        console.error(`    ${e.message}`);
      }
    })();
  }

  await ok('randomState returns 32-char hex string', () => {
    const s = randomState();
    assert.strictEqual(typeof s, 'string');
    assert.strictEqual(s.length, 32);
    assert(/^[0-9a-f]+$/.test(s), 'should be hex');
  });

  await ok('generateCodeVerifier returns 43-char unreserved string', () => {
    const v = generateCodeVerifier();
    assert.strictEqual(typeof v, 'string');
    assert.strictEqual(v.length, 43, 'RFC 7636: 43-128 chars');
    assert(/^[A-Za-z0-9\-._~]+$/.test(v), 'unreserved chars only');
  });

  await ok('generateCodeChallenge produces valid base64url', async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    assert.strictEqual(typeof challenge, 'string');
    assert.ok(challenge.length > 0);
    assert(!challenge.includes('+') && !challenge.includes('/'), 'base64url');
    assert(!challenge.endsWith('='), 'no padding');
  });

  await ok('generateCodeChallenge is deterministic for same verifier', async () => {
    const v = generateCodeVerifier();
    const c1 = await generateCodeChallenge(v);
    const c2 = await generateCodeChallenge(v);
    assert.strictEqual(c1, c2);
  });

  await ok('buildAuthorizeUrl returns url and codeVerifier for code flow', async () => {
    const { url, codeVerifier } = await buildAuthorizeUrl({
      baseUrl: 'http://localhost:9092',
      clientId: 'my-client',
      redirectUri: 'http://localhost:3000/callback',
    });
    assert.ok(url.startsWith('http://localhost:9092/authorize?'));
    const u = new URL(url);
    assert.strictEqual(u.searchParams.get('response_type'), 'code');
    assert.strictEqual(u.searchParams.get('client_id'), 'my-client');
    assert.strictEqual(u.searchParams.get('redirect_uri'), 'http://localhost:3000/callback');
    assert.ok(u.searchParams.get('scope'));
    assert.ok(u.searchParams.get('state'));
    assert.ok(u.searchParams.get('code_challenge'));
    assert.strictEqual(u.searchParams.get('code_challenge_method'), 'S256');
    assert.strictEqual(typeof codeVerifier, 'string');
    assert(codeVerifier.length >= 43);
  });

  await ok('buildAuthorizeUrl includes audience when provided', async () => {
    const { url } = await buildAuthorizeUrl({
      baseUrl: 'http://auth:9092',
      clientId: 'c',
      redirectUri: 'http://app/cb',
      audience: 'https://api.example.com',
    });
    const u = new URL(url);
    assert.strictEqual(u.searchParams.get('audience'), 'https://api.example.com');
  });

  await ok('buildAuthorizeUrl uses default client_id when omitted', async () => {
    const { url } = await buildAuthorizeUrl({
      baseUrl: 'http://localhost:9092',
      redirectUri: 'http://app/cb',
    });
    const u = new URL(url);
    assert.strictEqual(u.searchParams.get('client_id'), 'e2e-test');
  });

  await ok('buildAuthorizeUrl strips trailing slash from baseUrl', async () => {
    const { url } = await buildAuthorizeUrl({
      baseUrl: 'http://localhost:9092/',
      clientId: 'c',
      redirectUri: 'http://app/cb',
    });
    assert.ok(url.startsWith('http://localhost:9092/authorize?'));
  });

  await ok('LOGIN_SELECTORS has expected keys', () => {
    assert.strictEqual(typeof LOGIN_SELECTORS.email, 'string');
    assert.strictEqual(typeof LOGIN_SELECTORS.password, 'string');
    assert.strictEqual(typeof LOGIN_SELECTORS.submit, 'string');
    assert.strictEqual(typeof LOGIN_SELECTORS.form, 'string');
    assert.ok(LOGIN_SELECTORS.email.includes('username'));
    assert.ok(LOGIN_SELECTORS.password.includes('password'));
  });

  return { pass, fail };
}

runTests().then(({ pass, fail }) => {
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
});
