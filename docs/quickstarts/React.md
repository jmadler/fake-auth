# React Quickstart with auth2

Integrate auth2 (Auth0-compatible) into your React app using `@auth0/auth0-react` or vanilla fetch.

## Prerequisites

- auth2 running (e.g. `http://localhost:9092`)
- A client registered in `CLIENT_REGISTRY` with `redirect_uris` and `allowed_scopes`

## Configuration

| Variable | Example | Description |
|----------|---------|-------------|
| `ISSUER_URL` | `http://localhost:9092` | auth2 base URL |
| `client_id` | From CLIENT_REGISTRY | Your app's client ID |
| `redirect_uri` | `http://localhost:3000/callback` | Where auth2 redirects after login |

---

## Option 1: @auth0/auth0-react (recommended)

Install:

```bash
npm install @auth0/auth0-react
```

Wrap your app with `Auth0Provider`. Use your auth2 issuer as the Auth0 domain:

```tsx
// src/main.tsx or App.tsx
import { Auth0Provider } from '@auth0/auth0-react';

// auth2 issuer = Auth0 "domain" (without https://)
const issuer = 'http://localhost:9092';  // or https://auth2.example.com
const clientId = 'your-client-id';
const redirectUri = window.location.origin + '/callback';

<Auth0Provider
  domain={new URL(issuer).host}
  clientId={clientId}
  authorizationParams={{
    redirect_uri: redirectUri,
    audience: 'https://api.example.com',
    scope: 'openid profile email',
  }}
>
  <App />
</Auth0Provider>
```

**Note:** `@auth0/auth0-react` expects an Auth0-style domain. For auth2, pass the **host** of `ISSUER_URL` (e.g. `localhost:9092`). Some setups may require a custom `authorizationServer` URL. Check your SDK docs.

Alternatively, use the issuer URL directly if your SDK supports OIDC discovery:

```tsx
<Auth0Provider
  domain={new URL(issuer).host}
  clientId={clientId}
  authorizationParams={{
    redirect_uri: redirectUri,
  }}
  cacheLocation="localstorage"
>
  <App />
</Auth0Provider>
```

### Login / Logout

```tsx
import { useAuth0 } from '@auth0/auth0-react';

function LoginButton() {
  const { loginWithRedirect, logout, isAuthenticated, user } = useAuth0();

  if (isAuthenticated) {
    return (
      <div>
        <p>Hello, {user?.name}</p>
        <button onClick={() => logout({ returnTo: window.location.origin })}>Log out</button>
      </div>
    );
  }

  return <button onClick={() => loginWithRedirect()}>Log in</button>;
}
```

### Get access token

```tsx
const { getAccessTokenSilently } = useAuth0();
const token = await getAccessTokenSilently({ audience: 'https://api.example.com' });
```

---

## Option 2: Vanilla fetch (Authorization Code + PKCE)

If you prefer not to use the Auth0 SDK, implement the OAuth 2.0 / OIDC flow manually.

### Authorize URL

```
GET {ISSUER_URL}/authorize?
  response_type=code
  &client_id={client_id}
  &redirect_uri={redirect_uri}
  &scope=openid profile email
  &state={random_state}
  &code_challenge={S256_challenge}
  &code_challenge_method=S256
```

### Redirect to login

```tsx
function login() {
  const issuer = 'http://localhost:9092';
  const clientId = 'your-client-id';
  const redirectUri = `${window.location.origin}/callback`;
  const state = crypto.randomUUID();
  const codeVerifier = generateCodeVerifier();
  sessionStorage.setItem('code_verifier', codeVerifier);
  sessionStorage.setItem('oauth_state', state);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
    code_challenge: await generateCodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
  });
  window.location.href = `${issuer}/authorize?${params}`;
}
```

### Token exchange (callback page)

```tsx
// /callback - handle ?code=...&state=...
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  const savedState = sessionStorage.getItem('oauth_state');
  const codeVerifier = sessionStorage.getItem('code_verifier');

  if (!code || state !== savedState) throw new Error('Invalid callback');
  sessionStorage.removeItem('oauth_state');
  sessionStorage.removeItem('code_verifier');

  const issuer = 'http://localhost:9092';
  const clientId = 'your-client-id';
  const clientSecret = 'your-client-secret';  // use backend proxy in production
  const redirectUri = `${window.location.origin}/callback`;

  const res = await fetch(`${issuer}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: codeVerifier,
    }),
  });
  const tokens = await res.json();
  // Store tokens, redirect to app
  return tokens; // { access_token, id_token, refresh_token }
}
```

### PKCE helpers

```tsx
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateCodeChallenge(verifier: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

---

## CLIENT_REGISTRY example

```json
{
  "your-client-id": {
    "client_secret": "your-client-secret",
    "redirect_uris": ["http://localhost:3000/callback"],
    "allowed_scopes": ["openid", "profile", "email"]
  }
}
```

---

## Summary

| auth2 endpoint | Purpose |
|----------------|---------|
| `{ISSUER_URL}/authorize` | Start login, get authorization code |
| `{ISSUER_URL}/oauth/token` | Exchange code for tokens |
| `{ISSUER_URL}/login` | Hosted login page (optional) |
| `{ISSUER_URL}/.well-known/openid-configuration` | OIDC discovery |
