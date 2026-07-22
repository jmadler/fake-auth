# auth2-e2e-helpers

E2E test helpers for [auth2](https://github.com/jmadler/auth2) (Auth0-compatible) login flows. Works with **Cypress** and **Playwright**.

## Installation

```bash
npm install auth2-e2e-helpers
# or
yarn add auth2-e2e-helpers
```

From the auth2 repo (monorepo / local):

```bash
cd e2e-helpers
npm link
# In your app: npm link auth2-e2e-helpers
```

## Playwright

### `auth2Login(page, options)`

Navigate to auth2 login, fill email/password, submit. Use when testing login UI or when the redirect destination is handled elsewhere.

```js
const { auth2Login } = require('auth2-e2e-helpers').playwright;

await auth2Login(page, {
  email: 'user@example.com',
  password: 'secret',
  baseUrl: 'http://localhost:9092',
  clientId: 'my-client-id',
  redirectUri: 'http://localhost:3000/callback',
});
```

### `auth2LoginWithRedirect(page, options)`

Full OAuth flow: visit authorize URL, fill login, submit, wait for redirect to callback with `?code=...`.

```js
const { auth2LoginWithRedirect } = require('auth2-e2e-helpers').playwright;

const { url, code, codeVerifier } = await auth2LoginWithRedirect(page, {
  baseUrl: 'http://localhost:9092',
  clientId: 'my-client-id',
  redirectUri: 'http://localhost:3000/callback',
  email: 'user@example.com',
  password: 'secret',
});

// url = final callback URL
// code = authorization code (exchange for tokens if needed)
// codeVerifier = PKCE verifier for token exchange
```

### `login(page, email, password, options?)`

Shorthand for `auth2Login` with flat arguments:

```js
const { login } = require('auth2-e2e-helpers').playwright;
await login(page, 'user@example.com', 'secret', { baseUrl: 'http://localhost:9092' });
```

---

## Cypress

### Setup

Register commands once in `cypress/support/e2e.js` or `cypress/support/commands.js`:

```js
const { cypress } = require('auth2-e2e-helpers');
cypress.registerCommands();
```

### `cy.auth2Login(options)`

```js
cy.auth2Login({
  email: 'user@example.com',
  password: 'secret',
  baseUrl: 'http://localhost:9092',
  clientId: 'my-client-id',
  redirectUri: 'http://localhost:3000/callback',
});
```

### `cy.auth2LoginWithRedirect(options)`

```js
cy.auth2LoginWithRedirect({
  baseUrl: 'http://localhost:9092',
  clientId: 'my-client-id',
  redirectUri: 'http://localhost:3000/callback',
  email: 'user@example.com',
  password: 'secret',
});
```

---

## Options

| Option          | Type   | Default                 | Description                    |
|-----------------|--------|-------------------------|--------------------------------|
| `email`         | string | required                | User email                    |
| `password`      | string | required                | User password                 |
| `baseUrl`       | string | `http://localhost:9092` | auth2 issuer URL              |
| `clientId`      | string | `e2e-test`              | OAuth client ID               |
| `redirectUri`   | string | baseUrl + /callback     | Callback URL (required for OAuth) |
| `scope`         | string | `openid profile email`  | OAuth scope                   |
| `emailSelector` | string | `input[name="username"]`| Override email input selector |
| `passwordSelector` | string | `input[name="password"]` | Override password selector |
| `submitSelector` | string | `button[type="submit"]` | Override submit button        |
| `timeout`       | number | 10000                   | Redirect wait timeout (Playwright / auth2LoginWithRedirect) |

---

## Creating test users

Use the [GraphQL test API](#graphql-test-api) (when `GRAPHQL_TEST_API_ENABLED=true`) to create users programmatically before E2E runs:

```bash
curl -X POST http://localhost:9092/graphql \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { createUser(email: \"test@example.com\", password: \"Pass123!\", name: \"Test User\") { id email } }"}'
```

See [docs/quickstarts/E2E.md](../docs/quickstarts/E2E.md) for full examples.
