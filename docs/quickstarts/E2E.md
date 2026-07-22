# E2E Testing with auth2

Run end-to-end tests against auth2 using **Cypress** or **Playwright** with the `auth2-e2e-helpers` package and optional **GraphQL test API** for programmatic user creation.

## Prerequisites

- auth2 running (e.g. `http://localhost:9092`)
- A client registered in `CLIENT_REGISTRY` with `redirect_uris` including your app's callback URL
- For user creation: `GRAPHQL_TEST_API_ENABLED=true` and `ADMIN_API_KEY` set

---

## 1. Install auth2-e2e-helpers

```bash
npm install auth2-e2e-helpers
# or
yarn add auth2-e2e-helpers
```

From the auth2 repo (local development):

```bash
cd e2e-helpers && npm link
cd /path/to/your-app && npm link auth2-e2e-helpers
```

---

## 2. Create Test Users (GraphQL Test API)

Enable the GraphQL test API and create users before E2E runs:

### Enable the API

```bash
export GRAPHQL_TEST_API_ENABLED=true
export ADMIN_API_KEY=your-admin-key
```

Start auth2 with these variables. The API is available at `POST /graphql`.

### Create a user via curl

```bash
curl -X POST http://localhost:9092/graphql \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { createUser(email: \"e2e@example.com\", password: \"Pass123!\", name: \"E2E User\") { id email } }"
  }'
```

Response:

```json
{
  "data": {
    "createUser": {
      "id": "auth0|uuid",
      "email": "e2e@example.com"
    }
  }
}
```

### Create a user in your test setup (Node.js)

```js
async function createTestUser(email, password, name) {
  const res = await fetch('http://localhost:9092/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.ADMIN_API_KEY}`,
    },
    body: JSON.stringify({
      query: `mutation CreateUser($email: String!, $password: String!, $name: String) {
        createUser(email: $email, password: $password, name: $name) { id email }
      }`,
      variables: { email, password, name },
    }),
  });
  const json = await res.json();
  if (json.errors) throw new Error(json.errors[0].message);
  return json.data.createUser;
}

// In before/beforeAll:
const user = await createTestUser('e2e@example.com', 'Pass123!', 'E2E User');
```

---

## 3. Playwright Examples

### Basic login

```js
const { test, expect } = require('@playwright/test');
const { auth2Login } = require('auth2-e2e-helpers').playwright;

test('user can log in', async ({ page }) => {
  await auth2Login(page, {
    email: 'e2e@example.com',
    password: 'Pass123!',
    baseUrl: 'http://localhost:9092',
    clientId: 'my-client-id',
    redirectUri: 'http://localhost:3000/callback',
  });

  await expect(page).toHaveURL(/localhost:3000\/callback/);
  await expect(page).toHaveURL(/code=/);
});
```

### Full OAuth flow with redirect

```js
const { auth2LoginWithRedirect } = require('auth2-e2e-helpers').playwright;

test('complete OAuth flow', async ({ page }) => {
  const { url, code, codeVerifier } = await auth2LoginWithRedirect(page, {
    baseUrl: 'http://localhost:9092',
    clientId: 'my-client-id',
    redirectUri: 'http://localhost:3000/callback',
    email: 'e2e@example.com',
    password: 'Pass123!',
  });

  expect(code).toBeTruthy();
  // Exchange code for tokens if needed, or assert app handled it
});
```

### Global setup: create user before tests

```js
// playwright.config.js
module.exports = {
  globalSetup: './global-setup.js',
  // ...
};

// global-setup.js
const { createTestUser } = require('./test-utils');
module.exports = async () => {
  await createTestUser('e2e@example.com', 'Pass123!', 'E2E User');
};
```

---

## 4. Cypress Examples

### Setup

Register auth2 commands in `cypress/support/e2e.js`:

```js
const { cypress } = require('auth2-e2e-helpers');
cypress.registerCommands();
```

### Basic login test

```js
describe('auth2 login', () => {
  it('logs in successfully', () => {
    cy.auth2Login({
      email: 'e2e@example.com',
      password: 'Pass123!',
      baseUrl: 'http://localhost:9092',
      clientId: 'my-client-id',
      redirectUri: 'http://localhost:3000/callback',
    });

    cy.url().should('include', 'localhost:3000/callback');
    cy.url().should('include', 'code=');
  });
});
```

### Full redirect flow

```js
it('completes OAuth redirect flow', () => {
  cy.auth2LoginWithRedirect({
    baseUrl: 'http://localhost:9092',
    clientId: 'my-client-id',
    redirectUri: 'http://localhost:3000/callback',
    email: 'e2e@example.com',
    password: 'Pass123!',
  });

  cy.url().should('include', 'code=');
});
```

### Create user in beforeEach

```js
before(() => {
  cy.request({
    method: 'POST',
    url: 'http://localhost:9092/graphql',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${Cypress.env('ADMIN_API_KEY')}`,
    },
    body: {
      query: `mutation { createUser(email: "e2e@example.com", password: "Pass123!", name: "E2E User") { id } }`,
    },
  });
});
```

---

## 5. Configuration Summary

| Variable | Description |
|----------|-------------|
| `GRAPHQL_TEST_API_ENABLED` | Set to `true` to enable `POST /graphql` |
| `ADMIN_API_KEY` | Required for GraphQL API and user creation |
| `ISSUER_URL` | auth2 base URL (e.g. `http://localhost:9092`) |
| `redirect_uri` | Must be in client's `redirect_uris` |
| `clientId` | From `CLIENT_REGISTRY` |

---

## 6. Docker Compose for E2E

Run auth2 with GraphQL API enabled for tests:

```yaml
# docker-compose.e2e.yml
services:
  auth2:
    build: .
    ports:
      - "9092:9092"
    environment:
      PORT: "9092"
      DB_DRIVER: sqlite
      DB_PATH: /data/auth0.db
      ISSUER_URL: http://localhost:9092
      GRAPHQL_TEST_API_ENABLED: "true"
      ADMIN_API_KEY: e2e-admin-key
      CLIENT_REGISTRY: '{"e2e-client":{"client_secret":"secret","redirect_uris":["http://localhost:3000/callback"],"allowed_scopes":["openid","profile","email"]}}'
```

---

## Summary

1. **auth2-e2e-helpers** — `auth2Login`, `auth2LoginWithRedirect` for Playwright; `cy.auth2Login`, `cy.auth2LoginWithRedirect` for Cypress.
2. **GraphQL test API** — `mutation { createUser(email, password, name?) { id email } }` with `Authorization: Bearer ADMIN_API_KEY`.
3. Create users before tests, then use helpers to log in and assert on redirects.
