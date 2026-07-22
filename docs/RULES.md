# auth2 Rules & Forms

## Custom Login Form

Set `LOGIN_PAGE_TEMPLATE` to a path to a custom HTML file. The file is executed as a Go template with these variables:

| Variable | Description |
|----------|-------------|
| `.ClientID` | OAuth client_id |
| `.RedirectURI` | Callback URL |
| `.Scope` | Requested scope |
| `.State` | State parameter |
| `.ResponseType` | code, token, or id_token |
| `.Nonce` | Nonce for ID token |
| `.Audience` | API audience |
| `.CodeChallenge` | PKCE code challenge |
| `.CodeChallengeMethod` | S256 or plain |
| `.LoginHint` | Pre-filled email |

Your template must POST to `/login` with `name="username"` and `name="password"` inputs, plus hidden inputs for all OAuth params (client_id, redirect_uri, etc.).

---

## Rules (JavaScript)

Rules are JavaScript files that run during the authentication flow. They allow you to customize the user object (claims, metadata) before tokens are issued. Auth0 Rules are largely compatible; place `.js` files in a directory and point auth2 to it via `RULES_DIR`.

---

## Configuration

### Environment

| Variable   | Description                                        | Example              |
|------------|----------------------------------------------------|----------------------|
| `RULES_DIR`| Directory containing Rule `.js` files              | `/etc/auth2/rules`   |

If `RULES_DIR` is unset or empty, no Rules are executed.

---

## How Rules Work

1. Rules run **after** the user authenticates and **before** tokens are issued
2. Each `.js` file in `RULES_DIR` is executed in alphabetical order
3. Rules receive `user`, `context`, and a `callback` function
4. Rules can modify `user` and pass it to `callback` to change the final token claims

---

## Context Object

Each Rule receives a `context` object with:

| Field         | Description                          |
|---------------|--------------------------------------|
| `clientID`    | OAuth client_id                      |
| `clientName`  | Client name (if available)           |
| `connection`  | Connection used (e.g. `Username-Password-Authentication`, `google`) |
| `protocol`   | Protocol (e.g. `oidc`)               |
| `redirect_uri`| Redirect URI from the authorization  |

---

## User Object

The `user` object contains:

| Field             | Description                    |
|-------------------|--------------------------------|
| `user_id`         | Unique user ID                 |
| `email`           | Email address                  |
| `email_verified`  | Boolean                        |
| `name`            | Display name                   |
| `nickname`        | Nickname                       |
| `user_metadata`   | Custom user data               |
| `app_metadata`    | Server-side app data           |
| `id_token_claims` | Claims added to the ID token   |
| `access_token_claims` | Claims added to the access token |

---

## Rule Format

### Function style (Auth0-compatible)

```javascript
function (user, context, callback) {
  // Modify user
  user.nickname = "CustomNick";
  user.app_metadata = user.app_metadata || {};
  user.app_metadata.lastLogin = new Date().toISOString();

  // Add custom claim to ID token
  user.id_token_claims = user.id_token_claims || {};
  user.id_token_claims['https://myapp.com/role'] = 'admin';

  callback(null, user, context);
}
```

### Script style

```javascript
user.nickname = "Modified";
callback(null, user, context);
```

The Rule must call `callback(null, modifiedUser, context)` with the modified user. If you pass a different user object as the second argument, that becomes the new user for subsequent Rules and token issuance.

---

## Example Rules

### Add role to access token

`rules/add-role.js`:

```javascript
function (user, context, callback) {
  user.app_metadata = user.app_metadata || {};
  var role = user.app_metadata.role || 'user';
  user.access_token_claims = user.access_token_claims || {};
  user.access_token_claims.role = role;
  callback(null, user, context);
}
```

### Add custom claim to ID token

`rules/add-tenant.js`:

```javascript
function (user, context, callback) {
  user.id_token_claims = user.id_token_claims || {};
  user.id_token_claims.tenant_id = user.app_metadata?.tenant_id || 'default';
  callback(null, user, context);
}
```

### Track last login

`rules/last-login.js`:

```javascript
function (user, context, callback) {
  user.app_metadata = user.app_metadata || {};
  user.app_metadata.last_login = new Date().toISOString();
  callback(null, user, context);
}
```

Note: Persisting `app_metadata` changes requires a separate API call to update the user. Rules can modify the in-memory user for the current request; they do not automatically persist to the database.

### Conditional logic by connection

`rules/google-nickname.js`:

```javascript
function (user, context, callback) {
  if (context.connection === 'google') {
    user.nickname = user.email ? user.email.split('@')[0] : user.nickname;
  }
  callback(null, user, context);
}
```

---

## Execution Order

Rules in `RULES_DIR` are executed in **lexicographic order** by filename. Use prefixes to control order:

- `01-add-role.js`
- `02-add-tenant.js`
- `03-last-login.js`

---

## Error Handling

If a Rule throws or calls `callback(err)`, the authentication flow fails and no tokens are issued. Handle errors explicitly:

```javascript
function (user, context, callback) {
  try {
    user.id_token_claims = user.id_token_claims || {};
    user.id_token_claims.custom = computeSomething(user);
    callback(null, user, context);
  } catch (e) {
    callback(e);
  }
}
```

---

## Security

- Rules run in a JavaScript VM (goja) with no filesystem or network access
- Do not pass secrets in Rules; use `app_metadata` or external lookups via a backend service
- Sensitive data in `user` is redacted before audit logging
