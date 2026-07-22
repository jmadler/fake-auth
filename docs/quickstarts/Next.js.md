# Next.js Quickstart with auth2

Integrate auth2 (Auth0-compatible) into Next.js using NextAuth.js or a custom OAuth flow.

## Prerequisites

- auth2 running (e.g. `http://localhost:9092`)
- A client registered in `CLIENT_REGISTRY`

## Configuration

| Variable | Example |
|----------|---------|
| `ISSUER_URL` | `http://localhost:9092` |
| `client_id` | From CLIENT_REGISTRY |
| `redirect_uri` | `http://localhost:3000/api/auth/callback/auth2` (NextAuth) |

---

## Option 1: NextAuth.js

NextAuth supports custom OIDC providers. Configure auth2 as a custom OpenID Connect provider.

### Install

```bash
npm install next-auth
```

### Configure provider

Create or edit `app/api/auth/[...nextauth]/route.ts` (App Router) or `pages/api/auth/[...nextauth].ts` (Pages Router):

```ts
// app/api/auth/[...nextauth]/route.ts
import NextAuth from 'next-auth';

const ISSUER_URL = process.env.AUTH2_ISSUER_URL || 'http://localhost:9092';
const clientId = process.env.AUTH2_CLIENT_ID!;
const clientSecret = process.env.AUTH2_CLIENT_SECRET!;

export const authOptions = {
  providers: [
    {
      id: 'auth2',
      name: 'auth2',
      type: 'oauth',
      wellKnown: `${ISSUER_URL}/.well-known/openid-configuration`,
      clientId,
      clientSecret,
      authorization: {
        params: { scope: 'openid profile email' },
      },
    },
  ],
  callbacks: {
    async jwt({ token, account }) {
      if (account) {
        token.accessToken = account.access_token;
      }
      return token;
    },
    async session({ session, token }) {
      (session as any).accessToken = token.accessToken;
      return session;
    },
  },
  pages: {
    signIn: '/auth/signin',
  },
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
```

### Environment variables

```env
AUTH2_ISSUER_URL=http://localhost:9092
AUTH2_CLIENT_ID=your-client-id
AUTH2_CLIENT_SECRET=your-client-secret
NEXTAUTH_URL=http://localhost:3000
```

### CLIENT_REGISTRY

Ensure auth2 has this client:

```json
{
  "your-client-id": {
    "client_secret": "your-client-secret",
    "redirect_uris": ["http://localhost:3000/api/auth/callback/auth2"],
    "allowed_scopes": ["openid", "profile", "email"]
  }
}
```

### Usage

```tsx
import { signIn, signOut, useSession } from 'next-auth/react';

export default function Home() {
  const { data: session, status } = useSession();

  if (status === 'loading') return <p>Loading...</p>;
  if (session) {
    return (
      <>
        <p>Signed in as {session.user?.email}</p>
        <button onClick={() => signOut()}>Sign out</button>
      </>
    );
  }
  return <button onClick={() => signIn('auth2')}>Sign in with auth2</button>;
}
```

### SessionProvider

Wrap your app in `SessionProvider`:

```tsx
// app/layout.tsx
import { SessionProvider } from 'next-auth/react';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <SessionProvider>{children}</SessionProvider>
      </body>
    </html>
  );
}
```

---

## Option 2: Custom OAuth with auth2

For more control, implement the authorize + token exchange flow server-side.

### Authorize URL

```
GET {ISSUER_URL}/authorize?
  response_type=code
  &client_id={client_id}
  &redirect_uri={redirect_uri}
  &scope=openid profile email
  &state={state}
```

### API route: login

```ts
// app/api/auth/login/route.ts
import { redirect } from 'next/navigation';

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const returnTo = searchParams.get('returnTo') || '/';
  const state = crypto.randomUUID();

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.AUTH2_CLIENT_ID!,
    redirect_uri: `${process.env.NEXTAUTH_URL}/api/auth/callback`,
    scope: 'openid profile email',
    state,
  });

  // Store state in cookie or session for validation
  const issuer = process.env.AUTH2_ISSUER_URL!;
  redirect(`${issuer}/authorize?${params}`);
}
```

### API route: callback + token exchange

```ts
// app/api/auth/callback/route.ts
import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const code = searchParams.get('code');
  const state = searchParams.get('state');

  if (!code) {
    return NextResponse.redirect(new URL('/?error=no_code', req.url));
  }

  const res = await fetch(`${process.env.AUTH2_ISSUER_URL}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${process.env.NEXTAUTH_URL}/api/auth/callback`,
      client_id: process.env.AUTH2_CLIENT_ID!,
      client_secret: process.env.AUTH2_CLIENT_SECRET!,
    }),
  });

  const tokens = await res.json();
  if (!res.ok) {
    return NextResponse.redirect(new URL(`/?error=${tokens.error}`, req.url));
  }

  // Create session (e.g. JWT in cookie, or use NextAuth's DB adapter)
  const response = NextResponse.redirect(new URL('/', req.url));
  response.cookies.set('auth2_access_token', tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  });
  return response;
}
```

---

## Summary

| auth2 endpoint | Purpose |
|----------------|---------|
| `{ISSUER_URL}/.well-known/openid-configuration` | OIDC discovery for NextAuth |
| `{ISSUER_URL}/authorize` | Start authorization |
| `{ISSUER_URL}/oauth/token` | Exchange code for tokens |

With NextAuth + `wellKnown`, auth2's discovery document drives the entire OAuth/OIDC flow automatically.
