import type { Page } from 'playwright';

export interface Auth2LoginOptions {
  email: string;
  password: string;
  baseUrl?: string;
  clientId?: string;
  redirectUri?: string;
  scope?: string;
  emailSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
}

export interface Auth2LoginWithRedirectOptions extends Auth2LoginOptions {
  baseUrl: string;
  clientId: string;
  redirectUri: string;
  timeout?: number;
}

export interface Auth2LoginWithRedirectResult {
  url: string;
  code?: string;
  codeVerifier?: string;
}

export declare const playwright: {
  auth2Login(page: Page, options: Auth2LoginOptions): Promise<void>;
  auth2LoginWithRedirect(page: Page, options: Auth2LoginWithRedirectOptions): Promise<Auth2LoginWithRedirectResult>;
  login(page: Page, email: string, password: string, options?: Partial<Auth2LoginOptions>): Promise<void>;
};

export declare const cypress: {
  registerCommands(): void;
  auth2Login(options: Auth2LoginOptions): Cypress.Chainable;
  auth2LoginWithRedirect(options: Auth2LoginWithRedirectOptions): Cypress.Chainable;
  LOGIN_SELECTORS: typeof import('./utils').LOGIN_SELECTORS;
};

export declare const utils: {
  randomState(): string;
  generateCodeVerifier(): string;
  generateCodeChallenge(verifier: string): Promise<string>;
  buildAuthorizeUrl(opts: Record<string, unknown>): Promise<{ url: string; codeVerifier?: string }>;
  LOGIN_SELECTORS: Record<string, string>;
};

export declare function auth2Login(page: Page, options: Auth2LoginOptions): Promise<void>;
export declare function auth2LoginWithRedirect(page: Page, options: Auth2LoginWithRedirectOptions): Promise<Auth2LoginWithRedirectResult>;
export declare function login(page: Page, email: string, password: string, options?: Partial<Auth2LoginOptions>): Promise<void>;
