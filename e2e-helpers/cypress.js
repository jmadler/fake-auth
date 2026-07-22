/**
 * auth2 E2E helpers for Cypress
 * @module auth2-e2e-helpers/cypress
 */

const {
  buildAuthorizeUrl,
  LOGIN_SELECTORS,
} = require('./utils');

/**
 * Register auth2 Cypress commands.
 * Call this once in cypress/support/e2e.js or cypress/support/commands.js:
 *
 *   const auth2Helpers = require('auth2-e2e-helpers/cypress');
 *   auth2Helpers.registerCommands();
 *
 * Then use: cy.auth2Login({ email, password, baseUrl, ... })
 */
function registerCommands() {
  if (typeof Cypress === 'undefined') {
    throw new Error('auth2-e2e-helpers/cypress must be loaded in Cypress context. Use in cypress/support/commands.js or e2e.js.');
  }

  Cypress.Commands.add('auth2Login', (options = {}) => {
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

    cy.visit(loginUrl);
    cy.get(emailSelector).clear().type(email);
    cy.get(passwordSelector).clear().type(password);
    cy.get(submitSelector).click();
    cy.url().should('satisfy', (url) => url.startsWith(redirectUri) || url.includes('code='));
  });

  Cypress.Commands.add('auth2LoginWithRedirect', async (options = {}) => {
    const {
      baseUrl = 'http://localhost:9092',
      clientId = 'e2e-test',
      redirectUri,
      email,
      password,
      scope = 'openid profile email',
      emailSelector = LOGIN_SELECTORS.email,
      passwordSelector = LOGIN_SELECTORS.password,
      submitSelector = LOGIN_SELECTORS.submit,
      timeout = 10000,
    } = options;

    if (!baseUrl || !clientId || !redirectUri || !email || !password) {
      throw new Error('auth2LoginWithRedirect: baseUrl, clientId, redirectUri, email, and password are required');
    }

    const { url: authorizeUrl } = await buildAuthorizeUrl({
      baseUrl,
      clientId,
      redirectUri,
      scope,
      responseType: 'code',
    });

    cy.visit(authorizeUrl);
    cy.get(emailSelector).clear().type(email);
    cy.get(passwordSelector).clear().type(password);
    cy.get(submitSelector).click();
    cy.url({ timeout }).should('satisfy', (url) => url.startsWith(redirectUri));
  });
}

/**
 * Standalone helper that wraps cy.visit, cy.get, etc.
 * Use when you prefer not to register custom commands.
 *
 * @param {object} options - Same as auth2Login
 * @returns {Cypress.Chainable}
 */
function auth2Login(options) {
  return Cypress.cy.auth2Login(options);
}

/**
 * Standalone helper for redirect flow.
 * @param {object} options - Same as auth2LoginWithRedirect
 * @returns {Cypress.Chainable}
 */
function auth2LoginWithRedirect(options) {
  return Cypress.cy.auth2LoginWithRedirect(options);
}

module.exports = {
  registerCommands,
  auth2Login,
  auth2LoginWithRedirect,
  LOGIN_SELECTORS,
};
