/**
 * auth2 E2E Helpers
 * @module auth2-e2e-helpers
 *
 * Provides login helpers for Cypress and Playwright to test auth2 (Auth0-compatible) flows.
 *
 * ## Playwright
 *   const { auth2Login, auth2LoginWithRedirect } = require('auth2-e2e-helpers').playwright;
 *   await auth2Login(page, { email, password, baseUrl, clientId, redirectUri });
 *
 * ## Cypress
 *   // In cypress/support/commands.js: require('auth2-e2e-helpers').cypress.registerCommands();
 *   // In test: cy.auth2Login({ email, password, baseUrl, clientId, redirectUri });
 */

const playwright = require('./playwright');
const cypress = require('./cypress');
const utils = require('./utils');

module.exports = {
  playwright,
  cypress,
  utils,
  // Convenience exports
  auth2Login: playwright.auth2Login,
  auth2LoginWithRedirect: playwright.auth2LoginWithRedirect,
  login: playwright.login,
};
