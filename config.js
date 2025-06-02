// config.js
// NEVER commit your client secret to version control! Use environment variables in production.
module.exports = {
    OKTA_ORG_URL: process.env.OKTA_ORG_URL || 'https://your-okta-domain.okta.com',
    OKTA_CLIENT_ID: process.env.OKTA_CLIENT_ID || 'your-okta-client-id',
    OKTA_CLIENT_SECRET: process.env.OKTA_CLIENT_SECRET || 'your-okta-client-secret',
    APP_BASE_URL: process.env.APP_BASE_URL || 'http://localhost:3000',
    SESSION_SECRET: process.env.SESSION_SECRET || 'super-secret-session-key-change-this', // IMPORTANT: Use a long, random string in production
};