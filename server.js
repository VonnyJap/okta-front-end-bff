// server.js
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');
const path = require('path');
const config = require('./config');

const app = express();
const port = process.env.PORT || 3000;

// Session middleware setup
app.use(session({
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
        httpOnly: true, // Prevent client-side JavaScript access to the cookie
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

let client; // OpenID Connect client instance

// Initialize Okta OIDC client
async function initializeOktaClient() {
    try {
        const issuer = await Issuer.discover(config.OKTA_ORG_URL + '/oauth2/default'); // Use 'default' auth server
        console.log('Discovered Okta issuer %s %O', issuer.issuer, issuer.metadata);

        client = new issuer.Client({
            client_id: config.OKTA_CLIENT_ID,
            client_secret: config.OKTA_CLIENT_SECRET,
            redirect_uris: [`${config.APP_BASE_URL}/authorization-code/callback`],
            response_types: ['code'], // Authorization Code Flow
            token_endpoint_auth_method: 'client_secret_post' // Recommended for web apps
        });
        console.log('Okta OIDC client initialized.');
    } catch (error) {
        console.error('Failed to initialize Okta OIDC client:', error);
        process.exit(1); // Exit if client cannot be initialized
    }
}

// Start the initialization
initializeOktaClient();

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// --- Authentication Routes ---

// Login route: Redirects to Okta for authentication
app.get('/login', (req, res) => {
    if (!client) {
        return res.status(500).send('Okta client not initialized. Please try again in a moment.');
    }

    // Generate PKCE code_verifier and code_challenge
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);

    // Generate state and nonce
    const state = generators.state();
    const nonce = generators.nonce();

    // Store them in the session for later validation
    req.session.code_verifier = code_verifier;
    req.session.oauth_state = state; // Explicitly store state
    req.session.oauth_nonce = nonce; // Explicitly store nonce

    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        redirect_uri: `${config.APP_BASE_URL}/authorization-code/callback`,
        code_challenge,
        code_challenge_method: 'S256',
        state, // <-- Pass the generated state
        nonce, // <-- Pass the generated nonce
    });

    console.log('Initiating login with state:', state, 'and nonce:', nonce);
    res.redirect(authorizationUrl);
});

// Callback route: Handles the redirect from Okta after authentication
app.get('/authorization-code/callback', async (req, res) => {
    if (!client) {
        return res.status(500).send('Okta client not initialized.');
    }
    console.log('Callback received with params:', req.query);
    const params = client.callbackParams(req);
    const code_verifier = req.session.code_verifier; // Retrieve from session

    console.log('Callback params:', params);
    console.log('Using code_verifier:', code_verifier);
    const state = req.session.oauth_state;
    const nonce = req.session.oauth_nonce;

    try {
        const tokenSet = await client.callback(
            `${config.APP_BASE_URL}/authorization-code/callback`,
            params,
            {
                code_verifier,
                state,
                nonce
            }
        );
        console.log('Received and validated tokens %j', tokenSet);
        console.log('Received ID Token claims %j', tokenSet.claims());

        // Store tokens and user info in session
        req.session.isAuthenticated = true;
        req.session.accessToken = tokenSet.access_token;
        req.session.idToken = tokenSet.id_token;
        req.session.user = tokenSet.claims(); // ID Token claims contain user info

        // Optional: Get full user profile from Okta UserInfo endpoint (requires 'profile' scope)
        const userinfo = await client.userinfo(tokenSet.access_token);
        req.session.userInfo = userinfo; // Store detailed user info

        delete req.session.code_verifier; // Clean up verifier
        delete req.session.oauth_state; // Clean up state
        delete req.session.oauth_nonce; // Clean up nonce

        res.redirect('/'); // Redirect back to the home page or dashboard
    } catch (error) {
        console.error('Authentication failed:', error);
        res.status(500).send(`Authentication failed: ${error.message}`);
    }
});

// Logout route: Clears session and redirects to Okta for session termination
app.get('/logout', async (req, res) => {
    if (!client) {
        return res.status(500).send('Okta client not initialized.');
    }
    const idToken = req.session.idToken;

    // Clear session first
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Failed to log out.');
        }

        // Redirect to Okta's end session endpoint to clear Okta session
        const endSessionUrl = client.endSessionUrl({
            id_token_hint: idToken, // Hint to Okta which session to terminate
            post_logout_redirect_uri: `${config.APP_BASE_URL}/logout/callback`,
        });
        res.redirect(endSessionUrl);
    });
});

// Logout Callback (from Okta after session termination)
app.get('/logout/callback', (req, res) => {
    // Okta redirects here after its session is cleared.
    // Our session should already be destroyed.
    res.redirect('/'); // Redirect to the home page
});

// User info endpoint: To check login status and get user details from client
app.get('/userinfo', (req, res) => {
    if (req.session.isAuthenticated) {
        res.json({
            isAuthenticated: true,
            user: req.session.user,      // Basic claims from ID Token
            userInfo: req.session.userInfo // Detailed info from UserInfo endpoint
        });
    } else {
        res.json({ isAuthenticated: false });
    }
});

// Simple protected route (example)
app.get('/protected', (req, res) => {
    if (req.session.isAuthenticated) {
        res.send(`<h1>Welcome, ${req.session.user.name || req.session.user.preferred_username}!</h1><p>This is a protected page.</p><a href="/logout">Logout</a>`);
    } else {
        res.redirect('/login');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Front-end server listening at ${config.APP_BASE_URL}`);
});