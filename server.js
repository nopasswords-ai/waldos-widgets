/**
 * Waldo's Widgets - Demo website integrating ViziPass authentication
 *
 * This demonstrates how a third-party website integrates with ViziPass
 * using the OIDC Authorization Code flow.
 *
 * Flow:
 * 1. User clicks "Login with ViziPass"
 * 2. Redirect to ViziPass /oauth2/authorize
 * 3. ViziPass shows challenge image, user authenticates with phone
 * 4. ViziPass redirects back with authorization code
 * 5. Website exchanges code for tokens
 * 6. Website validates ID token and creates session
 */

const express = require('express');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

const app = express();
const PORT = 3000;

// Serve static files (background image)
app.use(express.static(__dirname));

// ViziPass OIDC Configuration
const VIZIPASS_CONFIG = {
  issuer: 'http://localhost:4000',
  authorization_endpoint: 'http://localhost:4000/oauth2/authorize',
  token_endpoint: 'http://localhost:4000/oauth2/token',
  jwks_uri: 'http://localhost:4000/.well-known/jwks.json',

  // Client credentials (registered with ViziPass)
  client_id: 'test_client',
  client_secret: 'test_secret_123',
  redirect_uri: 'http://localhost:3000/callback'
};

// In-memory session store (use Redis/DB in production)
const sessions = new Map();

// Generate secure random state
function generateState() {
  return crypto.randomBytes(32).toString('base64url');
}

// Generate PKCE code verifier and challenge
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

// Store pending auth requests
const pendingAuth = new Map();

// Homepage - displays challenge image immediately
app.get('/', async (req, res) => {
  const sessionId = req.headers.cookie?.match(/session=([^;]+)/)?.[1];
  const session = sessions.get(sessionId);

  if (session) {
    // Show the same modern page, just without the challenge image
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Waldo's Widgets</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            min-height: 100vh;
            background: url('/background.jpg') no-repeat center center fixed;
            background-size: cover;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            position: relative;
          }
          body::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.4);
            pointer-events: none;
          }
          .container {
            position: relative;
            z-index: 1;
            text-align: center;
          }
          .logo h1 {
            font-size: 3rem;
            font-weight: 300;
            color: #fff;
            letter-spacing: 0.1em;
            text-transform: uppercase;
          }
          .logo h1 span {
            font-weight: 700;
            background: linear-gradient(90deg, #e94560, #f39c12);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
          }
          .logo .tagline {
            color: rgba(255,255,255,0.5);
            font-size: 0.9rem;
            letter-spacing: 0.3em;
            text-transform: uppercase;
            margin-top: 8px;
          }
          .user-info {
            margin-top: 30px;
            color: rgba(255,255,255,0.8);
            font-size: 1rem;
          }
          .logout-link {
            display: inline-block;
            margin-top: 20px;
            color: #e94560;
            text-decoration: none;
            font-size: 0.9rem;
          }
          .logout-link:hover {
            text-decoration: underline;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">
            <h1>Waldo's <span>Widgets</span></h1>
            <div class="tagline">Engineering Excellence</div>
          </div>
          <div class="user-info">
            Signed in as ${session.email}
          </div>
          <a href="/logout" class="logout-link">Sign out</a>
        </div>
      </body>
      </html>
    `);
  } else {
    // Generate OIDC parameters and get challenge
    const state = generateState();
    const { verifier, challenge } = generatePKCE();
    const nonce = generateState();

    // Store for verification when callback returns
    pendingAuth.set(state, { verifier, nonce, created: Date.now() });

    // Clean up old pending auths
    for (const [key, value] of pendingAuth) {
      if (Date.now() - value.created > 600000) {
        pendingAuth.delete(key);
      }
    }

    // Fetch challenge from ViziPass
    let challengeData = null;
    try {
      challengeData = await fetchChallenge(state, nonce, challenge);
    } catch (err) {
      console.error('Failed to fetch challenge:', err.message);
    }

    const imageData = challengeData?.image_data || '';
    const authRequestId = challengeData?.auth_request_id || '';

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Waldo's Widgets</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            min-height: 100vh;
            background: url('/background.jpg') no-repeat center center fixed;
            background-size: cover;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
          }
          /* Dark overlay for better text contrast */
          body::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.4);
            pointer-events: none;
          }
          .container {
            position: relative;
            z-index: 1;
            text-align: center;
          }
          .logo {
            margin-bottom: 40px;
          }
          .logo h1 {
            font-size: 3rem;
            font-weight: 300;
            color: #fff;
            letter-spacing: 0.1em;
            text-transform: uppercase;
          }
          .logo h1 span {
            font-weight: 700;
            background: linear-gradient(90deg, #e94560, #f39c12);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
          }
          .logo .tagline {
            color: rgba(255,255,255,0.5);
            font-size: 0.9rem;
            letter-spacing: 0.3em;
            text-transform: uppercase;
            margin-top: 8px;
          }
          .challenge-wrapper {
            display: inline-block;
            padding: 5px 5px 10px 5px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.4);
            text-align: center;
          }
          .challenge-container {
            position: relative;
            line-height: 0;
          }
          .challenge-img {
            display: block;
            width: 256px;
            height: 256px;
            border-radius: 4px;
          }
          .vizipass-label {
            font-size: 12px;
            font-weight: 600;
            color: #1e3a5f;
            margin-top: 3px;
            line-height: 1;
          }
          .auth-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 256px;
            height: 256px;
            background: rgba(34, 197, 94, 0.95);
            border-radius: 4px;
            color: white;
            text-align: center;
            visibility: hidden;
            opacity: 0;
          }
          .auth-overlay.show {
            visibility: visible;
            opacity: 1;
          }
          .auth-overlay-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 90%;
          }
          .auth-overlay .auth-title {
            display: block;
            font-size: 22px;
            font-weight: 600;
            line-height: 1.2;
          }
          .auth-overlay .auth-email {
            display: block;
            font-size: 13px;
            margin-top: 10px;
            opacity: 0.9;
            word-break: break-all;
            line-height: 1.3;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">
            <h1>Waldo's <span>Widgets</span></h1>
            <div class="tagline">Engineering Excellence</div>
          </div>

          <div class="challenge-wrapper">
            <div class="challenge-container">
              ${imageData
                ? `<img src="data:image/png;base64,${imageData}" class="challenge-img" id="challenge" />`
                : `<div class="challenge-img" style="background: #f3f4f6;"></div>`
              }
              <div class="auth-overlay" id="authOverlay">
                <div class="auth-overlay-content">
                  <span class="auth-title">Authenticated</span>
                  <span class="auth-email" id="authEmail"></span>
                </div>
              </div>
            </div>
            <div class="vizipass-label">ViziPass</div>
          </div>
        </div>

        <script>
          // Poll for auth completion
          const authRequestId = "${authRequestId}";
          const state = "${state}";
          let authComplete = false;

          if (authRequestId) {
            const checkAuth = async () => {
              if (authComplete) return;
              try {
                const res = await fetch('/check-auth?auth_request_id=' + authRequestId + '&state=' + state);
                const data = await res.json();
                if (data.authenticated) {
                  authComplete = true;
                  // Show authenticated overlay with email
                  const overlay = document.getElementById('authOverlay');
                  const emailEl = document.getElementById('authEmail');
                  if (data.email) {
                    emailEl.textContent = data.email;
                  }
                  overlay.classList.add('show');
                  // Keep showing for 4 seconds, then remove the image
                  setTimeout(() => {
                    const wrapper = document.querySelector('.challenge-wrapper');
                    if (wrapper) wrapper.remove();
                  }, 4000);
                }
              } catch (e) {}
            };
            setInterval(checkAuth, 1000);
          }
        </script>
      </body>
      </html>
    `);
  }
});

// Initiate login - redirect to ViziPass
app.get('/login', (req, res) => {
  const state = generateState();
  const { verifier, challenge } = generatePKCE();
  const nonce = generateState();

  // Store for verification when callback returns
  pendingAuth.set(state, { verifier, nonce, created: Date.now() });

  // Clean up old pending auths (older than 10 minutes)
  for (const [key, value] of pendingAuth) {
    if (Date.now() - value.created > 600000) {
      pendingAuth.delete(key);
    }
  }

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: VIZIPASS_CONFIG.client_id,
    redirect_uri: VIZIPASS_CONFIG.redirect_uri,
    scope: 'openid profile email',
    state: state,
    nonce: nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });

  const authUrl = `${VIZIPASS_CONFIG.authorization_endpoint}?${params}`;
  console.log('Redirecting to ViziPass:', authUrl);
  res.redirect(authUrl);
});

// OAuth callback - exchange code for tokens
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(`
      <h1>Authentication Failed</h1>
      <p>Error: ${error}</p>
      <p>${error_description || ''}</p>
      <a href="/">Try again</a>
    `);
  }

  // Verify state
  const pending = pendingAuth.get(state);
  if (!pending) {
    return res.status(400).send(`
      <h1>Invalid State</h1>
      <p>Authentication session expired or invalid.</p>
      <a href="/">Try again</a>
    `);
  }
  pendingAuth.delete(state);

  try {
    // Exchange code for tokens
    const tokenResponse = await exchangeCode(code, pending.verifier);

    if (tokenResponse.error) {
      throw new Error(tokenResponse.error_description || tokenResponse.error);
    }

    // Decode and validate ID token (simplified - use proper JWT validation in production)
    const idToken = tokenResponse.id_token;
    const payload = JSON.parse(
      Buffer.from(idToken.split('.')[1], 'base64url').toString()
    );

    // Verify nonce
    if (payload.nonce !== pending.nonce) {
      throw new Error('Invalid nonce');
    }

    // Create session
    const sessionId = crypto.randomBytes(32).toString('base64url');
    sessions.set(sessionId, {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      amr: payload.amr,
      access_token: tokenResponse.access_token,
      created: Date.now()
    });

    console.log('User authenticated:', payload.email);

    res.setHeader('Set-Cookie', `session=${sessionId}; HttpOnly; Path=/; Max-Age=3600`);
    res.redirect('/');

  } catch (err) {
    console.error('Token exchange failed:', err.message);
    res.status(500).send(`
      <h1>Authentication Failed</h1>
      <p>${err.message}</p>
      <a href="/">Try again</a>
    `);
  }
});

// Exchange authorization code for tokens
function exchangeCode(code, codeVerifier) {
  return new Promise((resolve, reject) => {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: VIZIPASS_CONFIG.redirect_uri,
      client_id: VIZIPASS_CONFIG.client_id,
      client_secret: VIZIPASS_CONFIG.client_secret,
      code_verifier: codeVerifier
    });

    const url = new URL(VIZIPASS_CONFIG.token_endpoint);
    const options = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': params.toString().length
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Invalid token response'));
        }
      });
    });

    req.on('error', reject);
    req.write(params.toString());
    req.end();
  });
}

// Fetch challenge from ViziPass with embedded image
function fetchChallenge(state, nonce, codeChallenge) {
  return new Promise((resolve, reject) => {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: VIZIPASS_CONFIG.client_id,
      redirect_uri: VIZIPASS_CONFIG.redirect_uri,
      scope: 'openid profile email',
      state: state,
      nonce: nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      embed_challenge: 'true'  // Request embedded challenge image
    });

    const url = new URL(VIZIPASS_CONFIG.issuer + '/api/v1/auth/challenge-session');
    const options = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': params.toString().length
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Invalid challenge response'));
        }
      });
    });

    req.on('error', reject);
    req.write(params.toString());
    req.end();
  });
}

// Store auth request mappings for polling
const authRequests = new Map();

// Check auth status (polled by client)
app.get('/check-auth', async (req, res) => {
  const { auth_request_id, state } = req.query;

  if (!auth_request_id || !state) {
    return res.json({ authenticated: false });
  }

  try {
    // Check with ViziPass if auth is complete
    const checkUrl = `${VIZIPASS_CONFIG.issuer}/api/v1/auth/check/${auth_request_id}`;

    const response = await new Promise((resolve, reject) => {
      http.get(checkUrl, (httpRes) => {
        let data = '';
        httpRes.on('data', chunk => data += chunk);
        httpRes.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve({ authenticated: false });
          }
        });
      }).on('error', () => resolve({ authenticated: false }));
    });

    if (response.authenticated && response.code) {
      // Auth complete - exchange code for tokens
      const pending = pendingAuth.get(state);
      if (!pending) {
        return res.json({ authenticated: false, error: 'Session expired' });
      }
      pendingAuth.delete(state);

      const tokenResponse = await exchangeCode(response.code, pending.verifier);

      if (tokenResponse.error) {
        return res.json({ authenticated: false, error: tokenResponse.error });
      }

      // Decode ID token
      const payload = JSON.parse(
        Buffer.from(tokenResponse.id_token.split('.')[1], 'base64url').toString()
      );

      // Create session
      const sessionId = crypto.randomBytes(32).toString('base64url');
      sessions.set(sessionId, {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        amr: payload.amr,
        access_token: tokenResponse.access_token,
        created: Date.now()
      });

      console.log('User authenticated via polling:', payload.email);

      // Return session cookie instruction
      res.setHeader('Set-Cookie', `session=${sessionId}; HttpOnly; Path=/; Max-Age=3600`);
      return res.json({ authenticated: true, email: payload.email, redirect: '/' });
    }

    res.json({ authenticated: false });
  } catch (err) {
    console.error('Check auth error:', err.message);
    res.json({ authenticated: false });
  }
});

// Logout
app.get('/logout', (req, res) => {
  const sessionId = req.headers.cookie?.match(/session=([^;]+)/)?.[1];
  if (sessionId) {
    sessions.delete(sessionId);
  }
  res.setHeader('Set-Cookie', 'session=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/');
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║           Waldo's Widgets - Demo Website                   ║
╠════════════════════════════════════════════════════════════╣
║  Website:    http://localhost:${PORT}                         ║
║  ViziPass:   ${VIZIPASS_CONFIG.issuer}                    ║
║                                                            ║
║  Flow:                                                     ║
║  1. Click "Login with ViziPass"                            ║
║  2. Authenticate with your phone                           ║
║  3. Get redirected back, logged in!                        ║
╚════════════════════════════════════════════════════════════╝
  `);
});
