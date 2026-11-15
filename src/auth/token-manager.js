/**
 * Token Manager
 * 
 * This module handles storage, retrieval, and refreshing of OAuth tokens.
 */
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config({ path: require('path').join(__dirname, '..', '..', '.env') });

// Configuration
const PINTEREST_APP_ID = process.env.PINTEREST_APP_ID;
const PINTEREST_APP_SECRET = process.env.PINTEREST_APP_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3052/';
const PINTEREST_API_URL = process.env.PINTEREST_API_URL || 'https://api.pinterest.com/v5';
const TOKEN_PATH = path.join(__dirname, '..', '..', 'tokens', 'pinterest_token.json');

/**
 * Stores a token to the JSON file
 * @param {Object} token Token object to store
 * @returns {Promise<void>}
 */
async function storeToken(token) {
  // Ensure token has all required fields
  const tokenData = {
    access_token: token.access_token,
    refresh_token: token.refresh_token || null,
    expires_at: token.expires_at || (Date.now() + 86400000), // Default 24 hours
    refresh_token_expires_at: token.refresh_token_expires_at || null,
    scopes: token.scopes || [],
    name: token.name || 'Pinterest API Token'
  };

  // Ensure tokens directory exists
  const tokenDir = path.dirname(TOKEN_PATH);
  if (!fs.existsSync(tokenDir)) {
    fs.mkdirSync(tokenDir, { recursive: true });
  }

  // Write token to file
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokenData, null, 2));
  console.error('Token stored successfully.');
}

/**
 * Reads token from the JSON file
 * @returns {Object|null} Token object or null if not found
 */
function readToken() {
  try {
    if (!fs.existsSync(TOKEN_PATH)) {
      console.error('No token file found.');
      return null;
    }

    const tokenData = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
    return tokenData;
  } catch (error) {
    console.error('Error reading token:', error.message);
    return null;
  }
}

/**
 * Checks if a token is expired
 * @param {Object} token Token object
 * @param {number} bufferSeconds Seconds before expiration to consider token expired
 * @returns {boolean} True if token is expired
 */
function isTokenExpired(token, bufferSeconds = 300) {
  if (!token || !token.expires_at) {
    return true;
  }

  // Consider token expired if it's within bufferSeconds of expiration
  return token.expires_at < Date.now() + (bufferSeconds * 1000);
}

/**
 * Builds the stored token object from a Pinterest /oauth/token response.
 * Pinterest returns expires_in (seconds), not expires_at, so compute it here.
 * @param {Object} data Response body
 * @param {Object} [previous] Previously stored token (to keep fields Pinterest omits)
 */
function buildToken(data, previous = {}) {
  const now = Date.now();
  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token || previous.refresh_token || null,
    token_type: data.token_type,
    expires_at: data.expires_in ? now + data.expires_in * 1000 : undefined,
    refresh_token_expires_at: data.refresh_token_expires_in
      ? now + data.refresh_token_expires_in * 1000
      : previous.refresh_token_expires_at,
    scopes: data.scope || previous.scopes || []
  };
}

/**
 * Refreshes an access token using the refresh token.
 * No scope is sent, so Pinterest keeps every scope granted at sign-in
 * (sending scope=boards:read here used to downgrade the token to read-only).
 * @param {string} refreshTokenValue Refresh token
 * @returns {Promise<Object>} New token object
 */
async function refreshToken(refreshTokenValue) {
  try {
    const previous = readToken() || {};
    const response = await axios.post(`${PINTEREST_API_URL}/oauth/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshTokenValue || previous.refresh_token
      }).toString(),
      {
        headers: {
          'Authorization': `Basic ${Buffer.from(`${PINTEREST_APP_ID}:${PINTEREST_APP_SECRET}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const token = buildToken(response.data, previous);
    await storeToken(token);
    return token;
  } catch (error) {
    console.error('Error refreshing token:', error.response?.data || error.message);
    throw error;
  }
}

// Kept for backwards compatibility with the old export; it was a copy of refreshToken.
const inspectToken = () => refreshToken();

/**
 * Gets a valid access token, refreshing if necessary
 * @returns {Promise<Object|null>} Valid token object or null if not available
 */
async function getValidToken() {
  try {
    const token = readToken();
    
    if (!token) {
      throw new Error('No token found. Authentication required.');
    }
    
    // Check if token is expired
    if (isTokenExpired(token)) {
      console.error('Token expired. Refreshing...');
      
      if (!token.refresh_token) {
        console.error('No refresh token available. Re-authentication required.');
        return null;
      }
      
      return await refreshToken(token.refresh_token);
    }
    
    return token;
  } catch (error) {
    console.error('Error getting valid token:', error.message);
    throw error;
  }
}

/**
 * Exchanges an authorization code for an access token
 * @param {string} code Authorization code from OAuth flow
 * @returns {Promise<Object>} Token object
 */
async function exchangeCodeForToken(code) {
  try {
    const response = await axios.post(`${PINTEREST_API_URL}/oauth/token`, 
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: REDIRECT_URI,
        continuous_refresh: 'true'
      }).toString(), 
      {
        headers: {
          'Authorization': `Basic ${Buffer.from(`${PINTEREST_APP_ID}:${PINTEREST_APP_SECRET}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const token = buildToken(response.data);

    // Store the new token
    await storeToken(token);
    return token;
  } catch (error) {
    console.error('Error exchanging code for token:', error.response?.data || error.message);
    throw error;
  }
}

/**
 * Revokes the current token
 * @returns {Promise<boolean>} True if token was revoked successfully
 */
async function revokeToken() {
  try {
    const token = readToken();
    
    if (!token || !token.access_token) {
      console.error('No token to revoke.');
      return false;
    }

    await axios.post(`${PINTEREST_API_URL}/oauth/token/revoke`, null, {
      params: {
        client_id: PINTEREST_APP_ID,
        client_secret: PINTEREST_APP_SECRET,
        token: token.access_token
      }
    });
    
    // Delete the token file
    if (fs.existsSync(TOKEN_PATH)) {
      fs.unlinkSync(TOKEN_PATH);
    }
    
    console.error('Token revoked successfully.');
    return true;
  } catch (error) {
    console.error('Error revoking token:', error.response?.data || error.message);
    return false;
  }
}

module.exports = {
  storeToken,
  readToken,
  isTokenExpired,
	inspectToken,
  refreshToken,
  getValidToken,
  exchangeCodeForToken,
  revokeToken
};
