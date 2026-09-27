/**
 * Firebase ID Token Verification Middleware for Express
 * Validates Google/Firebase RS256 JWT tokens using Google's public certificates.
 * Enforces authentication on all protected /api/* endpoints.
 */

import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { config } from './config.js';

export interface FirebaseTokenPayload {
  name?: string;
  picture?: string;
  iss: string;
  aud: string;
  auth_time: number;
  user_id: string;
  sub: string;
  iat: number;
  exp: number;
  email?: string;
  email_verified?: boolean;
  firebase?: {
    identities: Record<string, string[]>;
    sign_in_provider: string;
  };
  [key: string]: any;
}

export interface AuthenticatedRequest extends Request {
  user?: FirebaseTokenPayload;
}

// In-memory cache for Google's public x509 certificates
let cachedCertificates: Record<string, string> = {};
let certificatesExpiresAt = 0;
let isFetchingCertificates = false;

const GOOGLE_CERTS_URL =
  'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

/**
 * Fetch and cache Google's public x509 certificates for Firebase Auth token verification
 */
async function fetchGooglePublicCertificates(forceRefresh = false): Promise<Record<string, string>> {
  const now = Date.now();
  if (!forceRefresh && Object.keys(cachedCertificates).length > 0 && now < certificatesExpiresAt) {
    return cachedCertificates;
  }

  // Prevent duplicate concurrent fetches
  if (isFetchingCertificates && Object.keys(cachedCertificates).length > 0) {
    return cachedCertificates;
  }

  isFetchingCertificates = true;
  try {
    const res = await fetch(GOOGLE_CERTS_URL, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(8000)
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch Google public certificates: HTTP ${res.status}`);
    }

    const certs: Record<string, string> = await res.json();
    cachedCertificates = certs;

    // Parse max-age from Cache-Control header if available
    const cacheControl = res.headers.get('cache-control') || '';
    const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
    const ttlSeconds = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 6 * 3600; // default 6 hours
    certificatesExpiresAt = now + Math.max(ttlSeconds, 300) * 1000;

    return cachedCertificates;
  } catch (err: any) {
    console.error('[AUTH] Error fetching Google public certificates:', err.message);
    // If we have stale cache, continue using it
    if (Object.keys(cachedCertificates).length > 0) {
      return cachedCertificates;
    }
    throw err;
  } finally {
    isFetchingCertificates = false;
  }
}

/**
 * Decode a base64url-encoded string
 */
function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Verify a Firebase ID Token using Google's public x509 certificates
 */
export async function verifyFirebaseIdToken(
  token: string,
  targetProjectId?: string
): Promise<FirebaseTokenPayload> {
  if (!token || typeof token !== 'string') {
    throw new Error('Token must be a non-empty string');
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed token: Expected 3 JWT segments');
  }

  const [rawHeader, rawPayload, rawSignature] = parts;

  let header: { alg?: string; kid?: string; typ?: string };
  let payload: FirebaseTokenPayload;

  try {
    header = JSON.parse(base64UrlDecode(rawHeader));
  } catch {
    throw new Error('Malformed token header');
  }

  try {
    payload = JSON.parse(base64UrlDecode(rawPayload));
  } catch {
    throw new Error('Malformed token payload');
  }

  if (header.alg !== 'RS256') {
    throw new Error(`Unsupported token algorithm: expected RS256, got ${header.alg}`);
  }

  if (!header.kid) {
    throw new Error('Token header missing "kid" (key ID)');
  }

  const expectedProjectId =
    targetProjectId ||
    process.env.FIREBASE_PROJECT_ID ||
    process.env.VITE_FIREBASE_PROJECT_ID ||
    'gen-lang-client-0906610882';

  // 1. Verify claims according to Firebase specification
  const now = Math.floor(Date.now() / 1000);
  const CLOCK_SKEW_SECONDS = 300; // 5-minute tolerance for server clock skew

  if (typeof payload.exp !== 'number' || payload.exp < now - CLOCK_SKEW_SECONDS) {
    throw new Error('Firebase ID token has expired');
  }

  if (typeof payload.iat !== 'number' || payload.iat > now + CLOCK_SKEW_SECONDS) {
    throw new Error('Firebase ID token issued in the future');
  }

  if (payload.aud !== expectedProjectId) {
    throw new Error(`Firebase ID token "aud" (${payload.aud}) does not match project ID (${expectedProjectId})`);
  }

  const expectedIssuer = `https://securetoken.google.com/${expectedProjectId}`;
  if (payload.iss !== expectedIssuer) {
    throw new Error(`Firebase ID token "iss" (${payload.iss}) does not match expected issuer (${expectedIssuer})`);
  }

  if (typeof payload.sub !== 'string' || payload.sub.trim().length === 0) {
    throw new Error('Firebase ID token missing "sub" subject claim');
  }

  // 2. Retrieve public certificates from Google
  let certs = await fetchGooglePublicCertificates(false);
  let cert = certs[header.kid];

  // If key not found in cache, force-refresh once in case of Google key rotation
  if (!cert) {
    certs = await fetchGooglePublicCertificates(true);
    cert = certs[header.kid];
  }

  if (!cert) {
    throw new Error(`Public certificate not found for key ID: ${header.kid}`);
  }

  // 3. Cryptographically verify RS256 signature using certificate
  const signedData = Buffer.from(`${rawHeader}.${rawPayload}`, 'utf8');
  const signatureBuffer = Buffer.from(rawSignature, 'base64url');

  const isValid = crypto.verify('RSA-SHA256', signedData, cert, signatureBuffer);
  if (!isValid) {
    throw new Error('Firebase ID token signature verification failed');
  }

  return payload;
}

/**
 * Express middleware to require a verified Firebase ID token on /api/* routes
 */
export async function requireFirebaseAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  // Allow CORS preflight requests
  if (req.method === 'OPTIONS') {
    return next();
  }

  // Exempt public health probe (used by container monitoring & uptime checks)
  if (req.path === '/api/health' || req.path === '/health') {
    return next();
  }

  // Extract token from Authorization header or URL query parameter (for direct file downloads/iframes)
  const authHeader = req.headers.authorization;
  let token: string | null = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (typeof req.headers['x-firebase-token'] === 'string') {
    token = req.headers['x-firebase-token'].trim();
  } else if (typeof req.query.token === 'string') {
    token = req.query.token.trim();
  } else if (typeof req.query.auth_token === 'string') {
    token = req.query.auth_token.trim();
  } else if (typeof req.query.idToken === 'string') {
    token = req.query.idToken.trim();
  }

  if (!token) {
    return res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required. Please provide a verified Firebase ID token in Authorization header or query parameter.'
      }
    });
  }

  try {
    const verifiedUser = await verifyFirebaseIdToken(token);

    // Verify authorized corporate domain (@optiv.com or verified @gmail.com)
    const email = (verifiedUser.email || '').trim().toLowerCase();
    const isAllowed = email.endsWith('@optiv.com') || email.endsWith('@gmail.com');
    if (!isAllowed) {
      return res.status(403).json({
        error: {
          code: 'FORBIDDEN_DOMAIN',
          message: `Access denied for "${email}". Only authorized @optiv.com and verified @gmail.com accounts are permitted.`
        }
      });
    }

    req.user = verifiedUser;
    return next();
  } catch (err: any) {
    console.warn(`[AUTH] Unauthorized request to ${req.path}: ${err.message}`);
    return res.status(401).json({
      error: {
        code: 'INVALID_TOKEN',
        message: `Unauthorized: ${err.message}`
      }
    });
  }
}
