/**
 * Client-Side API Helper with Firebase ID Token Injection
 * Ensures all /api/* requests carry a valid Authorization: Bearer token.
 */

import { auth } from './firebase';

/**
 * Get current Firebase user ID token (automatically refreshes if expired)
 */
export async function getAuthToken(forceRefresh = false): Promise<string | null> {
  const user = auth.currentUser;
  if (!user) return null;
  try {
    return await user.getIdToken(forceRefresh);
  } catch (err) {
    console.error('Failed to get Firebase ID token:', err);
    return null;
  }
}

/**
 * Authenticated fetch helper for all backend /api/* endpoints
 * Attaches Authorization: Bearer <token> and retries once if token expired
 */
export async function authenticatedFetch(
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<Response> {
  const token = await getAuthToken();
  const headers = new Headers(init.headers || {});
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(input, {
    ...init,
    headers
  });

  // If unauthorized and we had a token, try refreshing once
  if (res.status === 401 && token) {
    const refreshedToken = await getAuthToken(true);
    if (refreshedToken && refreshedToken !== token) {
      headers.set('Authorization', `Bearer ${refreshedToken}`);
      return fetch(input, {
        ...init,
        headers
      });
    }
  }

  return res;
}

/**
 * Appends token query parameter for browser direct links, iframes, and file downloads
 */
export async function getAuthenticatedUrl(baseUrl: string): Promise<string> {
  const token = await getAuthToken();
  if (!token) return baseUrl;
  const separator = baseUrl.includes('?') ? '&' : '?';
  return `${baseUrl}${separator}token=${encodeURIComponent(token)}`;
}
