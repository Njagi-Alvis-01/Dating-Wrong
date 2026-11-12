import { auth } from '../services/firebase.ts';

/**
 * Helper around native fetch that attaches Firebase ID Token and/or
 * cryptographic admin session token without mutating global window.fetch.
 */
export async function authorizedFetch(
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<Response> {
  const headers = new Headers(init.headers || {});

  try {
    const currentUser = auth.currentUser;
    if (currentUser) {
      const idToken = await currentUser.getIdToken();
      if (idToken) {
        headers.set('Authorization', `Bearer ${idToken}`);
      }
    }
  } catch {
    // Non-blocking: proceed with session token if available
  }

  try {
    const adminSession = sessionStorage.getItem('dw_admin_session_token');
    if (adminSession) {
      headers.set('x-admin-session-token', adminSession);
    }
  } catch {
    // Ignore storage access errors
  }

  return window.fetch(input, {
    ...init,
    headers,
  });
}
