import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';

// Global Fetch Interceptor: Automatically attaches verified Firebase ID token or cryptographic session token to protected endpoints
const originalFetch = window.fetch;
window.fetch = async (...args) => {
  let [resource, config] = args;
  const url = typeof resource === 'string' ? resource : resource instanceof Request ? resource.url : '';

  if (url.includes('/api/admin/') || url.includes('/api/book/content')) {
    try {
      const { auth } = await import('./services/firebase.ts');
      const currentUser = auth.currentUser;
      config = config ? { ...config } : {};
      const headers = new Headers(config.headers || {});

      if (currentUser) {
        const idToken = await currentUser.getIdToken();
        if (idToken) {
          headers.set('Authorization', `Bearer ${idToken}`);
        }
      }

      const adminSession = sessionStorage.getItem('dw_admin_session_token');
      if (adminSession) {
        headers.set('x-admin-session-token', adminSession);
      }

      config.headers = headers;
    } catch {
      // Non-blocking fallback
    }
  }

  return originalFetch(resource, config);
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
