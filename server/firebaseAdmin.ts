import { initializeApp, getApps, getApp, cert, App } from 'firebase-admin/app';
import { getFirestore, Firestore } from 'firebase-admin/firestore';
import { getAuth, Auth } from 'firebase-admin/auth';
import firebaseConfig from '../firebase-applet-config.json';

const firebaseProjectId = process.env.FIREBASE_PROJECT_ID || firebaseConfig.projectId;

function buildAdminCredential() {
  const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
  if (rawJson) {
    try {
      const decoded = rawJson.trim().startsWith('{')
        ? rawJson
        : Buffer.from(rawJson, 'base64').toString('utf-8');
      const parsed = JSON.parse(decoded);
      if (parsed.private_key && typeof parsed.private_key === 'string') {
        parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
      }
      return cert(parsed);
    } catch (err: any) {
      console.warn(`[FIREBASE ADMIN INIT] Could not parse FIREBASE_SERVICE_ACCOUNT_KEY: ${err.message}`);
    }
  }

  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY;
  if (clientEmail && privateKey) {
    return cert({
      projectId: firebaseProjectId,
      clientEmail,
      privateKey: privateKey.replace(/\\n/g, '\n'),
    });
  }

  return undefined;
}

// Vercel has no Google Application Default Credentials by default.
// Refuse to start with a partially privileged Firebase client: payment review,
// entitlements, admin tickets and reader access require Firebase Admin privileges.
const hasExplicitAdminCredentials = Boolean(
  process.env.FIREBASE_SERVICE_ACCOUNT_KEY ||
  (process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY)
);

// Guarded singleton initialization for serverless execution
let adminApp: App;
const explicitCredential = buildAdminCredential();

if (process.env.VERCEL === '1' && !hasExplicitAdminCredentials) {
  throw new Error(
    'Firebase Admin credentials are missing. Configure FIREBASE_SERVICE_ACCOUNT_KEY (recommended) or FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY in Vercel.'
  );
}

if (getApps().length === 0) {
  adminApp = initializeApp(
    explicitCredential
      ? { credential: explicitCredential, projectId: firebaseProjectId }
      : { projectId: firebaseProjectId }
  );
} else {
  adminApp = getApp();
}

// Target the explicit Firestore database configured for Dating Wrong
const firestoreDbId =
  process.env.FIRESTORE_DATABASE_ID ||
  firebaseConfig.firestoreDatabaseId ||
  'ai-studio-datingwrongbyger-7148f8d1-9dc9-4edc-9876-4352495da2c9';

const db: Firestore = getFirestore(adminApp, firestoreDbId);
const adminAuth: Auth = getAuth(adminApp);

export { adminApp, db, adminAuth, firestoreDbId, firebaseProjectId };
