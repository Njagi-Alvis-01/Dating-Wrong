import { initializeApp, getApps, getApp, App } from 'firebase-admin/app';
import { getFirestore, Firestore } from 'firebase-admin/firestore';
import { getAuth, Auth } from 'firebase-admin/auth';
import firebaseConfig from '../firebase-applet-config.json';

// Guarded singleton initialization for serverless execution
let adminApp: App;
if (getApps().length === 0) {
  adminApp = initializeApp({
    projectId: process.env.FIREBASE_PROJECT_ID || firebaseConfig.projectId,
  });
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

export { adminApp, db, adminAuth, firestoreDbId };
