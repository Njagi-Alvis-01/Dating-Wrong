# Dating Wrong — Vercel production configuration

This project uses a Vite static frontend and an Express API hosted as a Vercel Node.js Function. Do not configure a separate Express server process on Vercel.

## Required Vercel environment variables

Set these for **Production, Preview and Development** as appropriate, then redeploy:

- `FIREBASE_PROJECT_ID`: `synthetic-outrider-gw1xt`
- `FIRESTORE_DATABASE_ID`: `ai-studio-datingwrongbyger-7148f8d1-9dc9-4edc-9876-4352495da2c9`
- `FIREBASE_SERVICE_ACCOUNT_KEY`: complete Firebase service-account JSON, stored as a Vercel secret. Use a service account from the project above with Firebase Authentication token verification and Firestore read/write privileges.
- `ADMIN_SESSION_SECRET`: a stable random secret of at least 32 bytes. It must remain the same across deployments and serverless instances.
- `GMAIL_USER`: Gmail account used to send Dating Wrong notifications.
- `GMAIL_PASS`: Gmail App Password for that account (not the normal Gmail login password).
- `SMTP_FROM`: sender identity, e.g. `"Dating Wrong" <your-sending-address@gmail.com>`.
- `APP_URL` and `ADMIN_DASHBOARD_URL`: `https://www.datingwrong.online`.

The SMTP credentials currently configured in Google AI Studio do not automatically transfer to Vercel. Add them in Vercel Project → Settings → Environment Variables. Never put service-account JSON, Gmail app passwords, or signing secrets in source code or GitHub.

## Optional provider settings

- Africa's Talking SMS: `AT_USERNAME`, `AT_API_KEY`, and optionally `AT_SENDER_ID`. Until configured, the application reports SMS as not configured rather than claiming an SMS was sent.
- Daraja STK Push: configure `MPESA_CONSUMER_KEY`, `MPESA_CONSUMER_SECRET`, `MPESA_PASSKEY`, `MPESA_SHORTCODE`, `MPESA_ENV=production`, and `MPESA_CALLBACK_URL=https://www.datingwrong.online/api/payments/daraja/callback` if the STK Push option is intended to be used. The manual Pochi la Biashara flow does not require Daraja credentials.

## Vercel project settings

- Git repository: `Njagi-Alvis-01/Dating-Wrong`
- Production branch: `origin`
- Framework preset: Vite (or Other with the same commands)
- Build command: `npm run build`
- Output directory: `dist`
- Install command: `npm install`
- Node.js: 20 or later

The API function is `api/[...path].ts`; `vercel.json` sends non-file frontend routes to the SPA entry point.

## Firebase console checks

1. Confirm the service account belongs to project `synthetic-outrider-gw1xt` and can access the named Firestore database above.
2. Confirm Google sign-in is enabled in Firebase Authentication.
3. Add `www.datingwrong.online` and the Vercel production domain to Firebase Authentication → Settings → Authorized domains.
4. Keep Firestore security rules deployed. Server-side privileged operations use Firebase Admin; customer API calls must carry a valid Google Firebase ID token.

## Deployment verification

After environment variables are added and the repair branch is deployed to a Preview URL:

1. Open `/api/health` and verify HTTP 200.
2. Open `/api/book` and `/api/book/preview`.
3. Test Google sign-in, Pochi config retrieval, and a real M-PESA confirmation SMS submission.
4. Confirm one `paymentRequests` document and one linked `payments` document are created.
5. Confirm each administrator receives an email. SMS is verified only if Africa's Talking is configured.
6. Test review-ticket links, approval, rejection, duplicate transaction rejection, entitlement restoration, and the protected reader.
7. Test bookmarks, reading progress, offline cache, and all admin dashboard functions before promoting the repair branch to Production.

Do not use a genuine payment for the first test. Use a controlled low-value test payment or a verified test environment and reconcile it with the actual Pochi transaction record.
