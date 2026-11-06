import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { adminAuth, db } from '../firebaseAdmin.ts';

// Explicit 3-administrator allowlist for Dating Wrong
export const ADMIN_ALLOWLIST = [
  'wanyekigerison@gmail.com',
  'alvisnjagi@gmail.com',
  'ochiengmark2908@gmail.com',
] as const;

export type AdminEmail = (typeof ADMIN_ALLOWLIST)[number];

export interface AuthenticatedAdminRequest extends Request {
  adminUser?: {
    uid: string;
    email: string;
    authMethod: 'firebase_id_token' | 'cryptographic_admin_ticket' | 'admin_session_token';
  };
}

// Server HMAC Secret for signing administrative session nonces
const ADMIN_HMAC_SECRET = process.env.ADMIN_SESSION_SECRET || crypto.randomBytes(32).toString('hex');

/**
 * Creates a cryptographically signed admin session token.
 * Valid for 12 hours.
 */
export function generateAdminSessionToken(adminEmail: string): string {
  const cleanEmail = adminEmail.trim().toLowerCase();
  const expiresAt = Date.now() + 12 * 60 * 60 * 1000;
  const payload = `${cleanEmail}:${expiresAt}`;
  const signature = crypto.createHmac('sha256', ADMIN_HMAC_SECRET).update(payload).digest('hex');
  const token = Buffer.from(`${payload}:${signature}`).toString('base64url');
  return token;
}

/**
 * Verifies a cryptographically signed admin session token.
 */
export function verifyAdminSessionToken(token: string): { valid: boolean; email?: string } {
  try {
    const raw = Buffer.from(token, 'base64url').toString('utf-8');
    const parts = raw.split(':');
    if (parts.length !== 3) return { valid: false };
    const [email, expiresAtStr, signature] = parts;
    const expiresAt = parseInt(expiresAtStr, 10);

    if (Date.now() > expiresAt) {
      return { valid: false };
    }

    const payload = `${email}:${expiresAtStr}`;
    const expectedSig = crypto.createHmac('sha256', ADMIN_HMAC_SECRET).update(payload).digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSig, 'hex'))) {
      return { valid: false };
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!ADMIN_ALLOWLIST.includes(cleanEmail as AdminEmail)) {
      return { valid: false };
    }

    return { valid: true, email: cleanEmail };
  } catch {
    return { valid: false };
  }
}

/**
 * Express Middleware: Require Verified Administrator
 * Strictly enforces:
 * 1. Never trusts client-supplied headers (e.g. x-admin-email, x-user-role) without cryptographic proof.
 * 2. Verifies Firebase ID tokens using Firebase Admin SDK.
 * 3. Enforces the 3-administrator allowlist on the server.
 * 4. Fails closed on any verification error.
 */
export async function requireAdminAuth(
  req: AuthenticatedAdminRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    const sessionHeader = (req.headers['x-admin-session-token'] || req.headers['x-admin-token']) as string | undefined;
    const ticketHeader = req.headers['x-admin-ticket'] as string | undefined;

    // 1. Primary: Verify Firebase ID Token via Firebase Admin SDK
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const idToken = authHeader.substring(7).trim();
      if (idToken) {
        try {
          const decoded = await adminAuth.verifyIdToken(idToken);
          const email = (decoded.email || '').trim().toLowerCase();

          if (!ADMIN_ALLOWLIST.includes(email as AdminEmail)) {
            console.warn(`[ADMIN FORBIDDEN] Authenticated user ${email} is not in the Dating Wrong administrator allowlist.`);
            res.status(403).json({
              error: 'Forbidden: Access denied.',
              message: 'Your Google account is not on the authorized administrator allowlist for Dating Wrong.',
            });
            return;
          }

          req.adminUser = {
            uid: decoded.uid,
            email,
            authMethod: 'firebase_id_token',
          };
          return next();
        } catch (tokenErr: any) {
          console.warn(`[ADMIN TOKEN ERROR] Firebase ID token verification failed: ${tokenErr.message}`);
          // Fall through to test other methods if present
        }
      }
    }

    // 2. Secondary: Verify Cryptographic Admin Session Token
    if (sessionHeader) {
      const verification = verifyAdminSessionToken(sessionHeader);
      if (verification.valid && verification.email) {
        req.adminUser = {
          uid: `admin_${verification.email.replace(/[^a-zA-Z0-9]/g, '_')}`,
          email: verification.email,
          authMethod: 'admin_session_token',
        };
        return next();
      }
    }

    // 3. Tertiary: Verify Admin Single-Use Ticket (if passed in header)
    if (ticketHeader) {
      const ticketHash = crypto.createHash('sha256').update(ticketHeader.trim()).digest('hex');
      const ticketDoc = await db.collection('accessTickets').doc(ticketHash).get();
      if (ticketDoc.exists) {
        const data = ticketDoc.data();
        if (data && data.type === 'admin_review' && !data.isConsumed && Date.now() <= new Date(data.expiresAt).getTime()) {
          const email = (data.targetEmail || '').trim().toLowerCase();
          if (ADMIN_ALLOWLIST.includes(email as AdminEmail)) {
            req.adminUser = {
              uid: `admin_${email.replace(/[^a-zA-Z0-9]/g, '_')}`,
              email,
              authMethod: 'cryptographic_admin_ticket',
            };
            return next();
          }
        }
      }
    }

    // Any attempt to access with client-supplied headers without cryptographic proof is rejected
    const untrustedEmail = req.headers['x-admin-email'];
    if (untrustedEmail) {
      console.warn(`[ADMIN SECURITY REJECTION] Rejected unverified request attempting to claim admin identity: ${untrustedEmail}`);
    }

    res.status(401).json({
      error: 'Unauthorized: Administrator authentication required.',
      message: 'Valid Firebase ID token or cryptographic administrator token required. Client-supplied headers are not trusted.',
    });
  } catch (err: any) {
    console.error(`[ADMIN AUTH UNEXPECTED ERROR] ${err.message}`);
    res.status(500).json({
      error: 'Authentication service temporarily unavailable.',
    });
  }
}
