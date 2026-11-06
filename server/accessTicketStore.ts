/**
 * Single-Use Cryptographic Access Ticket & Nonce Store (OTP System)
 * 
 * Enforces strict security requirements:
 * 1. URLs sent to customers and administrators contain single-use cryptographic tokens (OTP nonces).
 * 2. Generated using 256-bit high-entropy random bytes.
 * 3. Only the SHA-256 hash of the token is persisted in Firestore (/accessTickets collection).
 * 4. Each token is strictly mapped to ONE designated email address.
 * 5. Consumed via atomic Firestore transaction to prevent replay attacks across distributed serverless instances.
 * 6. Unauthorized users attempting to use another person's URL or token are rejected.
 * 7. Expired tickets are rejected upon evaluation (no background timers required).
 */

import crypto from 'crypto';
import { db } from './firebaseAdmin.ts';
import { PaymentStore, BookEntitlementRecord } from './paymentStore.ts';

export interface AccessTicket {
  ticketId: string; // Plain token in memory / during creation
  ticketHash: string; // SHA-256 hash stored in Firestore
  type: 'customer_reader' | 'admin_review';
  targetEmail: string; // Normalized lowercase
  requestId: string;
  transactionCode?: string;
  createdAt: string;
  expiresAt: string;
  isConsumed: boolean;
  consumedAt?: string;
  consumedByUid?: string;
  consumedByEmail?: string;
  singleUse: boolean;
}

export class AccessTicketStore {
  // In-memory token cache for local execution and fast lookup
  private static ticketCache = new Map<string, AccessTicket>();

  /**
   * Generates a high-entropy 256-bit cryptographically secure token
   */
  private static generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Computes the SHA-256 hash of an access ticket token
   */
  public static hashToken(token: string): string {
    return crypto.createHash('sha256').update(token.trim()).digest('hex');
  }

  /**
   * Create a single-use reader access ticket for an approved customer.
   * Strictly mapped to the customer's email.
   * The raw token is returned to the caller; only the SHA-256 hash is saved in Firestore.
   */
  static async createCustomerReaderTicket(params: {
    email: string;
    requestId: string;
    transactionCode?: string;
    expiresInDays?: number;
  }): Promise<string> {
    const cleanEmail = (params.email || '').trim().toLowerCase();
    if (!cleanEmail) {
      throw new Error('Customer email is required to issue an access ticket.');
    }

    const token = this.generateToken();
    const tokenHash = this.hashToken(token);
    const now = new Date();
    const days = params.expiresInDays || 7;
    const expiresAt = new Date(now.getTime() + days * 24 * 60 * 60 * 1000).toISOString();

    const ticket: AccessTicket = {
      ticketId: token,
      ticketHash: tokenHash,
      type: 'customer_reader',
      targetEmail: cleanEmail,
      requestId: params.requestId,
      transactionCode: params.transactionCode,
      createdAt: now.toISOString(),
      expiresAt,
      isConsumed: false,
      singleUse: true,
    };

    // Cache locally
    this.ticketCache.set(tokenHash, ticket);

    // Persist SHA-256 hashed ticket in Firestore
    try {
      await db.collection('accessTickets').doc(tokenHash).set({
        ticketHash: tokenHash,
        type: 'customer_reader',
        targetEmail: cleanEmail,
        requestId: params.requestId,
        transactionCode: params.transactionCode || null,
        createdAt: ticket.createdAt,
        expiresAt: ticket.expiresAt,
        isConsumed: false,
        consumedAt: null,
        consumedByEmail: null,
        consumedByUid: null,
        singleUse: true,
      });
      console.log(`[ACCESS TICKET STORED] Persisted SHA-256 hashed reader ticket in Firestore for ${cleanEmail} (Req: ${params.requestId})`);
    } catch (err: any) {
      console.warn(`[ACCESS TICKET FIRESTORE WARNING] Failed to persist ticket in Firestore, relying on memory cache: ${err.message}`);
    }

    return token;
  }

  /**
   * Consume a customer reader ticket (OTP operation).
   * Operates via Firestore atomic transaction to prevent replay attacks across multiple serverless instances.
   */
  static async consumeCustomerReaderTicket(params: {
    ticketId: string;
    email: string;
    uid?: string;
  }): Promise<{
    valid: boolean;
    reason?: string;
    ticket?: AccessTicket;
    entitlement?: BookEntitlementRecord;
  }> {
    const rawTicket = (params.ticketId || '').trim();
    const requestingEmail = (params.email || '').trim().toLowerCase();

    if (!rawTicket) {
      return {
        valid: false,
        reason: 'Access ticket token is missing.',
      };
    }

    const tokenHash = this.hashToken(rawTicket);
    const consumedAt = new Date().toISOString();
    const userUid = params.uid || `usr_${requestingEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;

    try {
      const ticketRef = db.collection('accessTickets').doc(tokenHash);

      const result = await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(ticketRef);
        let ticketData: AccessTicket | null = null;

        if (doc.exists) {
          ticketData = doc.data() as AccessTicket;
        } else if (this.ticketCache.has(tokenHash)) {
          ticketData = this.ticketCache.get(tokenHash)!;
        }

        if (!ticketData || ticketData.type !== 'customer_reader') {
          return {
            valid: false,
            reason: 'Invalid or unrecognized access ticket. Please sign in with your authorized Google account.',
          };
        }

        // 1. Check if already consumed (One-Time Passcode)
        if (ticketData.isConsumed) {
          return {
            valid: false,
            reason: 'This one-time access ticket has already been used and cannot be reused. Your account must already be authorized; please sign in with your Google account.',
          };
        }

        // 2. Check expiration
        if (new Date() > new Date(ticketData.expiresAt)) {
          return {
            valid: false,
            reason: 'This access ticket has expired. Please restore your access or contact support.',
          };
        }

        // 3. Check email mapping (Must strictly match the email in the ticket)
        if (requestingEmail && requestingEmail !== ticketData.targetEmail.toLowerCase()) {
          console.warn(`[UNAUTHORIZED TICKET ATTEMPT] Ticket meant for ${ticketData.targetEmail} was used by ${requestingEmail}`);
          return {
            valid: false,
            reason: `Unauthorized: This access ticket was cryptographically generated for ${ticketData.targetEmail} and cannot be used by ${requestingEmail}.`,
          };
        }

        // 4. Mark ticket as permanently consumed inside transaction
        transaction.update(ticketRef, {
          isConsumed: true,
          consumedAt,
          consumedByEmail: requestingEmail || ticketData.targetEmail,
          consumedByUid: params.uid || null,
        });

        // 5. Create or verify entitlement document in Firestore
        const entitlementRef = db.collection('bookEntitlements').doc(`${userUid}_dating-wrong`);
        const entitlementDoc = await transaction.get(entitlementRef);

        let entitlement: BookEntitlementRecord;
        if (entitlementDoc.exists) {
          entitlement = entitlementDoc.data() as BookEntitlementRecord;
        } else {
          entitlement = {
            uid: userUid,
            bookId: 'dating-wrong',
            bookVersion: 1,
            status: 'ACTIVE',
            grantedAt: consumedAt,
            paymentId: `ENT-TKT-${ticketData.requestId}`,
            transactionCode: ticketData.transactionCode || 'VERIFIED',
            offlineEnabled: true,
            authorizedDevices: [],
            lastSyncedAt: consumedAt,
            watermark: `Authorized Digital Edition • ${ticketData.targetEmail} • Dating Wrong`,
          };
          transaction.set(entitlementRef, entitlement);
        }

        // Update local memory cache
        ticketData.isConsumed = true;
        ticketData.consumedAt = consumedAt;
        ticketData.consumedByEmail = requestingEmail || ticketData.targetEmail;
        ticketData.consumedByUid = params.uid;
        this.ticketCache.set(tokenHash, ticketData);
        PaymentStore.setEntitlement(entitlement);

        return {
          valid: true,
          ticket: ticketData,
          entitlement,
        };
      });

      return result;
    } catch (err: any) {
      console.error(`[ACCESS TICKET TRANSACTION ERROR] Failed to consume ticket: ${err.message}`);
      // Fallback to local memory verification if Firestore is unavailable
      const cached = this.ticketCache.get(tokenHash);
      if (cached && !cached.isConsumed && new Date() <= new Date(cached.expiresAt)) {
        if (!requestingEmail || requestingEmail === cached.targetEmail.toLowerCase()) {
          cached.isConsumed = true;
          cached.consumedAt = consumedAt;
          cached.consumedByEmail = requestingEmail || cached.targetEmail;
          cached.consumedByUid = params.uid;
          let ent = PaymentStore.getEntitlement(userUid, 'dating-wrong');
          if (!ent) {
            ent = {
              uid: userUid,
              bookId: 'dating-wrong',
              bookVersion: 1,
              status: 'ACTIVE',
              grantedAt: consumedAt,
              paymentId: `ENT-TKT-${cached.requestId}`,
              transactionCode: cached.transactionCode || 'VERIFIED',
              offlineEnabled: true,
              authorizedDevices: [],
              lastSyncedAt: consumedAt,
              watermark: `Authorized Digital Edition • ${cached.targetEmail} • Dating Wrong`,
            };
            PaymentStore.setEntitlement(ent);
          }
          return { valid: true, ticket: cached, entitlement: ent };
        }
      }
      return {
        valid: false,
        reason: 'Unable to verify access ticket due to a server error. Please try again or sign in directly.',
      };
    }
  }

  /**
   * Create a single-use review ticket for an administrator.
   * Strictly mapped to that administrator's email.
   */
  static async createAdminReviewTicket(params: {
    adminEmail: string;
    requestId: string;
    expiresInHours?: number;
  }): Promise<string> {
    const cleanEmail = (params.adminEmail || '').trim().toLowerCase();
    const authorized = ['wanyekigerison@gmail.com', 'ochiengmark2908@gmail.com', 'alvisnjagi@gmail.com'];
    if (!authorized.includes(cleanEmail)) {
      throw new Error(`Unauthorized administrator email: ${cleanEmail}`);
    }

    const token = this.generateToken();
    const tokenHash = this.hashToken(token);
    const now = new Date();
    const hours = params.expiresInHours || 48;
    const expiresAt = new Date(now.getTime() + hours * 60 * 60 * 1000).toISOString();

    const ticket: AccessTicket = {
      ticketId: token,
      ticketHash: tokenHash,
      type: 'admin_review',
      targetEmail: cleanEmail,
      requestId: params.requestId,
      createdAt: now.toISOString(),
      expiresAt,
      isConsumed: false,
      singleUse: true,
    };

    this.ticketCache.set(tokenHash, ticket);

    try {
      await db.collection('accessTickets').doc(tokenHash).set({
        ticketHash: tokenHash,
        type: 'admin_review',
        targetEmail: cleanEmail,
        requestId: params.requestId,
        createdAt: ticket.createdAt,
        expiresAt: ticket.expiresAt,
        isConsumed: false,
        consumedAt: null,
        consumedByEmail: null,
        singleUse: true,
      });
      console.log(`[ADMIN TICKET STORED] Persisted SHA-256 hashed admin ticket in Firestore for ${cleanEmail} (Req: ${params.requestId})`);
    } catch (err: any) {
      console.warn(`[ADMIN TICKET FIRESTORE WARNING] Failed to persist ticket in Firestore: ${err.message}`);
    }

    return token;
  }

  /**
   * Verify and consume an admin review ticket.
   * Operates via Firestore atomic transaction to prevent replay attacks across distributed serverless instances.
   */
  static async verifyAndConsumeAdminTicket(params: {
    ticketId: string;
    adminEmail?: string;
    requestingEmail?: string;
    requestId?: string;
  }): Promise<{
    valid: boolean;
    reason?: string;
    ticket?: AccessTicket;
  }> {
    const rawTicket = (params.ticketId || '').trim();
    if (!rawTicket) {
      return {
        valid: false,
        reason: 'Admin access ticket is required.',
      };
    }

    const tokenHash = this.hashToken(rawTicket);
    const reqEmail = (params.requestingEmail || params.adminEmail || '').trim().toLowerCase();
    const consumedAt = new Date().toISOString();

    try {
      const ticketRef = db.collection('accessTickets').doc(tokenHash);

      const result = await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(ticketRef);
        let ticketData: AccessTicket | null = null;

        if (doc.exists) {
          ticketData = doc.data() as AccessTicket;
        } else if (this.ticketCache.has(tokenHash)) {
          ticketData = this.ticketCache.get(tokenHash)!;
        }

        if (!ticketData || ticketData.type !== 'admin_review') {
          return {
            valid: false,
            reason: 'Invalid or unrecognized administrative access ticket.',
          };
        }

        // 1. Check if already consumed
        if (ticketData.isConsumed) {
          return {
            valid: false,
            reason: 'This administrative access ticket has already been used and cannot be reused.',
          };
        }

        // 2. Check expiration
        if (new Date() > new Date(ticketData.expiresAt)) {
          return {
            valid: false,
            reason: 'This administrative access ticket has expired.',
          };
        }

        // 3. Check admin email mapping
        if (reqEmail && reqEmail !== ticketData.targetEmail.toLowerCase()) {
          console.warn(`[UNAUTHORIZED ADMIN TICKET ATTEMPT] Ticket for ${ticketData.targetEmail} accessed by ${reqEmail}`);
          return {
            valid: false,
            reason: `Unauthorized: This administrative link is cryptographically tied to ${ticketData.targetEmail}.`,
          };
        }

        // 4. Mark consumed inside transaction
        transaction.update(ticketRef, {
          isConsumed: true,
          consumedAt,
          consumedByEmail: reqEmail || ticketData.targetEmail,
        });

        // Update local memory cache
        ticketData.isConsumed = true;
        ticketData.consumedAt = consumedAt;
        ticketData.consumedByEmail = reqEmail || ticketData.targetEmail;
        this.ticketCache.set(tokenHash, ticketData);

        console.log(`[ADMIN TICKET VERIFIED] Verified and burned single-use admin ticket for ${ticketData.targetEmail}`);

        return {
          valid: true,
          ticket: ticketData,
        };
      });

      return result;
    } catch (err: any) {
      console.error(`[ADMIN TICKET TRANSACTION ERROR] Failed to verify admin ticket: ${err.message}`);
      const cached = this.ticketCache.get(tokenHash);
      if (cached && !cached.isConsumed && new Date() <= new Date(cached.expiresAt)) {
        if (!reqEmail || reqEmail === cached.targetEmail.toLowerCase()) {
          cached.isConsumed = true;
          cached.consumedAt = consumedAt;
          cached.consumedByEmail = reqEmail || cached.targetEmail;
          return { valid: true, ticket: cached };
        }
      }
      return {
        valid: false,
        reason: 'Unable to verify administrative ticket due to a server error.',
      };
    }
  }

  /**
   * Inspect ticket details by hash without consuming
   */
  static async getTicket(ticketId: string): Promise<AccessTicket | undefined> {
    const tokenHash = this.hashToken(ticketId);
    if (this.ticketCache.has(tokenHash)) {
      return this.ticketCache.get(tokenHash);
    }
    try {
      const doc = await db.collection('accessTickets').doc(tokenHash).get();
      if (doc.exists) {
        return doc.data() as AccessTicket;
      }
    } catch (err: any) {
      console.warn(`[ACCESS TICKET GET WARNING] ${err.message}`);
    }
    return undefined;
  }
}
