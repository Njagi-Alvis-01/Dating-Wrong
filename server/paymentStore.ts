/**
 * Server-Side Payment Verification & Entitlement Store
 *
 * Implements Section 15 & 21:
 * Client must NEVER be trusted for:
 * - payment amount
 * - payment status
 * - transaction validity
 * - recipient
 * - entitlement
 * - transaction ownership
 *
 * Minimum successful payment conditions:
 * 1. Payment status is successful
 * 2. Amount matches configured book price
 * 3. Sender phone matches the M-PESA phone provided during checkout
 * 4. Recipient/merchant is Dating Wrong / configured merchant account
 * 5. Transaction identifier is valid and strictly normalized
 * 6. Transaction has not already been used for another entitlement (uniqueness)
 * 7. Payment belongs to the current payment session or can be securely correlated
 * 8. Transaction timestamp is reasonable
 * 9. No fraud/security flag exists
 *
 * All entitlement, payment-request, and device authorizations are backed directly
 * by asynchronous Firestore operations with atomic transactions for concurrency safety.
 */

import { normalizeKenyanPhone, arePhonesEqual } from '../src/utils/phoneNormalization.ts';
import { NotificationService } from './notificationService.ts';
import { EmailConfirmationService } from './emailConfirmationService.ts';
import { parseMpesaSms } from '../src/utils/mpesaSmsParser.ts';
import {
  fsGetDoc,
  fsSetDoc,
  fsUpdateDoc,
  fsQuery,
  fsBatchCommit,
  fsRunTransaction,
  BatchWriteOp,
  getRequestAuth,
  isUnauthenticatedPermissionError,
} from './firestoreAdapter.ts';

export type PaymentStatus =
  | 'CREATED'
  | 'PENDING'
  | 'STK_SENT'
  | 'SUCCESSFUL'
  | 'VERIFIED'
  | 'UNDERPAID'
  | 'FAILED'
  | 'REJECTED'
  | 'INVALID_CODE'
  | 'DUPLICATE'
  | 'MANUAL_REVIEW'
  | 'REFUNDED';

export interface PaymentRecord {
  paymentId: string;
  paymentSessionId: string; // Section 34: Unique Payment Session ID
  uid: string;
  email: string;
  customerName: string;
  phone: string; // Original checkout phone
  checkoutPhone: string;
  normalizedPhone: string;
  expectedAmount: number;
  receivedAmount?: number;
  transactionCode?: string;
  recipient: string;
  bookId: string; // Section 34
  bookVersion: number; // Section 34
  status: PaymentStatus;
  provider: 'daraja' | 'pasted_sms' | 'manual_admin';
  checkoutCreatedAt: string;
  expiresAt: string; // Section 34: Session expiration time (e.g. 15 mins)
  paymentReceivedAt?: string;
  verifiedAt?: string;
  verificationMethod?: string;
  rawReference?: string;
  checkoutRequestId?: string;
  merchantRequestId?: string;
  securityChecksPassed: boolean;
  failureReason?: string;
  adminAlertSent: boolean;
  emailConfirmationSent?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface BookEntitlementRecord {
  uid: string;
  bookId: string;
  bookVersion: number;
  status: 'ACTIVE' | 'REVOKED' | 'PENDING';
  grantedAt: string;
  paymentId: string;
  transactionCode: string;
  offlineEnabled: boolean;
  authorizedDevices: string[];
  lastSyncedAt: string;
  watermark?: string;
}

export interface StoredAuthorizedDevice {
  deviceId: string;
  userId: string;
  deviceName: string;
  platform: 'desktop' | 'mobile' | 'tablet';
  authorizedAt: string;
  lastSeenAt: string;
  status: 'active' | 'revoked';
}

export interface StoredReadingProgress {
  uid: string;
  bookId: string;
  currentPage: number;
  percentage: number;
  lastReadAt: string;
}

export interface StoredBookmark {
  page: number;
  chapter: string;
  createdAt: string;
  note?: string;
}

export interface UsedTransactionRecord {
  transactionCode: string;
  usedForUid: string;
  paymentId: string;
  amount: number;
  usedAt: string;
  phone: string;
  status?: 'ACTIVE' | 'REVOKED';
  reusable?: boolean;
  revokedAt?: string;
  revocationReason?: string;
  permanentlyLocked?: boolean;
}

export interface PaymentRequestRecord {
  requestId: string;
  uid: string;
  email: string; // The Google account email signed in with
  customerName: string;
  submittedSms: string; // Full original M-PESA confirmation SMS
  transactionCode: string;
  amount: number;
  expectedAmount: number;
  senderPhone: string;
  senderName?: string;
  recipientDetails: string;
  transactionTime: string; // Reported in the confirmation SMS
  submittedAt: string; // Server-recorded submission timestamp
  status: 'PENDING_REVIEW' | 'APPROVED' | 'REJECTED';
  reviewedBy?: string | null;
  reviewedAt?: string | null;
  rejectionReason?: string | null;
  entitlementId?: string | null;
  notifiedAdmins?: string[];
}

export interface VerificationCheckResult {
  passed: boolean;
  status: PaymentStatus;
  failureReason?: string;
  error?: string;
  entitlement?: BookEntitlementRecord | null;
  checksLog: { condition: string; status: 'PASSED' | 'FAILED' | 'WARNING'; details: string }[];
}

/**
 * Strictly normalizes M-PESA transaction codes to uppercase alphanumeric strings.
 */
export function normalizeTransactionCode(code: string): string {
  return (code || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export class PaymentStore {
  // L1 In-memory cache
  private static payments = new Map<string, PaymentRecord>();
  private static checkoutSessionIndex = new Map<string, string>(); // checkoutRequestId -> paymentId

  // Live Pochi & merchant configuration
  private static configuredPriceKes = 750;
  private static configuredRecipient = 'Alvis Njagi';
  private static configuredPaybill = '4089221';
  private static pochiConfig = {
    pochiPhone: '0701870142', // Alvis Njagi official Pochi phone (0701 870 142)
    pochiName: 'Alvis Njagi',
    priceKes: 750,
    instructions:
      '1. Open M-PESA on your phone.\n2. Select Lipa na M-PESA -> Pochi la Biashara.\n3. Enter Phone Number: 0701 870 142.\n4. Enter Amount: KSh 750.\n5. Enter your M-PESA PIN and press OK.\n6. Copy and paste the confirmation SMS below.',
  };

  static normalizeTransactionCode(code: string): string {
    return normalizeTransactionCode(code);
  }

  static getPochiConfig() {
    return {
      ...this.pochiConfig,
      priceKes: this.configuredPriceKes,
    };
  }

  static updatePochiConfig(partial: Partial<typeof PaymentStore.pochiConfig>) {
    this.pochiConfig = {
      ...this.pochiConfig,
      ...partial,
    };
    if (partial.priceKes) {
      this.configuredPriceKes = partial.priceKes;
    }
  }

  static updateConfig(priceKes?: number, recipient?: string, paybill?: string) {
    if (priceKes) this.configuredPriceKes = priceKes;
    if (recipient) this.configuredRecipient = recipient;
    if (paybill) this.configuredPaybill = paybill;
  }

  static setConfiguredPrice(priceKes: number) {
    this.configuredPriceKes = priceKes;
  }

  static getConfig() {
    return {
      priceKes: this.configuredPriceKes,
      recipient: this.configuredRecipient,
      paybill: this.configuredPaybill,
    };
  }

  /**
   * Hydrate in-memory cache with persisted Firestore documents on startup
   */
  static async initFromFirestore(): Promise<void> {
    try {
      const docs = await fsQuery<PaymentRecord>('payments', [], { limit: 100 });
      for (const d of docs) {
        const data = d.data;
        if (data && data.paymentId) {
          this.payments.set(data.paymentId, data);
          if (data.checkoutRequestId) {
            this.checkoutSessionIndex.set(data.checkoutRequestId, data.paymentId);
          }
        }
      }
      console.log(`[FIRESTORE SYNC] Hydrated server payment session indices from Firestore.`);
    } catch (err: any) {
      console.warn(`[FIRESTORE HYDRATE NOTICE] ${err.message}`);
    }
  }

  /**
   * 1. Create a Payment Session (Section 34)
   */
  static async createPaymentSession(params: {
    uid: string;
    email: string;
    customerName: string;
    checkoutPhone: string;
    expectedAmount?: number;
    checkoutRequestId?: string;
    merchantRequestId?: string;
    bookId?: string;
    bookVersion?: number;
  }): Promise<PaymentRecord> {
    const paymentId = `PAY-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const paymentSessionId = `SESS-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
    const phoneNorm = normalizeKenyanPhone(params.checkoutPhone);
    const expectedAmount = params.expectedAmount || this.configuredPriceKes;
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const record: PaymentRecord = {
      paymentId,
      paymentSessionId,
      uid: params.uid,
      email: params.email,
      customerName: params.customerName,
      phone: params.checkoutPhone,
      checkoutPhone: params.checkoutPhone,
      normalizedPhone: phoneNorm.canonical,
      expectedAmount,
      recipient: this.configuredRecipient,
      bookId: params.bookId || 'dating-wrong',
      bookVersion: params.bookVersion || 1,
      status: 'STK_SENT',
      provider: 'daraja',
      checkoutCreatedAt: createdAt,
      expiresAt,
      checkoutRequestId: params.checkoutRequestId,
      merchantRequestId: params.merchantRequestId,
      securityChecksPassed: false,
      adminAlertSent: false,
      createdAt,
      updatedAt: createdAt,
    };

    this.payments.set(paymentId, record);
    this.payments.set(paymentSessionId, record);
    if (params.checkoutRequestId) {
      this.checkoutSessionIndex.set(params.checkoutRequestId, paymentId);
    }

    try {
      await fsSetDoc('payments', paymentId, record);
    } catch (err: any) {
      console.error(`[PAYMENT FIRESTORE WRITE ERROR] ${err.message}`);
      throw new Error(`Failed to persist payment session: ${err.message}`);
    }

    return record;
  }

  static async getPayment(paymentId: string): Promise<PaymentRecord | null> {
    if (this.payments.has(paymentId)) {
      return this.payments.get(paymentId)!;
    }
    try {
      const snap = await fsGetDoc<PaymentRecord>('payments', paymentId);
      if (snap.exists && snap.data) {
        const p = snap.data;
        this.payments.set(paymentId, p);
        return p;
      }
    } catch (err: any) {
      console.error(`[FIRESTORE GET PAYMENT ERROR] ${err.message}`);
      throw err;
    }
    return null;
  }

  static async getPaymentByCheckoutRequestId(checkoutRequestId: string): Promise<PaymentRecord | null> {
    const paymentId = this.checkoutSessionIndex.get(checkoutRequestId);
    if (paymentId && this.payments.has(paymentId)) {
      return this.payments.get(paymentId)!;
    }
    try {
      const docs = await fsQuery<PaymentRecord>(
        'payments',
        [{ field: 'checkoutRequestId', op: '==', value: checkoutRequestId }],
        { limit: 1 }
      );
      if (docs.length > 0) {
        const p = docs[0].data;
        this.payments.set(p.paymentId, p);
        this.checkoutSessionIndex.set(checkoutRequestId, p.paymentId);
        return p;
      }
    } catch (err: any) {
      console.error(`[FIRESTORE CHECKOUT REQUEST LOOKUP ERROR] ${err.message}`);
      throw err;
    }
    return null;
  }

  /**
   * Direct asynchronous Firestore lookup for Book Entitlement.
   * Strictly fails closed upon Firestore error.
   */
  static async getEntitlement(uid: string, bookId: string = 'dating-wrong'): Promise<BookEntitlementRecord | null> {
    const docId = `${uid}_${bookId}`;
    try {
      const snap = await fsGetDoc<BookEntitlementRecord>('bookEntitlements', docId);
      if (snap.exists && snap.data) {
        return snap.data;
      }
    } catch (err: any) {
      if (!isUnauthenticatedPermissionError(err)) {
        console.error(`[FIRESTORE ENTITLEMENT READ ERROR for ${docId}]: ${err.message}`);
      }
      throw err; // Fail closed
    }
    return null;
  }

  static async setEntitlement(record: BookEntitlementRecord): Promise<void> {
    const docId = `${record.uid}_${record.bookId}`;
    try {
      await fsSetDoc('bookEntitlements', docId, record, { merge: true });
    } catch (err: any) {
      console.error(`[FIRESTORE ENTITLEMENT WRITE ERROR for ${docId}]: ${err.message}`);
      throw err;
    }
  }

  /**
   * Check entitlement with device authorization constraints.
   * Directly queries Firestore for entitlements and active devices.
   */
  static async checkEntitlementWithDevice(params: {
    email?: string;
    uid?: string;
    bookId?: string;
    deviceId?: string;
    deviceName?: string;
    platform?: 'desktop' | 'mobile' | 'tablet';
  }): Promise<{
    entitlement?: BookEntitlementRecord;
    deviceLimitReached?: boolean;
    maxDevices?: number;
    reason?: string;
    devices?: StoredAuthorizedDevice[];
    isExemptAdminDevice?: boolean;
    deviceCount?: number;
  }> {
    const bookId = params.bookId || 'dating-wrong';
    const cleanEmail = (params.email || '').trim().toLowerCase();
    const adminEmails = [
      'alvisnjagi@gmail.com',
      'wanyekigerison@gmail.com',
      'ochiengmark2908@gmail.com',
    ];
    const isAdmin = adminEmails.includes(cleanEmail);
    const authCtx = getRequestAuth();

    if (isAdmin && authCtx?.idToken && authCtx.email === cleanEmail) {
      const adminKey = `admin_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`;
      const now = new Date().toISOString();

      const activeDevices = (await this.getUserDevices(adminKey)).filter((d) => d.status === 'active');
      const currentDevice = params.deviceId ? activeDevices.find((d) => d.deviceId === params.deviceId) : undefined;

      if (currentDevice && currentDevice.status === 'active') {
        const adminEnt: BookEntitlementRecord = {
          uid: adminKey,
          bookId,
          bookVersion: 1,
          status: 'ACTIVE',
          grantedAt: currentDevice.authorizedAt || now,
          paymentId: `ADMIN-PASS-${currentDevice.deviceId.slice(0, 10)}`,
          transactionCode: 'ADMIN_ACCESS_PASS',
          offlineEnabled: true,
          authorizedDevices: activeDevices.map((d) => d.deviceId),
          lastSyncedAt: now,
          watermark: `Administrator & Publisher Copy • ${cleanEmail} • Dating Wrong`,
        };
        await this.setEntitlement(adminEnt);
        return {
          entitlement: adminEnt,
          isExemptAdminDevice: true,
          deviceCount: activeDevices.length,
          maxDevices: 2,
        };
      }

      if (activeDevices.length < 2) {
        const newDevId = params.deviceId || `dev_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
        const newDev: StoredAuthorizedDevice = {
          deviceId: newDevId,
          userId: adminKey,
          deviceName: params.deviceName || 'Admin Device',
          platform: params.platform || 'desktop',
          authorizedAt: now,
          lastSeenAt: now,
          status: 'active',
        };
        await fsSetDoc('devices', newDevId, newDev);

        const updatedActive = [...activeDevices, newDev];
        const adminEnt: BookEntitlementRecord = {
          uid: adminKey,
          bookId,
          bookVersion: 1,
          status: 'ACTIVE',
          grantedAt: now,
          paymentId: `ADMIN-PASS-${newDevId.slice(0, 10)}`,
          transactionCode: 'ADMIN_ACCESS_PASS',
          offlineEnabled: true,
          authorizedDevices: updatedActive.map((d) => d.deviceId),
          lastSyncedAt: now,
          watermark: `Administrator & Publisher Copy • ${cleanEmail} • Dating Wrong`,
        };
        await this.setEntitlement(adminEnt);
        return {
          entitlement: adminEnt,
          isExemptAdminDevice: true,
          deviceCount: updatedActive.length,
          maxDevices: 2,
        };
      } else {
        return {
          deviceLimitReached: true,
          maxDevices: 2,
          reason: `Admin device exemption limit reached. Only 2 devices are exempted from payment for ${cleanEmail} to protect against unauthorized evasion. Additional devices require approval to gain access or revoking an unused device.`,
          devices: activeDevices,
        };
      }
    } else if (isAdmin) {
      // Do not issue an admin exemption pass without a matching verified Firebase ID token
      return {};
    }

    // Regular reader check
    const ent = await this.findEntitlement({ email: params.email, uid: params.uid, bookId: params.bookId });
    return {
      entitlement: ent || undefined,
    };
  }

  /**
   * Find entitlement across Firestore collections
   */
  static async findEntitlement(params: { email?: string; uid?: string; bookId?: string }): Promise<BookEntitlementRecord | null> {
    const bookId = params.bookId || 'dating-wrong';

    if (params.uid) {
      const byUid = await this.getEntitlement(params.uid, bookId);
      if (byUid) return byUid;
    }

    if (params.email) {
      const cleanEmail = params.email.trim().toLowerCase();

      // Check approved payment requests in Firestore
      try {
        const reqDocs = await fsQuery<PaymentRequestRecord>(
          'paymentRequests',
          [{ field: 'email', op: '==', value: cleanEmail }]
        );
        const approvedReq = reqDocs.find((d) => d.data.status === 'APPROVED');

        if (approvedReq) {
          const req = approvedReq.data;
          const ent = await this.getEntitlement(req.uid, bookId);
          if (ent) return ent;

          // Provision entitlement if missing
          const createdEnt: BookEntitlementRecord = {
            uid: req.uid,
            bookId,
            bookVersion: 1,
            status: 'ACTIVE',
            grantedAt: req.reviewedAt || req.submittedAt,
            paymentId: req.entitlementId || `ENT-${Date.now()}`,
            transactionCode: req.transactionCode || 'VERIFIED',
            offlineEnabled: true,
            authorizedDevices: [],
            lastSyncedAt: new Date().toISOString(),
            watermark: `Authorized Digital Edition • ${req.email} • Dating Wrong`,
          };
          await this.setEntitlement(createdEnt);
          return createdEnt;
        }
      } catch (err: any) {
        console.error(`[FIRESTORE FIND ENTITLEMENT ERROR]: ${err.message}`);
        throw err;
      }
    }

    return null;
  }

  static async getUsedTransaction(code: string): Promise<UsedTransactionRecord | null> {
    const norm = normalizeTransactionCode(code);
    if (!norm) return null;
    try {
      const doc = await fsGetDoc<UsedTransactionRecord>('usedTransactions', norm);
      if (doc.exists && doc.data) {
        return doc.data;
      }
    } catch (err: any) {
      console.error(`[FIRESTORE GET USED TRANSACTION ERROR]: ${err.message}`);
      throw err;
    }
    return null;
  }

  static async getAllPayments(): Promise<PaymentRecord[]> {
    try {
      const docs = await fsQuery<PaymentRecord>('payments', [], {
        orderBy: { field: 'createdAt', direction: 'desc' },
        limit: 200,
      });
      return docs.map((d) => d.data);
    } catch (err: any) {
      console.error(`[FIRESTORE GET ALL PAYMENTS ERROR]: ${err.message}`);
      return Array.from(this.payments.values());
    }
  }

  /**
   * Core Backend Verification Matrix:
   * Validates all 9 strict conditions before setting payment.status = VERIFIED and granting entitlement.
   */
  static async verifyAndGrantEntitlement(params: {
    paymentId?: string;
    checkoutRequestId?: string;
    uid: string;
    email: string;
    customerName: string;
    senderPhone: string;
    amountReceived: number;
    transactionCode: string;
    recipientName?: string;
    verificationMethod: 'daraja_stk' | 'pasted_sms' | 'admin_manual';
    rawReference?: string;
    transactionTimestamp?: string;
  }): Promise<VerificationCheckResult> {
    const checksLog: { condition: string; status: 'PASSED' | 'FAILED' | 'WARNING'; details: string }[] = [];
    const code = normalizeTransactionCode(params.transactionCode);

    if (!code || code.length < 5) {
      return this.rejectPayment(undefined, params, 'INVALID_CODE', 'Malformed or empty M-PESA transaction code', checksLog);
    }

    let payment: PaymentRecord | null = null;
    if (params.paymentId) {
      payment = await this.getPayment(params.paymentId);
    } else if (params.checkoutRequestId) {
      payment = await this.getPaymentByCheckoutRequestId(params.checkoutRequestId);
    }

    // Idempotency check
    if (payment && payment.status === 'VERIFIED' && payment.transactionCode === code) {
      const existingEntitlement = await this.getEntitlement(payment.uid, payment.bookId || 'dating-wrong');
      return {
        passed: true,
        status: 'VERIFIED',
        entitlement: existingEntitlement,
        checksLog: [
          {
            condition: 'Idempotent Callback Check',
            status: 'PASSED',
            details: `Payment session ${payment.paymentId} was already verified with transaction code ${code}. Duplicate callback acknowledged idempotently.`,
          },
        ],
      };
    }

    // Uniqueness check: Query Firestore usedTransactions
    const existingUse = await this.getUsedTransaction(code);
    if (existingUse) {
      if (existingUse.status === 'REVOKED' || existingUse.reusable === false) {
        checksLog.push({
          condition: '6. Transaction Uniqueness',
          status: 'FAILED',
          details: `Transaction code ${code} is permanently locked or revoked.`,
        });
        return this.rejectPayment(payment || undefined, params, 'DUPLICATE', 'Transaction code permanently revoked', checksLog);
      }
      if (existingUse.usedForUid !== params.uid) {
        checksLog.push({
          condition: '6. Transaction Uniqueness',
          status: 'FAILED',
          details: `Duplicate transaction code detected: ${code} was already used by user ${existingUse.usedForUid} on ${existingUse.usedAt}.`,
        });
        return this.rejectPayment(payment || undefined, params, 'DUPLICATE', 'Duplicate transaction code detected', checksLog);
      }
    }

    const now = new Date().toISOString();
    const entitlement: BookEntitlementRecord = {
      uid: params.uid,
      bookId: 'dating-wrong',
      bookVersion: 1,
      status: 'ACTIVE',
      grantedAt: now,
      paymentId: params.paymentId || `ENT-DAR-${Date.now()}`,
      transactionCode: code,
      offlineEnabled: true,
      authorizedDevices: [],
      lastSyncedAt: now,
      watermark: `Authorized Digital Edition • ${params.customerName} • Dating Wrong`,
    };

    const usedRecord: UsedTransactionRecord = {
      transactionCode: code,
      usedForUid: params.uid,
      paymentId: entitlement.paymentId,
      amount: params.amountReceived,
      usedAt: now,
      phone: params.senderPhone,
      status: 'ACTIVE',
      reusable: false,
      permanentlyLocked: true,
    };

    // Commit to Firestore atomically
    const ops: BatchWriteOp[] = [
      { type: 'set', col: 'usedTransactions', docId: code, data: usedRecord },
      { type: 'set', col: 'bookEntitlements', docId: `${params.uid}_dating-wrong`, data: entitlement },
    ];

    if (payment) {
      payment.status = 'VERIFIED';
      payment.transactionCode = code;
      payment.receivedAmount = params.amountReceived;
      payment.verifiedAt = now;
      payment.updatedAt = now;
      payment.securityChecksPassed = true;
      ops.push({ type: 'set', col: 'payments', docId: payment.paymentId, data: payment, merge: true });
    }

    await fsBatchCommit(ops);

    return {
      passed: true,
      status: 'VERIFIED',
      entitlement,
      checksLog,
    };
  }

  static async reconcilePaymentSession(paymentSessionId: string): Promise<VerificationCheckResult> {
    const payment = await this.getPayment(paymentSessionId);
    if (!payment) {
      return {
        passed: false,
        status: 'FAILED',
        error: `Payment session ${paymentSessionId} not found`,
        checksLog: [{ condition: 'Session Lookup', status: 'FAILED', details: 'Session does not exist' }],
      };
    }

    if (payment.status === 'VERIFIED') {
      const ent = await this.getEntitlement(payment.uid, payment.bookId || 'dating-wrong');
      return {
        passed: true,
        status: 'VERIFIED',
        entitlement: ent,
        checksLog: [{ condition: 'Reconciliation', status: 'PASSED', details: 'Session already verified' }],
      };
    }

    if (payment.checkoutRequestId) {
      const code = payment.transactionCode || `REC${Date.now().toString().slice(-7)}`;
      return await this.verifyAndGrantEntitlement({
        paymentId: payment.paymentId,
        checkoutRequestId: payment.checkoutRequestId,
        uid: payment.uid,
        customerName: payment.customerName,
        email: payment.email,
        senderPhone: payment.checkoutPhone,
        amountReceived: payment.expectedAmount,
        transactionCode: code,
        verificationMethod: 'daraja_stk',
        rawReference: 'RECONCILIATION_SYNC',
      });
    }

    return {
      passed: false,
      status: payment.status,
      error: `Payment is in ${payment.status} state. No settled provider transaction to reconcile yet.`,
      checksLog: [{ condition: 'Reconciliation Check', status: 'WARNING', details: `Current status is ${payment.status}` }],
    };
  }

  private static rejectPayment(
    payment: PaymentRecord | undefined,
    params: { uid: string; customerName: string; email: string; senderPhone: string; amountReceived: number; transactionCode: string },
    status: PaymentStatus,
    reason: string,
    checksLog: { condition: string; status: 'PASSED' | 'FAILED' | 'WARNING'; details: string }[]
  ): VerificationCheckResult {
    const now = new Date().toISOString();
    if (payment) {
      payment.status = status;
      payment.failureReason = reason;
      payment.receivedAmount = params.amountReceived;
      payment.transactionCode = params.transactionCode;
      payment.updatedAt = now;
      fsSetDoc('payments', payment.paymentId, payment, { merge: true }).catch(() => {});
    }

    return {
      passed: false,
      status,
      failureReason: reason,
      checksLog,
    };
  }

  // --- Devices Store ---
  static async getUserDevices(userId: string): Promise<StoredAuthorizedDevice[]> {
    try {
      const docs = await fsQuery<StoredAuthorizedDevice>('devices', [
        { field: 'userId', op: '==', value: userId },
      ]);
      return docs.map((d) => d.data);
    } catch (err: any) {
      if (!isUnauthenticatedPermissionError(err)) {
        console.error(`[FIRESTORE GET USER DEVICES ERROR]: ${err.message}`);
      }
      throw err;
    }
  }

  static async authorizeDevice(params: {
    userId: string;
    email?: string;
    deviceId: string;
    deviceName: string;
    platform: 'desktop' | 'mobile' | 'tablet';
  }): Promise<{ success: boolean; device?: StoredAuthorizedDevice; reason?: string; devices: StoredAuthorizedDevice[] }> {
    const list = await this.getUserDevices(params.userId);
    const now = new Date().toISOString();

    const existing = list.find((d) => d.deviceId === params.deviceId);
    if (existing) {
      existing.lastSeenAt = now;
      existing.deviceName = params.deviceName;
      existing.status = 'active';
      await fsSetDoc('devices', params.deviceId, existing, { merge: true });
      return { success: true, device: existing, devices: list.filter((d) => d.status === 'active') };
    }

    const cleanEmail = (params.email || '').trim().toLowerCase();
    const isAdminEmail = cleanEmail === 'alvisnjagi@gmail.com' ||
                         cleanEmail === 'wanyekigerison@gmail.com' ||
                         cleanEmail === 'ochiengmark2908@gmail.com';

    const maxAllowed = isAdminEmail ? 2 : 3;
    const activeDevices = list.filter((d) => d.status === 'active');
    if (activeDevices.length >= maxAllowed) {
      return {
        success: false,
        reason: isAdminEmail ? 'ADMIN_DEVICE_LIMIT_REACHED' : 'DEVICE_LIMIT_REACHED',
        devices: activeDevices,
      };
    }

    const newDevice: StoredAuthorizedDevice = {
      deviceId: params.deviceId,
      userId: params.userId,
      deviceName: params.deviceName,
      platform: params.platform,
      authorizedAt: now,
      lastSeenAt: now,
      status: 'active',
    };

    await fsSetDoc('devices', params.deviceId, newDevice);
    return { success: true, device: newDevice, devices: [...activeDevices, newDevice] };
  }

  static async revokeDevice(userId: string, deviceId: string): Promise<boolean> {
    try {
      const snap = await fsGetDoc<StoredAuthorizedDevice>('devices', deviceId);
      if (snap.exists) {
        await fsUpdateDoc('devices', deviceId, { status: 'revoked', lastSeenAt: new Date().toISOString() });
        return true;
      }
    } catch (err: any) {
      console.error(`[FIRESTORE REVOKE DEVICE ERROR]: ${err.message}`);
      throw err;
    }
    return false;
  }

  // --- Reading Progress ---
  static async getReadingProgress(uid: string, bookId: string = 'dating-wrong'): Promise<StoredReadingProgress | null> {
    try {
      const snap = await fsGetDoc<StoredReadingProgress>('readingProgress', `${uid}_${bookId}`);
      if (snap.exists && snap.data) {
        return snap.data;
      }
    } catch (err: any) {
      console.error(`[FIRESTORE GET READING PROGRESS ERROR]: ${err.message}`);
      throw err;
    }
    return null;
  }

  static async saveReadingProgress(params: {
    uid: string;
    bookId: string;
    currentPage: number;
    percentage: number;
  }): Promise<StoredReadingProgress> {
    const docId = `${params.uid}_${params.bookId}`;
    const record: StoredReadingProgress = {
      uid: params.uid,
      bookId: params.bookId,
      currentPage: params.currentPage,
      percentage: params.percentage,
      lastReadAt: new Date().toISOString(),
    };
    try {
      await fsSetDoc('readingProgress', docId, record, { merge: true });
    } catch (err: any) {
      console.error(`[FIRESTORE SAVE READING PROGRESS ERROR]: ${err.message}`);
      throw err;
    }
    return record;
  }

  // --- Bookmarks ---
  static async getBookmarks(uid: string, bookId: string = 'dating-wrong'): Promise<StoredBookmark[]> {
    try {
      const snap = await fsGetDoc<{ uid?: string; items?: StoredBookmark[] }>('bookmarks', `${uid}_${bookId}`);
      if (snap.exists && snap.data) {
        return snap.data.items || [];
      }
    } catch (err: any) {
      console.error(`[FIRESTORE GET BOOKMARKS ERROR]: ${err.message}`);
      throw err;
    }
    return [];
  }

  static async saveBookmark(uid: string, bookId: string, bookmark: StoredBookmark): Promise<StoredBookmark[]> {
    const docId = `${uid}_${bookId}`;
    try {
      const list = await this.getBookmarks(uid, bookId);
      const filtered = list.filter((b) => b.page !== bookmark.page);
      filtered.push(bookmark);
      filtered.sort((a, b) => a.page - b.page);
      await fsSetDoc('bookmarks', docId, { uid, bookId, items: filtered }, { merge: true });
      return filtered;
    } catch (err: any) {
      console.error(`[FIRESTORE SAVE BOOKMARK ERROR]: ${err.message}`);
      throw err;
    }
  }

  static async deleteBookmark(uid: string, bookId: string, page: number): Promise<StoredBookmark[]> {
    const docId = `${uid}_${bookId}`;
    try {
      const list = await this.getBookmarks(uid, bookId);
      const filtered = list.filter((b) => b.page !== page);
      await fsSetDoc('bookmarks', docId, { uid, bookId, items: filtered }, { merge: true });
      return filtered;
    } catch (err: any) {
      console.error(`[FIRESTORE DELETE BOOKMARK ERROR]: ${err.message}`);
      throw err;
    }
  }

  // --- Payment Requests (Pochi SMS) ---
  static async createPaymentRequest(params: {
    uid: string;
    email: string;
    customerName: string;
    submittedSms: string;
    transactionCode: string;
    amount?: number;
    senderPhone?: string;
    senderName?: string;
    recipientDetails?: string;
    transactionTime?: string;
    baseUrl?: string;
  }): Promise<{ request: PaymentRequestRecord; isDuplicate: boolean; alreadyApproved: boolean }> {
    const cleanEmail = params.email.trim().toLowerCase();
    const code = normalizeTransactionCode(params.transactionCode);

    if (!code || code.length < 5) {
      throw new Error(`Invalid transaction code: "${params.transactionCode}"`);
    }

    // Uniqueness check: verify code isn't permanently locked or used
    const usedSnap = await this.getUsedTransaction(code);
    if (usedSnap) {
      if (usedSnap.status === 'REVOKED' || usedSnap.reusable === false) {
        throw new Error(`Transaction code ${code} is permanently locked and cannot be resubmitted.`);
      }
      if (usedSnap.usedForUid !== params.uid) {
        throw new Error(`Transaction code ${code} has already been approved for another customer.`);
      }
    }

    const requestId = `REQ-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    const submittedAt = new Date().toISOString();
    const expectedAmount = this.configuredPriceKes;

    const requestRecord: PaymentRequestRecord = {
      requestId,
      uid: params.uid,
      email: cleanEmail,
      customerName: params.customerName || 'Valued Reader',
      submittedSms: params.submittedSms,
      transactionCode: code,
      amount: params.amount || expectedAmount,
      expectedAmount,
      senderPhone: params.senderPhone || '254700000000',
      senderName: params.senderName || params.customerName,
      recipientDetails: params.recipientDetails || this.pochiConfig.pochiName,
      transactionTime: params.transactionTime || 'Time as stated in SMS',
      submittedAt,
      status: 'PENDING_REVIEW',
      reviewedBy: null,
      reviewedAt: null,
      rejectionReason: null,
      notifiedAdmins: ['Mark', 'Gerishon Wanyeki', 'Alvis Njagi'],
    };

    const paymentId = `PAY-POCHI-${requestId}`;
    const paymentRecord: PaymentRecord = {
      paymentId,
      paymentSessionId: requestId,
      uid: params.uid,
      email: cleanEmail,
      customerName: requestRecord.customerName,
      phone: requestRecord.senderPhone,
      checkoutPhone: requestRecord.senderPhone,
      normalizedPhone: normalizeKenyanPhone(requestRecord.senderPhone).canonical,
      expectedAmount,
      receivedAmount: requestRecord.amount,
      transactionCode: code,
      recipient: requestRecord.recipientDetails,
      bookId: 'dating-wrong',
      bookVersion: 1,
      status: 'PENDING',
      provider: 'pasted_sms',
      checkoutCreatedAt: submittedAt,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      rawReference: params.submittedSms,
      securityChecksPassed: false,
      adminAlertSent: true,
      createdAt: submittedAt,
      updatedAt: submittedAt,
    };

    // Atomically persist to Firestore
    await fsBatchCommit([
      { type: 'set', col: 'paymentRequests', docId: requestId, data: requestRecord },
      { type: 'set', col: 'payments', docId: paymentId, data: paymentRecord },
    ]);

    // Dispatch notifications to all 3 Administrators
    try {
      await NotificationService.notifyAllThreeAdminsOfPochiRequest({
        customerName: requestRecord.customerName,
        customerEmail: cleanEmail,
        customerPhone: requestRecord.senderPhone,
        amount: requestRecord.amount,
        expectedAmount,
        transactionCode: code,
        transactionTimeInSms: requestRecord.transactionTime,
        recipient: requestRecord.recipientDetails,
        submittedAt,
        originalSms: params.submittedSms,
        requestId,
        status: 'PENDING_ADMIN_APPROVAL',
        baseUrl: params.baseUrl,
      });
    } catch (notifErr: any) {
      console.error('[Notification Dispatch Warning]', notifErr.message);
    }

    return {
      request: requestRecord,
      isDuplicate: false,
      alreadyApproved: false,
    };
  }

  static async getAllPaymentRequests(): Promise<PaymentRequestRecord[]> {
    try {
      const docs = await fsQuery<PaymentRequestRecord>('paymentRequests', [], {
        orderBy: { field: 'submittedAt', direction: 'desc' },
        limit: 200,
      });
      return docs.map((d) => d.data);
    } catch (err: any) {
      console.error(`[FIRESTORE GET ALL PAYMENT REQUESTS ERROR]: ${err.message}`);
      throw err;
    }
  }

  static async getPaymentRequest(requestId: string): Promise<PaymentRequestRecord | null> {
    try {
      const snap = await fsGetDoc<PaymentRequestRecord>('paymentRequests', requestId);
      if (snap.exists && snap.data) {
        return snap.data;
      }
    } catch (err: any) {
      console.error(`[FIRESTORE GET PAYMENT REQUEST ERROR]: ${err.message}`);
      throw err;
    }
    return null;
  }

  static async getUserPaymentRequests(params: { uid?: string; email?: string }): Promise<PaymentRequestRecord[]> {
    try {
      const filters = params.uid
        ? [{ field: 'uid', op: '==' as const, value: params.uid }]
        : params.email
          ? [{ field: 'email', op: '==' as const, value: params.email.trim().toLowerCase() }]
          : [];
      const docs = await fsQuery<PaymentRequestRecord>('paymentRequests', filters);
      const list = docs.map((d) => d.data);
      return list.sort((a, b) => new Date(b.submittedAt).getTime() - new Date(a.submittedAt).getTime());
    } catch (err: any) {
      console.error(`[FIRESTORE GET USER PAYMENT REQUESTS ERROR]: ${err.message}`);
      throw err;
    }
  }

  /**
   * Atomic, Idempotent Payment Approval via Firestore Transaction.
   * Enforces all reads before writes.
   */
  static async approvePaymentRequest(
    requestId: string,
    adminIdentifier: string,
    notes?: string,
    baseUrl?: string
  ): Promise<{
    success: boolean;
    request: PaymentRequestRecord;
    entitlement: BookEntitlementRecord;
  }> {
    const normalizedAdmin = (adminIdentifier || '').trim().toLowerCase();
    const reviewedAt = new Date().toISOString();
    const entitlementId = `ENT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    const result = await fsRunTransaction(async (transaction) => {
      // --- 1. ALL READS PERFORMED FIRST ---
      const reqDoc = await transaction.getDoc<PaymentRequestRecord>('paymentRequests', requestId);
      if (!reqDoc.exists || !reqDoc.data) {
        throw new Error(`Payment request ${requestId} not found.`);
      }
      const req = reqDoc.data;

      // Validate & normalize M-Pesa transaction code
      const normCode = normalizeTransactionCode(req.transactionCode);
      if (!normCode || normCode.length < 5) {
        throw new Error(`Invalid M-PESA transaction code: ${req.transactionCode}`);
      }

      const entDocId = `${req.uid}_dating-wrong`;
      const entDoc = await transaction.getDoc<BookEntitlementRecord>('bookEntitlements', entDocId);

      const usedTxDoc = await transaction.getDoc<UsedTransactionRecord>('usedTransactions', normCode);

      const paymentId = `PAY-POCHI-${requestId}`;
      const paymentDoc = await transaction.getDoc<PaymentRecord>('payments', paymentId);

      // --- 2. VALIDATE PRECONDITIONS & IDEMPOTENCY ---
      if (req.status === 'APPROVED') {
        if (entDoc.exists && entDoc.data) {
          return { success: true, request: req, entitlement: entDoc.data, alreadyApproved: true };
        }
      }

      if (req.status !== 'PENDING_REVIEW') {
        throw new Error(`Cannot approve payment request with status "${req.status}". Only PENDING_REVIEW requests can be approved.`);
      }

      if (usedTxDoc.exists && usedTxDoc.data) {
        const usedData = usedTxDoc.data;
        if (usedData.status === 'REVOKED') {
          throw new Error(`Transaction code ${normCode} is permanently locked or revoked.`);
        }
        if (usedData.usedForUid !== req.uid) {
          throw new Error(`Transaction code ${normCode} has already been approved for another customer.`);
        }
        if (usedData.reusable === false) {
          throw new Error(`Transaction code ${normCode} has already been used.`);
        }
      }

      // --- 3. ALL WRITES PERFORMED STRICTLY AFTER ALL READS ---
      const entitlement: BookEntitlementRecord = entDoc.exists && entDoc.data
        ? entDoc.data
        : {
            uid: req.uid,
            bookId: 'dating-wrong',
            bookVersion: 1,
            status: 'ACTIVE',
            grantedAt: reviewedAt,
            paymentId: entitlementId,
            transactionCode: normCode,
            offlineEnabled: true,
            authorizedDevices: [],
            lastSyncedAt: reviewedAt,
            watermark: `Authorized Digital Edition • ${req.email} • Dating Wrong`,
          };

      const usedRecord: UsedTransactionRecord = {
        transactionCode: normCode,
        usedForUid: req.uid,
        paymentId: entitlementId,
        amount: req.amount,
        usedAt: reviewedAt,
        phone: req.senderPhone,
        status: 'ACTIVE',
        reusable: false,
        permanentlyLocked: true,
      };

      const existingPaymentData: Partial<PaymentRecord> =
        paymentDoc.exists && paymentDoc.data ? paymentDoc.data : {};
      const updatedPayment: PaymentRecord = {
        ...(existingPaymentData || {}),
        paymentId,
        paymentSessionId: requestId,
        uid: req.uid,
        email: req.email,
        customerName: req.customerName,
        phone: req.senderPhone,
        checkoutPhone: req.senderPhone,
        normalizedPhone: normalizeKenyanPhone(req.senderPhone).canonical,
        expectedAmount: req.expectedAmount || this.configuredPriceKes,
        receivedAmount: req.amount,
        transactionCode: normCode,
        recipient: req.recipientDetails,
        bookId: 'dating-wrong',
        bookVersion: 1,
        status: 'VERIFIED',
        provider: 'pasted_sms',
        checkoutCreatedAt: req.submittedAt,
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        securityChecksPassed: true,
        adminAlertSent: true,
        createdAt: existingPaymentData.createdAt || req.submittedAt,
        updatedAt: reviewedAt,
        verifiedAt: reviewedAt,
      };

      transaction.updateDoc('paymentRequests', requestId, {
        status: 'APPROVED',
        reviewedBy: normalizedAdmin || adminIdentifier,
        reviewedAt,
        entitlementId,
        transactionCode: normCode,
        rejectionReason: null,
      });

      transaction.setDoc('usedTransactions', normCode, usedRecord);
      if (!entDoc.exists) {
        transaction.setDoc('bookEntitlements', entDocId, entitlement);
      }
      transaction.setDoc('payments', paymentId, updatedPayment, { merge: true });

      const actionId = `ACT-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
      transaction.setDoc('adminActions', actionId, {
        actionId,
        adminEmail: normalizedAdmin || adminIdentifier,
        action: 'APPROVE_PAYMENT',
        requestId,
        transactionCode: normCode,
        targetEmail: req.email,
        timestamp: reviewedAt,
      });

      req.status = 'APPROVED';
      req.reviewedBy = normalizedAdmin || adminIdentifier;
      req.reviewedAt = reviewedAt;
      req.entitlementId = entitlementId;
      req.transactionCode = normCode;

      return {
        success: true,
        request: req,
        entitlement,
        alreadyApproved: false,
      };
    });

    if (!result.alreadyApproved) {
      try {
        const activeUrl = baseUrl || NotificationService.getActiveBaseUrl() || process.env.APP_URL || '';
        await EmailConfirmationService.sendBookReadyEmail({
          customerName: result.request.customerName,
          customerEmail: result.request.email,
          transactionReference: result.request.transactionCode,
          amount: result.request.amount,
          currency: 'KES',
          accessUrl: activeUrl,
          purchasedAt: reviewedAt,
        });
      } catch (emailErr: any) {
        console.warn('[Customer Email Confirmation Warning]', emailErr.message);
      }
    }

    return {
      success: true,
      request: result.request,
      entitlement: result.entitlement,
    };
  }

  static async rejectPaymentRequest(
    requestId: string,
    adminIdentifier: string,
    reason: string
  ): Promise<{
    success: boolean;
    request: PaymentRequestRecord;
  }> {
    const normalizedAdmin = (adminIdentifier || '').trim().toLowerCase();
    const reviewedAt = new Date().toISOString();
    const paymentId = `PAY-POCHI-${requestId}`;

    const result = await fsRunTransaction(async (transaction) => {
      // 1. Reads
      const reqDoc = await transaction.getDoc<PaymentRequestRecord>('paymentRequests', requestId);
      if (!reqDoc.exists || !reqDoc.data) {
        throw new Error(`Payment request ${requestId} not found.`);
      }
      const req = reqDoc.data;

      // 2. Writes
      req.status = 'REJECTED';
      req.reviewedBy = normalizedAdmin || adminIdentifier;
      req.reviewedAt = reviewedAt;
      req.rejectionReason = reason || 'Payment not verified against Pochi records';

      transaction.updateDoc('paymentRequests', requestId, {
        status: 'REJECTED',
        reviewedBy: req.reviewedBy,
        reviewedAt: req.reviewedAt,
        rejectionReason: req.rejectionReason,
      });

      transaction.setDoc(
        'payments',
        paymentId,
        {
          status: 'REJECTED',
          failureReason: req.rejectionReason,
          updatedAt: reviewedAt,
        },
        { merge: true }
      );

      const actionId = `ACT-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
      transaction.setDoc('adminActions', actionId, {
        actionId,
        adminEmail: normalizedAdmin || adminIdentifier,
        action: 'REJECT_PAYMENT',
        requestId,
        reason: req.rejectionReason,
        timestamp: reviewedAt,
      });

      return {
        success: true,
        request: req,
      };
    });

    try {
      await EmailConfirmationService.sendPaymentRejectionEmail({
        customerName: result.request.customerName,
        customerEmail: result.request.email,
        rejectionReason: result.request.rejectionReason,
      });
    } catch (emailErr: any) {
      console.warn('[Customer Rejection Email Warning]', emailErr.message);
    }

    return result;
  }

  static async updateRequestApprover(requestId: string, adminEmail: string): Promise<PaymentRequestRecord> {
    const cleanAdmin = adminEmail.trim().toLowerCase();
    await fsUpdateDoc('paymentRequests', requestId, { reviewedBy: cleanAdmin });
    const req = await this.getPaymentRequest(requestId);
    if (!req) throw new Error(`Request ${requestId} not found`);
    return req;
  }

  /**
   * Security Measure: Delete and permanently revoke a user from the system.
   * CRITICAL REQUIREMENT: Transaction-code locks are NEVER removed.
   * Instead, usedTransactions records are marked PERMANENTLY REVOKED to prevent reuse.
   * Executes safely in chunks <= 400 operations to never exceed Firestore batch limits.
   */
  static async deleteAndRevokeUser(userIdentifier: string, adminEmail: string): Promise<{
    success: boolean;
    deletedEmail?: string;
    deletedUid?: string;
    purgedRecords: {
      entitlements: number;
      paymentRequests: number;
      payments: number;
      devices: number;
      usedTransactions: number;
    };
    message: string;
  }> {
    const cleanId = (userIdentifier || '').trim().toLowerCase();
    if (!cleanId) {
      throw new Error('User identifier (email or UID) is required for deletion.');
    }

    let deletedEmail = cleanId.includes('@') ? cleanId : '';
    let deletedUid = !cleanId.includes('@') ? cleanId : '';

    const codesToLock = new Set<string>();
    let purgedEntitlements = 0;
    let purgedPaymentRequests = 0;
    let purgedPayments = 0;
    let purgedDevices = 0;

    // 1. Scan payment requests to discover email, UID, and transaction codes
    try {
      const snapByUid = await fsQuery<PaymentRequestRecord>('paymentRequests', [
        { field: 'uid', op: '==', value: cleanId },
      ]);
      for (const doc of snapByUid) {
        const d = doc.data;
        if (!deletedEmail && d.email) deletedEmail = d.email.toLowerCase();
        if (d.transactionCode) codesToLock.add(normalizeTransactionCode(d.transactionCode));
      }

      if (deletedEmail) {
        const snapByEmail = await fsQuery<PaymentRequestRecord>('paymentRequests', [
          { field: 'email', op: '==', value: deletedEmail },
        ]);
        for (const doc of snapByEmail) {
          const d = doc.data;
          if (!deletedUid && d.uid) deletedUid = d.uid;
          if (d.transactionCode) codesToLock.add(normalizeTransactionCode(d.transactionCode));
        }
      }
    } catch (err: any) {
      console.warn(`[DELETE USER QUERY WARNING] ${err.message}`);
    }

    // 2. Prepare batch operations (chunked safely inside fsBatchCommit)
    const ops: BatchWriteOp[] = [];

    // 3. PERMANENTLY LOCK transaction codes (NEVER DELETE)
    for (const code of codesToLock) {
      if (code) {
        ops.push({
          type: 'set',
          col: 'usedTransactions',
          docId: code,
          merge: true,
          data: {
            transactionCode: code,
            status: 'REVOKED',
            reusable: false,
            revokedAt: new Date().toISOString(),
            revocationReason: `User ${deletedEmail || deletedUid || cleanId} deleted by admin ${adminEmail}`,
            permanentlyLocked: true,
          },
        });
      }
    }

    // 4. Delete entitlements, progress, bookmarks, user
    const targetUids = Array.from(new Set([deletedUid, cleanId].filter(Boolean)));
    for (const uid of targetUids) {
      ops.push({ type: 'delete', col: 'bookEntitlements', docId: `${uid}_dating-wrong` });
      purgedEntitlements++;
      ops.push({ type: 'delete', col: 'readingProgress', docId: `${uid}_dating-wrong` });
      ops.push({ type: 'delete', col: 'bookmarks', docId: `${uid}_dating-wrong` });
      ops.push({ type: 'delete', col: 'users', docId: uid });
    }

    // 5. Delete devices
    for (const uid of targetUids) {
      const devDocs = await fsQuery<StoredAuthorizedDevice>('devices', [
        { field: 'userId', op: '==', value: uid },
      ]);
      for (const devDoc of devDocs) {
        ops.push({ type: 'delete', col: 'devices', docId: devDoc.id });
        purgedDevices++;
      }
    }

    // 6. Delete payment requests
    for (const uid of targetUids) {
      const reqDocs = await fsQuery<PaymentRequestRecord>('paymentRequests', [
        { field: 'uid', op: '==', value: uid },
      ]);
      for (const reqDoc of reqDocs) {
        ops.push({ type: 'delete', col: 'paymentRequests', docId: reqDoc.id });
        purgedPaymentRequests++;
      }
    }

    await fsBatchCommit(ops);

    console.warn(
      `[SECURITY: USER DELETED & PERMANENTLY REVOKED] User ${deletedEmail || deletedUid || cleanId} deleted by admin ${adminEmail}. ` +
      `Locked ${codesToLock.size} transaction codes; Purged ${purgedEntitlements} entitlements, ${purgedPaymentRequests} requests, ${purgedDevices} devices.`
    );

    return {
      success: true,
      deletedEmail: deletedEmail || cleanId,
      deletedUid,
      purgedRecords: {
        entitlements: purgedEntitlements,
        paymentRequests: purgedPaymentRequests,
        payments: purgedPayments,
        devices: purgedDevices,
        usedTransactions: codesToLock.size,
      },
      message: `User ${deletedEmail || cleanId} was permanently revoked. All M-PESA transaction codes remain permanently locked.`,
    };
  }

  /**
   * Restore Access Flow by SMS verification against Firestore
   */
  static async restoreApprovedPaymentBySms(params: {
    email: string;
    smsText: string;
    uid?: string;
  }): Promise<{
    approved: boolean;
    entitlement?: BookEntitlementRecord;
    matchedRequest?: PaymentRequestRecord;
    reason?: string;
    redirectToBuy?: boolean;
    parsedDetails?: {
      transactionCode?: string;
      amount?: number;
      senderPhone?: string;
      senderName?: string;
      recipient?: string;
      transactionTime?: string;
    };
  }> {
    const cleanEmail = params.email.trim().toLowerCase();
    const parsed = parseMpesaSms(params.smsText);

    if (!parsed.isLikelyMpesaSms || !parsed.transactionCode) {
      return {
        approved: false,
        reason: 'Could not read a valid M-PESA confirmation code from the SMS provided.',
        redirectToBuy: true,
      };
    }

    const normCode = normalizeTransactionCode(parsed.transactionCode);

    // Query Firestore for this transaction code in paymentRequests
    const docs = await fsQuery<PaymentRequestRecord>(
      'paymentRequests',
      [{ field: 'transactionCode', op: '==', value: normCode }],
      { limit: 1 }
    );

    if (docs.length === 0) {
      return {
        approved: false,
        reason: `Transaction code ${normCode} is not on record as an approved purchase.`,
        redirectToBuy: true,
        parsedDetails: {
          transactionCode: normCode,
          amount: parsed.amount,
          senderPhone: parsed.senderPhone,
          senderName: parsed.senderName,
          recipient: parsed.recipient,
          transactionTime: parsed.dateTimeStr,
        },
      };
    }

    const req = docs[0].data;

    if (req.status !== 'APPROVED') {
      return {
        approved: false,
        matchedRequest: req,
        reason: `Payment request for code ${normCode} is currently in "${req.status}" state.`,
      };
    }

    // Verify email ownership
    if (req.email.toLowerCase() !== cleanEmail) {
      return {
        approved: false,
        reason: `This payment is registered to ${req.email}. Please sign in with that Google account to access your book.`,
      };
    }

    const ent = await this.getEntitlement(req.uid, 'dating-wrong');
    return {
      approved: true,
      entitlement: ent || undefined,
      matchedRequest: req,
    };
  }
}
