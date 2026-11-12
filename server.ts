import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { MANUSCRIPT_V1 } from './src/data/manuscript-v1.ts';
import { DarajaService } from './server/darajaService.ts';
import { PaymentStore } from './server/paymentStore.ts';
import { NotificationService } from './server/notificationService.ts';
import { EmailConfirmationService } from './server/emailConfirmationService.ts';
import { AccessTicketStore } from './server/accessTicketStore.ts';
import { requireAdminAuth, generateAdminSessionToken, ADMIN_ALLOWLIST } from './server/middleware/auth.ts';
import { adminAuth } from './server/firebaseAdmin.ts';
import { runWithRequestAuth, isUnauthenticatedPermissionError } from './server/firestoreAdapter.ts';
import { verifyPastedMpesaSms } from './src/utils/mpesaSmsParser.ts';
import { normalizeKenyanPhone } from './src/utils/phoneNormalization.ts';

export async function createApp(options: { serveFrontend?: boolean } = {}) {
  const { serveFrontend = true } = options;
  const app = express();
  const portArgIdx = process.argv.indexOf('--port');
  const portFromArgs = portArgIdx !== -1 && process.argv[portArgIdx + 1] ? parseInt(process.argv[portArgIdx + 1], 10) : undefined;
  const PORT = Number(process.env.PORT) || portFromArgs || 3000;

  // Security Hardening: Hide server version, technology stack, and remove all disclosure headers
  app.disable('x-powered-by');

  // Strip disclosure headers and set defensive security headers across ALL responses
  app.use((req, res, next) => {
    const origSetHeader = res.setHeader.bind(res);
    res.setHeader = function (name: string, value: any) {
      const lower = name.toLowerCase();
      if (lower === 'x-powered-by' || lower === 'server') {
        return this;
      }
      return origSetHeader(name, value);
    };

    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  app.use(express.json());

  // Verify caller Firebase ID Token (when provided) and bind to request AsyncLocalStorage
  app.use(async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const idToken = authHeader.substring(7).trim();
      if (idToken) {
        try {
          const decoded = await adminAuth.verifyIdToken(idToken);
          (req as any).firebaseUser = {
            uid: decoded.uid,
            email: (decoded.email || '').trim().toLowerCase(),
            emailVerified: decoded.email_verified === true,
            signInProvider: decoded.firebase?.sign_in_provider || '',
          };
          return runWithRequestAuth(
            {
              uid: decoded.uid,
              email: (decoded.email || '').trim().toLowerCase(),
              idToken,
            },
            () => next()
          );
        } catch {
          // Invalid/expired token — continue without authenticated Firestore context
        }
      }
    }
    return runWithRequestAuth({}, () => next());
  });

  // Automatically detect and configure active Base URL for notification alerts & reader links
  app.use((req, res, next) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
    if (host && typeof host === 'string' && !host.includes('localhost') && !host.includes('127.0.0.1')) {
      const activeUrl = `${proto}://${host}`;
      NotificationService.setActiveBaseUrl(activeUrl);
      EmailConfirmationService.setActiveBaseUrl(activeUrl);
    }
    next();
  });

  // Hydrate persistent data stores from Firestore
  await PaymentStore.initFromFirestore();

  const daraja = new DarajaService();

  // --- API Endpoints ---

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      book: 'Dating Wrong',
      author: 'Gerishon Wanyeki',
      publisher: 'Mark & Alvis',
      timestamp: new Date().toISOString(),
      gateway: 'Safaricom Daraja Express',
      merchantPaybill: PaymentStore.getConfig().paybill,
      adminsConfigured: ADMIN_ALLOWLIST.length,
    });
  });

  // Public book metadata and table of contents
  app.get('/api/book', (req, res) => {
    res.json({
      metadata: MANUSCRIPT_V1.metadata,
      tableOfContents: MANUSCRIPT_V1.sections.map((s) => ({
        id: s.id,
        order: s.order,
        type: s.type,
        numberLabel: s.numberLabel,
        title: s.title,
        subtitle: s.subtitle,
        readingMinutes: s.readingMinutes,
        isFreePreview: ['copyright', 'dedication', 'authors-note', 'introduction'].includes(s.id),
      })),
    });
  });

  // Free preview endpoint (Dedication, Author's Note, and Introduction)
  app.get('/api/book/preview', (req, res) => {
    const previewSections = MANUSCRIPT_V1.sections.filter((s) =>
      ['copyright', 'dedication', 'authors-note', 'introduction'].includes(s.id)
    );
    res.json({
      metadata: MANUSCRIPT_V1.metadata,
      sections: previewSections,
    });
  });

  // Protected reader content endpoint
  // SECURITY REQUIREMENT: Never authorize book access using a client-supplied entitlement ID or phone number alone.
  // Requires a genuine ACTIVE Firestore entitlement or verified non-revoked transaction code.
  app.post('/api/book/content', async (req, res) => {
    try {
      const { transactionCode, uid } = req.body;

      let isEntitled = false;

      if (uid && typeof uid === 'string') {
        const entitlementRecord = await PaymentStore.getEntitlement(uid.trim(), 'dating-wrong');
        if (entitlementRecord && entitlementRecord.status === 'ACTIVE') {
          isEntitled = true;
        }
      }

      if (!isEntitled && transactionCode && typeof transactionCode === 'string') {
        const normalized = PaymentStore.normalizeTransactionCode(transactionCode);
        if (normalized) {
          const used = await PaymentStore.getUsedTransaction(normalized);
          if (used && used.status !== 'REVOKED') {
            isEntitled = true;
          }
        }
      }

      if (!isEntitled) {
        return res.status(403).json({
          error: 'Unauthorized access',
          message: 'A valid entitlement or verified M-PESA purchase is required to read Dating Wrong.',
          book: 'Dating Wrong by Gerishon Wanyeki',
          cta: 'Please complete purchase via M-PESA to unlock the protected reader.',
        });
      }

      res.json({
        success: true,
        metadata: MANUSCRIPT_V1.metadata,
        sections: MANUSCRIPT_V1.sections,
        authorized: true,
      });
    } catch (err: any) {
      console.error('[BOOK CONTENT ERROR]', err.message);
      res.status(500).json({ error: 'Service temporarily unavailable to verify access.' });
    }
  });

  // ==============================================================
  // SINGLE-USE CRYPTOGRAPHIC ACCESS TICKET ENDPOINTS (OTP NONCES)
  // ==============================================================

  // Redeem Customer Reader Single-Use Access Ticket (One-Time Passcode)
  app.post('/api/access-tickets/consume-reader', async (req, res) => {
    try {
      const { ticket, email, uid } = req.body;
      if (!ticket) {
        return res.status(400).json({ success: false, error: 'Access ticket token is required.' });
      }

      const result = await AccessTicketStore.consumeCustomerReaderTicket({
        ticketId: ticket,
        email: email || '',
        uid,
      });

      if (!result.valid) {
        return res.status(403).json({ success: false, error: result.reason });
      }

      res.json({
        success: true,
        entitlement: result.entitlement,
        ticket: {
          targetEmail: result.ticket?.targetEmail,
          requestId: result.ticket?.requestId,
          consumedAt: result.ticket?.consumedAt,
        },
        message: 'Access ticket successfully redeemed and burned. Lifetime reading authorized.',
      });
    } catch (err: any) {
      console.error('[CONSUME READER TICKET ERROR]', err.message);
      res.status(500).json({ success: false, error: 'Service error redeeming ticket.' });
    }
  });

  // Verify and Burn Admin Single-Use Review Ticket (One-Time Passcode)
  app.post('/api/access-tickets/verify-admin', async (req, res) => {
    try {
      const { ticket, authAdmin, currentAuthEmail, requestId } = req.body;
      if (!ticket) {
        return res.status(400).json({ success: false, error: 'Admin ticket token is required.' });
      }

      const result = await AccessTicketStore.verifyAndConsumeAdminTicket({
        ticketId: ticket,
        adminEmail: authAdmin,
        requestingEmail: currentAuthEmail,
        requestId,
      });

      if (!result.valid) {
        return res.status(403).json({ success: false, error: result.reason });
      }

      const targetEmail = (result.ticket?.targetEmail || authAdmin || '').trim().toLowerCase();
      const adminSessionToken = generateAdminSessionToken(targetEmail);

      res.json({
        success: true,
        targetAdmin: targetEmail,
        requestId: result.ticket?.requestId,
        adminSessionToken,
        message: 'Administrative ticket verified and authorized.',
      });
    } catch (err: any) {
      console.error('[VERIFY ADMIN TICKET ERROR]', err.message);
      res.status(500).json({ success: false, error: 'Service error verifying admin ticket.' });
    }
  });

  // ==========================================
  // SECTION 14 & 15: M-PESA DARAJA STK PUSH
  // ==========================================

  // Step 1: Backend initiates genuine M-PESA STK Push via Daraja
  app.post('/api/payments/mpesa/initiate', async (req, res) => {
    try {
      const { phone, amount, name, email, uid } = req.body;

      if (!phone) {
        return res.status(400).json({ error: 'Phone number is required for M-PESA payment' });
      }

      const phoneNorm = normalizeKenyanPhone(phone);
      if (!phoneNorm.isValid) {
        return res.status(400).json({
          error: 'Please enter a valid Kenyan phone number (e.g. 0712 345 678 or 254712345678)',
        });
      }

      const config = PaymentStore.getConfig();
      const expectedAmount = amount || config.priceKes;
      const userUid = uid || `GUEST_${Date.now()}`;
      const customerEmail = email || 'reader@datingwrong.ke';
      const customerName = name || 'Valued Reader';

      // Call Daraja Service
      const stkResponse = await daraja.initiateStkPush({
        phone: phoneNorm.canonical,
        amount: expectedAmount,
        accountReference: 'DATING-WRONG',
        transactionDesc: 'Book Purchase',
        customerName,
        customerEmail,
        userId: userUid,
      });

      // Create Payment Session in Backend Store
      const paymentRecord = await PaymentStore.createPaymentSession({
        uid: userUid,
        email: customerEmail,
        customerName,
        checkoutPhone: phoneNorm.canonical,
        expectedAmount,
        checkoutRequestId: stkResponse.checkoutRequestId,
        merchantRequestId: stkResponse.merchantRequestId,
      });

      res.json({
        success: true,
        paymentId: paymentRecord.paymentId,
        paymentSessionId: paymentRecord.paymentSessionId,
        checkoutRequestId: stkResponse.checkoutRequestId,
        merchantRequestId: stkResponse.merchantRequestId,
        customerMessage: stkResponse.customerMessage,
        businessName: 'Mark & Alvis Publishers',
        paybill: config.paybill,
        accountReference: 'DATING-WRONG',
        amount: expectedAmount,
        phone: phoneNorm.displayLocal,
      });
    } catch (err: any) {
      console.error('Error initiating Daraja STK Push:', err.message);
      res.status(500).json({
        error: 'Failed to initiate M-PESA payment prompt. Please verify your phone number and retry.',
        details: err.message,
      });
    }
  });

  // Step 2: Check M-PESA STK Push Status
  app.get('/api/payments/mpesa/status/:checkoutRequestId', async (req, res) => {
    try {
      const { checkoutRequestId } = req.params;
      const payment = await PaymentStore.getPaymentByCheckoutRequestId(checkoutRequestId);

      if (!payment) {
        return res.status(404).json({ error: 'Payment request not found' });
      }

      res.json({
        paymentId: payment.paymentId,
        checkoutRequestId,
        status: payment.status,
        receiptNumber: payment.transactionCode || null,
        amount: payment.receivedAmount || payment.expectedAmount,
        phone: payment.checkoutPhone,
        securityChecksPassed: payment.securityChecksPassed,
        failureReason: payment.failureReason || null,
      });
    } catch (err: any) {
      console.error('[MPESA STATUS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to retrieve payment status' });
    }
  });

  // Step 3: Daraja Webhook Callback (Called directly by Safaricom servers upon PIN authorization)
  app.post('/api/payments/daraja/callback', async (req, res) => {
    console.log('[Daraja Callback Webhook Received]', JSON.stringify(req.body));
    try {
      const parsed = daraja.parseCallback(req.body);

      const payment = await PaymentStore.getPaymentByCheckoutRequestId(parsed.checkoutRequestId);
      if (!payment) {
        console.warn(`[Daraja Callback] No payment session found for CheckoutRequestID ${parsed.checkoutRequestId}`);
        return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
      }

      if (!parsed.isSuccessful || !parsed.transactionCode || !parsed.amount) {
        console.warn(`[Daraja Callback Failed] ${parsed.resultDesc}`);
        payment.status = 'FAILED';
        payment.failureReason = parsed.resultDesc;
        payment.updatedAt = new Date().toISOString();
        return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
      }

      // Execute full backend verification matrix (All 9 security checks)
      await PaymentStore.verifyAndGrantEntitlement({
        paymentId: payment.paymentId,
        checkoutRequestId: parsed.checkoutRequestId,
        uid: payment.uid,
        email: payment.email,
        customerName: payment.customerName,
        senderPhone: parsed.phone || payment.checkoutPhone,
        amountReceived: parsed.amount,
        transactionCode: parsed.transactionCode,
        verificationMethod: 'daraja_stk',
        transactionTimestamp: parsed.transactionDate,
      });

      res.json({ ResultCode: 0, ResultDesc: 'Success' });
    } catch (err: any) {
      console.error('[Daraja Callback Handler Error]', err.message);
      res.json({ ResultCode: 0, ResultDesc: 'Error processed' });
    }
  });

  // Step 4: Customer Prompt Confirmation / Sandbox Simulation Endpoint
  app.post('/api/payments/mpesa/confirm-pin-entry', async (req, res) => {
    try {
      const { checkoutRequestId, customCode, uid, name, email, phone, amount } = req.body;

      const payment = checkoutRequestId
        ? await PaymentStore.getPaymentByCheckoutRequestId(checkoutRequestId)
        : null;

      const config = PaymentStore.getConfig();
      const expectedAmount = amount || payment?.expectedAmount || config.priceKes;
      const targetPhone = phone || payment?.checkoutPhone || '254700000000';
      const targetUid = uid || payment?.uid || `USR-${Date.now()}`;
      const targetName = name || payment?.customerName || 'Authorized Reader';
      const targetEmail = email || payment?.email || 'reader@datingwrong.ke';

      // Generate or use code
      let code = (customCode || '').trim().toUpperCase();
      if (!code) {
        const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        const numbers = '0123456789';
        code = 'R';
        for (let i = 0; i < 2; i++) code += letters.charAt(Math.floor(Math.random() * letters.length));
        for (let i = 0; i < 2; i++) code += numbers.charAt(Math.floor(Math.random() * numbers.length));
        for (let i = 0; i < 5; i++) code += (letters + numbers).charAt(Math.floor(Math.random() * (letters.length + numbers.length)));
      }

      // Execute the 9 strict security checks
      const result = await PaymentStore.verifyAndGrantEntitlement({
        paymentId: payment?.paymentId,
        checkoutRequestId,
        uid: targetUid,
        email: targetEmail,
        customerName: targetName,
        senderPhone: targetPhone,
        amountReceived: expectedAmount,
        transactionCode: code,
        verificationMethod: 'daraja_stk',
      });

      if (!result.passed) {
        return res.status(400).json({
          success: false,
          status: result.status,
          error: result.failureReason,
          checksLog: result.checksLog,
        });
      }

      res.json({
        success: true,
        status: 'VERIFIED',
        receiptNumber: code,
        entitlement: result.entitlement,
        checksLog: result.checksLog,
      });
    } catch (err: any) {
      console.error('Error confirming M-PESA PIN entry:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // =========================================================================
  // SECTION 16: PLAN B — MANUAL SMS RECEIPT & VERIFICATION
  // =========================================================================
  app.post('/api/payments/verify-sms-or-receipt', async (req, res) => {
    try {
      const { smsText, receiptCode, phone, uid, name, email } = req.body;

      const config = PaymentStore.getConfig();
      const targetUid = uid || `USR_${Date.now()}`;
      const targetEmail = email || 'reader@datingwrong.ke';
      const targetName = name || 'Verified Reader';
      const checkoutPhone = phone || '254700000000';

      let extractedCode = (receiptCode || '').trim().toUpperCase();
      let extractedAmount = config.priceKes;
      let rawReference = smsText || receiptCode;

      // If user provided a pasted SMS text:
      if (smsText && smsText.trim().length > 15) {
        const smsVerification = verifyPastedMpesaSms({
          smsText,
          expectedAmount: config.priceKes,
          checkoutPhone,
          merchantName: config.recipient,
          paybillNumber: config.paybill,
        });

        if (!smsVerification.isValid) {
          if (smsVerification.decision === 'UNDERPAID') {
            await NotificationService.notifyAllThreeAdmins({
              customerName: targetName,
              customerEmail: targetEmail,
              customerPhone: checkoutPhone,
              amount: smsVerification.extractedAmount || 0,
              expectedAmount: config.priceKes,
              transactionCode: smsVerification.extractedCode || 'UNKNOWN',
              status: 'UNDERPAID',
              verificationMethod: 'pasted_sms',
            });
          }

          return res.status(400).json({
            success: false,
            decision: smsVerification.decision,
            error: smsVerification.reason || 'SMS verification check failed',
            checks: smsVerification.checks,
            parsed: smsVerification.parsed,
          });
        }

        extractedCode = smsVerification.extractedCode!;
        extractedAmount = smsVerification.extractedAmount!;
      }

      const normalizedCode = PaymentStore.normalizeTransactionCode(extractedCode);
      if (!normalizedCode || normalizedCode.length < 8) {
        return res.status(400).json({
          error: 'Please enter a valid 10-character M-PESA transaction code (e.g. RK72QM9XLP)',
        });
      }

      // Check transaction uniqueness before granting
      const existingUse = await PaymentStore.getUsedTransaction(normalizedCode);
      if (existingUse) {
        await NotificationService.notifyAllThreeAdmins({
          customerName: targetName,
          customerEmail: targetEmail,
          customerPhone: checkoutPhone,
          amount: extractedAmount,
          expectedAmount: config.priceKes,
          transactionCode: normalizedCode,
          status: 'DUPLICATE',
          verificationMethod: 'pasted_sms',
        });

        return res.status(409).json({
          success: false,
          decision: 'DUPLICATE',
          error: `Transaction code ${normalizedCode} has already been used to unlock the book for another account. A transaction code can only unlock the book once.`,
        });
      }

      // Run through strict backend verification
      const verifyResult = await PaymentStore.verifyAndGrantEntitlement({
        uid: targetUid,
        email: targetEmail,
        customerName: targetName,
        senderPhone: checkoutPhone,
        amountReceived: extractedAmount,
        transactionCode: normalizedCode,
        verificationMethod: 'pasted_sms',
        rawReference,
      });

      if (!verifyResult.passed) {
        return res.status(400).json({
          success: false,
          decision: verifyResult.status,
          error: verifyResult.failureReason,
          checksLog: verifyResult.checksLog,
        });
      }

      res.json({
        success: true,
        message: 'M-PESA transaction verified. Digital book unlocked.',
        entitlement: verifyResult.entitlement,
        checksLog: verifyResult.checksLog,
      });
    } catch (err: any) {
      console.error('Error verifying SMS receipt:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // =========================================================================
  // M-PESA POCHI LA BIASHARA PAYMENT VERIFICATION FLOW
  // =========================================================================

  // Public Pochi configuration for checkout
  app.get('/api/config/pochi', (req, res) => {
    res.json(PaymentStore.getPochiConfig());
  });

  // Customer submits their pasted M-PESA SMS
  app.post('/api/payments/pochi/submit-sms', async (req, res) => {
    try {
      const { uid, email, customerName, submittedSms, senderPhone } = req.body;
      const authenticatedUser = (req as any).firebaseUser as { uid: string; email: string } | undefined;

      if (!authenticatedUser || !authenticatedUser.emailVerified || authenticatedUser.signInProvider !== 'google.com') {
        return res.status(401).json({ success: false, error: 'Please sign in with a verified Google account before submitting your M-PESA confirmation SMS.' });
      }
      if (uid !== authenticatedUser.uid || String(email || '').trim().toLowerCase() !== authenticatedUser.email) {
        return res.status(403).json({ success: false, error: 'The submitted account does not match your verified sign-in session.' });
      }

      if (!uid || !email) {
        return res.status(401).json({
          success: false,
          error: 'Google Sign-In is required to submit payment verification. Please sign in to attach your account.',
        });
      }

      if (!submittedSms || typeof submittedSms !== 'string' || submittedSms.trim().length < 15) {
        return res.status(400).json({
          success: false,
          error: 'Please paste the complete M-PESA confirmation SMS you received from Safaricom.',
        });
      }

      // Check if user already has an active entitlement
      const existingEnt = await PaymentStore.getEntitlement(uid, 'dating-wrong');
      if (existingEnt && existingEnt.status === 'ACTIVE') {
        return res.json({
          success: true,
          message: 'Your account is already authorized to read Dating Wrong.',
          alreadyAuthorized: true,
          entitlement: existingEnt,
        });
      }

      // Parse the submitted SMS
      const parsed = verifyPastedMpesaSms({
        smsText: submittedSms,
        expectedAmount: PaymentStore.getPochiConfig().priceKes,
        checkoutPhone: senderPhone || '',
        merchantName: PaymentStore.getPochiConfig().pochiName,
        paybillNumber: PaymentStore.getPochiConfig().pochiPhone,
      });

      // Extract transaction code from parsed or regex
      let code = parsed.extractedCode;
      if (!code) {
        const codeMatch = submittedSms.match(/\b([A-Z0-9]{10})\b/i);
        if (codeMatch) {
          code = codeMatch[1].toUpperCase();
        }
      }

      const normalizedCode = code ? PaymentStore.normalizeTransactionCode(code) : '';
      if (!normalizedCode || normalizedCode.length < 8) {
        return res.status(400).json({
          success: false,
          error: 'Could not extract a valid 10-character M-PESA transaction code from the pasted SMS. Please paste the full message starting with the transaction code.',
          parsed,
        });
      }

      // Extract amount
      let amount = parsed.extractedAmount;
      if (!amount || isNaN(amount)) {
        const amountMatch = submittedSms.match(/(?:Ksh|KSh|KES)\.?\s*([0-9,]+(?:\.\d{2})?)/i);
        if (amountMatch) {
          amount = parseFloat(amountMatch[1].replace(/,/g, ''));
        } else {
          amount = PaymentStore.getPochiConfig().priceKes;
        }
      }

      const effectiveSenderPhone = senderPhone || parsed.extractedPhone || parsed.parsed.senderPhone || '254700000000';
      const transactionTime = parsed.parsed.dateTimeStr || 'Stated in SMS';
      const recipientDetails = parsed.parsed.recipient || PaymentStore.getPochiConfig().pochiName;
      const senderName = parsed.parsed.senderName || customerName || 'Valued Reader';

      const host = req.headers['x-forwarded-host'] || req.get('host');
      const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
      const baseUrl = host ? `${proto}://${host}` : undefined;

      // Create Payment Request Record (PENDING_REVIEW) and notify 3 admins
      const result = await PaymentStore.createPaymentRequest({
        uid,
        email: email.trim().toLowerCase(),
        customerName: customerName || senderName,
        submittedSms: submittedSms.trim(),
        transactionCode: normalizedCode,
        amount,
        senderPhone: effectiveSenderPhone,
        senderName,
        recipientDetails,
        transactionTime,
        baseUrl,
      });

      const notificationsDelivered = Boolean(result.notificationResult?.success);
      res.json({
        success: true,
        message: notificationsDelivered
          ? 'Payment verification request received and administrator alerts were delivered.'
          : 'Payment verification request was saved, but administrator alerts could not be confirmed. The request remains available in the admin dashboard.',
        requestId: result.request.requestId,
        status: 'PENDING_REVIEW',
        notificationsDelivered,
        notificationResult: result.notificationResult
          ? {
              success: result.notificationResult.success,
              muted: result.notificationResult.muted || false,
              dispatchedTo: result.notificationResult.dispatchedTo,
            }
          : null,
        request: result.request,
        parsedDetails: {
          transactionCode: normalizedCode,
          amount,
          senderPhone: effectiveSenderPhone,
          senderName,
          recipientDetails,
          transactionTime,
        },
      });
    } catch (err: any) {
      console.error('[POCHI SUBMIT SMS ERROR]', err.message);
      res.status(400).json({
        success: false,
        error: err.message || 'Failed to submit payment verification request.',
      });
    }
  });

  // Check status of a specific payment request (polled by customer UI)
  app.get('/api/payments/pochi/request-status/:requestId', async (req, res) => {
    try {
      const { requestId } = req.params;
      const authenticatedUser = (req as any).firebaseUser as { uid: string } | undefined;
      if (!authenticatedUser) {
        return res.status(401).json({ success: false, error: 'Sign in to check your payment request.' });
      }
      const request = await PaymentStore.getPaymentRequest(requestId);

      if (!request) {
        return res.status(404).json({ success: false, error: 'Payment request not found.' });
      }

      if (request.uid !== authenticatedUser.uid) {
        return res.status(403).json({ success: false, error: 'You are not authorized to view this payment request.' });
      }

      let entitlement = null;
      if (request.status === 'APPROVED') {
        entitlement = await PaymentStore.getEntitlement(request.uid, 'dating-wrong');
      }

      res.json({
        success: true,
        request,
        status: request.status,
        entitlement,
      });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ success: false, error: 'Authentication required to check payment status.' });
      }
      console.error('[POCHI REQUEST STATUS ERROR]', err.message);
      res.status(500).json({ success: false, error: 'Failed to retrieve payment request status' });
    }
  });

  // Get user's payment requests
  app.get('/api/payments/pochi/user-requests', async (req, res) => {
    try {
      const authenticatedUser = (req as any).firebaseUser as { uid: string; email: string } | undefined;
      if (!authenticatedUser) {
        return res.status(401).json({ success: false, error: 'Sign in to retrieve your payment requests.' });
      }
      const uid = authenticatedUser.uid;
      const email = authenticatedUser.email;

      if (!uid && !email) {
        return res.status(400).json({ error: 'uid or email query param required' });
      }

      const requests = await PaymentStore.getUserPaymentRequests({ uid, email });
      res.json({
        success: true,
        requests,
      });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ success: false, error: 'Authentication required to retrieve payment requests.' });
      }
      console.error('[POCHI USER REQUESTS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to retrieve payment requests' });
    }
  });

  // Restore Access Flow
  app.post('/api/payments/pochi/restore-by-sms', async (req, res) => {
    try {
      const { email, smsText, uid } = req.body;
      const authenticatedUser = (req as any).firebaseUser as { uid: string; email: string } | undefined;
      if (!authenticatedUser || !authenticatedUser.emailVerified || authenticatedUser.signInProvider !== 'google.com') {
        return res.status(401).json({ success: false, approved: false, redirectToBuy: false, error: 'Please sign in with your verified Google account to restore access.' });
      }
      if (String(email || '').trim().toLowerCase() !== authenticatedUser.email || (uid && uid !== authenticatedUser.uid)) {
        return res.status(403).json({ success: false, approved: false, redirectToBuy: false, error: 'The account details do not match your signed-in Google account.' });
      }

      if (!email || !smsText) {
        return res.status(400).json({
          approved: false,
          redirectToBuy: true,
          error: 'Both account email and pasted SMS confirmation are required for restoration.',
        });
      }

      const result = await PaymentStore.restoreApprovedPaymentBySms({
        email,
        smsText,
        uid,
      });

      if (result.approved) {
        return res.json({
          success: true,
          approved: true,
          message: `Restoration approved! Verified purchase matched for ${email}.`,
          entitlement: result.entitlement,
          matchedRequest: result.matchedRequest,
          parsedDetails: result.parsedDetails,
        });
      } else {
        return res.json({
          success: false,
          approved: false,
          redirectToBuy: true,
          message: result.reason || 'No approved purchase found matching this SMS and email in our database.',
          reason: result.reason,
          parsedDetails: result.parsedDetails,
        });
      }
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({
          success: false,
          approved: false,
          redirectToBuy: false,
          error: 'Please sign in with Google to restore access.',
        });
      }
      console.error('[RESTORE BY SMS ERROR]', err.message);
      res.status(500).json({
        success: false,
        approved: false,
        redirectToBuy: true,
        error: err.message || 'Internal server error during restoration.',
      });
    }
  });

  // ==========================================
  // SECTION 28 & 29: DEVICE AUTHORIZATION & OFFLINE LICENSING
  // ==========================================

  // Check entitlement by email or uid for authorized users
  app.post('/api/entitlements/check', async (req, res) => {
    try {
      const { email, uid, deviceId, deviceName, platform } = req.body;
      const authenticatedUser = (req as any).firebaseUser as { uid: string; email: string } | undefined;
      if (!authenticatedUser) {
        return res.status(401).json({ authorized: false, error: 'Sign in with Google to verify access.' });
      }
      if (uid !== authenticatedUser.uid || String(email || '').trim().toLowerCase() !== authenticatedUser.email) {
        return res.status(403).json({ authorized: false, error: 'The account details do not match your signed-in account.' });
      }
      if (!email && !uid) {
        return res.status(400).json({ error: 'Email or UID is required' });
      }

      const checkResult = await PaymentStore.checkEntitlementWithDevice({
        email,
        uid,
        deviceId,
        deviceName,
        platform,
      });

      if (checkResult.deviceLimitReached) {
        return res.json({
          authorized: false,
          deviceLimitReached: true,
          maxDevices: checkResult.maxDevices || 2,
          reason: checkResult.reason,
          devices: checkResult.devices || [],
        });
      }

      if (checkResult.entitlement && checkResult.entitlement.status === 'ACTIVE') {
        return res.json({
          authorized: true,
          entitlement: checkResult.entitlement,
          isExemptAdminDevice: checkResult.isExemptAdminDevice || false,
          deviceCount: checkResult.deviceCount,
        });
      }

      return res.json({
        authorized: false,
      });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ authorized: false, error: 'Authentication required to verify entitlement.' });
      }
      console.error('[ENTITLEMENT CHECK ERROR]', err.message);
      res.status(500).json({ error: 'Service error checking entitlement.' });
    }
  });

  // Get authorized devices for user (max 2 for admins, max 3 for standard readers)
  app.get('/api/devices/:userId', async (req, res) => {
    try {
      const { userId } = req.params;
      const emailParam = ((req.query.email as string) || '').trim().toLowerCase();
      const cleanEmail = emailParam || (userId || '').trim().toLowerCase();
      const isAdmin = cleanEmail === 'alvisnjagi@gmail.com' ||
                      cleanEmail === 'wanyekigerison@gmail.com' ||
                      cleanEmail === 'ochiengmark2908@gmail.com' ||
                      userId.startsWith('admin_');
      const queryKey = (isAdmin && cleanEmail.includes('@'))
        ? `admin_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`
        : userId;
      const devices = await PaymentStore.getUserDevices(queryKey);
      res.json({
        devices: devices.filter((d) => d.status === 'active'),
        allDevices: devices,
        maxDevices: isAdmin ? 2 : 3,
      });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to retrieve devices.' });
      }
      console.error('[GET DEVICES ERROR]', err.message);
      res.status(500).json({ error: 'Failed to retrieve devices' });
    }
  });

  // Authorize a device for offline reading (max 3 for readers, max 2 for admins)
  app.post('/api/devices/authorize', async (req, res) => {
    try {
      const { userId, email, deviceId, deviceName, platform } = req.body;
      if (!userId || !deviceId) {
        return res.status(400).json({ error: 'userId and deviceId are required' });
      }

      const cleanEmail = (email || '').trim().toLowerCase();
      const isAdmin = cleanEmail === 'alvisnjagi@gmail.com' ||
                      cleanEmail === 'wanyekigerison@gmail.com' ||
                      cleanEmail === 'ochiengmark2908@gmail.com' ||
                      userId.startsWith('admin_');
      const targetUserId = (isAdmin && cleanEmail.includes('@'))
        ? `admin_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`
        : userId;

      const result = await PaymentStore.authorizeDevice({
        userId: targetUserId,
        email,
        deviceId,
        deviceName: deviceName || 'Reader Device',
        platform: platform || 'desktop',
      });

      if (!result.success) {
        const maxAllowed = isAdmin ? 2 : 3;
        return res.status(403).json({
          success: false,
          reason: result.reason,
          message: isAdmin
            ? 'Admin device exemption limit reached (Max 2 Devices). Please revoke an unused device from your Account to authorize this device.'
            : `You have reached the maximum of ${maxAllowed} authorized devices using this email address. Please revoke an unused device from your Account to authorize this device.`,
          devices: result.devices,
        });
      }

      res.json({
        success: true,
        device: result.device,
        activeDevices: result.devices,
        maxDevices: isAdmin ? 2 : 3,
      });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to authorize device.' });
      }
      console.error('[AUTHORIZE DEVICE ERROR]', err.message);
      res.status(500).json({ error: 'Failed to authorize device' });
    }
  });

  // Revoke an authorized device (free up slot for replacement)
  app.post('/api/devices/revoke', async (req, res) => {
    try {
      const { userId, deviceId, email } = req.body;
      if (!userId || !deviceId) {
        return res.status(400).json({ error: 'userId and deviceId are required' });
      }

      const cleanEmail = (email || '').trim().toLowerCase();
      const isAdmin = cleanEmail === 'alvisnjagi@gmail.com' ||
                      cleanEmail === 'wanyekigerison@gmail.com' ||
                      cleanEmail === 'ochiengmark2908@gmail.com' ||
                      userId.startsWith('admin_');
      const targetKey = (isAdmin && cleanEmail.includes('@'))
        ? `admin_${cleanEmail.replace(/[^a-zA-Z0-9]/g, '_')}`
        : userId;

      const revokedTarget = await PaymentStore.revokeDevice(targetKey, deviceId);
      const revokedUser = !revokedTarget && targetKey !== userId ? await PaymentStore.revokeDevice(userId, deviceId) : false;
      const revoked = revokedTarget || revokedUser;
      const activeDevices = (await PaymentStore.getUserDevices(targetKey)).filter((d) => d.status === 'active');

      res.json({
        success: revoked,
        message: revoked
          ? 'Device revoked successfully. You may now authorize a replacement device.'
          : 'Device was not found or already inactive.',
        activeDevices,
      });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to revoke device.' });
      }
      console.error('[REVOKE DEVICE ERROR]', err.message);
      res.status(500).json({ error: 'Failed to revoke device' });
    }
  });

  // Verify and renew offline license
  app.post('/api/devices/verify-license', async (req, res) => {
    try {
      const { userId, deviceId, licenseId } = req.body;
      if (!userId || !deviceId) {
        return res.status(400).json({ valid: false, error: 'Missing credentials' });
      }

      const devices = await PaymentStore.getUserDevices(userId);
      const active = devices.find((d) => d.deviceId === deviceId && d.status === 'active');

      if (!active) {
        return res.json({
          valid: false,
          reason: 'Device authorization has been revoked or expired.',
        });
      }

      const renewedExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

      res.json({
        valid: true,
        renewedLicense: {
          licenseId: licenseId || `LIC-${Date.now()}`,
          userId,
          bookId: 'dating-wrong',
          bookVersion: 1,
          issuedAt: new Date().toISOString(),
          expiresAt: renewedExpiresAt,
          authorizedDevice: {
            deviceId,
            deviceName: active.deviceName,
            platform: active.platform,
          },
          offlineEnabled: true,
          licenseVersion: 1,
        },
      });
    } catch (err: any) {
      console.error('[VERIFY LICENSE ERROR]', err.message);
      res.status(500).json({ valid: false, error: 'Failed to verify license' });
    }
  });

  // Issue signed offline Entitlement Token
  app.post('/api/entitlements/issue-token', async (req, res) => {
    try {
      const { uid, deviceId, bookId } = req.body;
      if (!uid || !deviceId) {
        return res.status(400).json({ error: 'uid and deviceId are required' });
      }

      const entitlement = await PaymentStore.getEntitlement(uid, bookId || 'dating-wrong');
      if (!entitlement || entitlement.status !== 'ACTIVE') {
        return res.status(403).json({ error: 'User does not possess an active entitlement for this book' });
      }

      const issuedAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      const tokenId = `TOK_${Date.now()}_${Math.random().toString(36).substring(2, 9).toUpperCase()}`;

      const payload = {
        tokenId,
        entitlementId: entitlement.paymentId,
        userId: uid,
        bookId: entitlement.bookId,
        bookVersion: entitlement.bookVersion,
        deviceId,
        transactionCode: entitlement.transactionCode,
        scope: 'read:offline',
        issuedAt,
        expiresAt,
        status: 'active',
        watermarkText: entitlement.watermark,
      };

      res.json({
        success: true,
        payload,
        expiresAt,
      });
    } catch (err: any) {
      console.error('[ISSUE TOKEN ERROR]', err.message);
      res.status(500).json({ error: 'Failed to issue offline entitlement token' });
    }
  });

  app.post('/api/entitlements/verify-token', async (req, res) => {
    try {
      const { tokenPayload } = req.body;
      if (!tokenPayload || !tokenPayload.userId || !tokenPayload.deviceId) {
        return res.status(400).json({ valid: false, error: 'Invalid token payload' });
      }

      const entitlement = await PaymentStore.getEntitlement(tokenPayload.userId, tokenPayload.bookId || 'dating-wrong');
      if (!entitlement || entitlement.status !== 'ACTIVE') {
        return res.json({ valid: false, reason: 'Entitlement not active or revoked on server' });
      }

      const isExpired = new Date(tokenPayload.expiresAt).getTime() <= Date.now();
      if (isExpired) {
        return res.json({ valid: false, reason: 'Offline token lease expired' });
      }

      res.json({ valid: true });
    } catch (err: any) {
      console.error('[VERIFY TOKEN ERROR]', err.message);
      res.status(500).json({ valid: false, error: 'Failed to verify token' });
    }
  });

  // Section 36: Transaction Status & Reconciliation Mechanism (Admin only)
  app.post('/api/payments/mpesa/reconcile/:paymentSessionId', requireAdminAuth, async (req, res) => {
    const { paymentSessionId } = req.params;
    try {
      const result = await PaymentStore.reconcilePaymentSession(paymentSessionId);
      res.json({
        success: result.passed,
        status: result.status,
        entitlement: result.entitlement || null,
        checksLog: result.checksLog,
        error: result.error || null,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Reading Progress Storage
  app.get('/api/reading-progress/:uid/:bookId', async (req, res) => {
    try {
      const { uid, bookId } = req.params;
      const progress = await PaymentStore.getReadingProgress(uid, bookId);
      res.json(progress || { uid, bookId, currentPage: 1, percentage: 0, lastReadAt: null });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to retrieve reading progress.' });
      }
      console.error('[GET PROGRESS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to retrieve reading progress' });
    }
  });

  app.post('/api/reading-progress', async (req, res) => {
    try {
      const { uid, bookId, currentPage, percentage } = req.body;
      if (!uid || !bookId) {
        return res.status(400).json({ error: 'uid and bookId are required' });
      }
      const saved = await PaymentStore.saveReadingProgress({
        uid,
        bookId,
        currentPage: Number(currentPage) || 1,
        percentage: Number(percentage) || 0,
      });
      res.json({ success: true, progress: saved });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to save reading progress.' });
      }
      console.error('[SAVE PROGRESS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to save reading progress' });
    }
  });

  // Bookmarks
  app.get('/api/bookmarks/:uid/:bookId', async (req, res) => {
    try {
      const { uid, bookId } = req.params;
      const bookmarks = await PaymentStore.getBookmarks(uid, bookId);
      res.json({ bookmarks });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to retrieve bookmarks.' });
      }
      console.error('[GET BOOKMARKS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to retrieve bookmarks' });
    }
  });

  app.post('/api/bookmarks', async (req, res) => {
    try {
      const { uid, bookId, page, chapter, note } = req.body;
      if (!uid || !bookId || page == null) {
        return res.status(400).json({ error: 'uid, bookId, and page are required' });
      }
      const updated = await PaymentStore.saveBookmark(uid, bookId, {
        page: Number(page),
        chapter: chapter || 'Chapter',
        createdAt: new Date().toISOString(),
        note,
      });
      res.json({ success: true, bookmarks: updated });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to save bookmark.' });
      }
      console.error('[SAVE BOOKMARK ERROR]', err.message);
      res.status(500).json({ error: 'Failed to save bookmark' });
    }
  });

  app.delete('/api/bookmarks/:uid/:bookId/:page', async (req, res) => {
    try {
      const { uid, bookId, page } = req.params;
      const updated = await PaymentStore.deleteBookmark(uid, bookId, Number(page));
      res.json({ success: true, bookmarks: updated });
    } catch (err: any) {
      if (isUnauthenticatedPermissionError(err)) {
        return res.status(401).json({ error: 'Authentication required to delete bookmark.' });
      }
      console.error('[DELETE BOOKMARK ERROR]', err.message);
      res.status(500).json({ error: 'Failed to delete bookmark' });
    }
  });

  // ==============================================================
  // PROTECTED ADMINISTRATOR ENDPOINTS
  // Strictly protected with requireAdminAuth (Firebase Admin ID tokens / Admin session tokens)
  // Enforces 3-administrator allowlist on every endpoint
  // ==============================================================

  // Section 42: Admin Dashboard Metrics & Statistics
  app.get('/api/admin/stats', requireAdminAuth, async (req, res) => {
    try {
      const all = await PaymentStore.getAllPayments();
      const verified = all.filter((p) => p.status === 'VERIFIED');
      const pending = all.filter((p) => p.status === 'PENDING' || p.status === 'STK_SENT');
      const underpaid = all.filter((p) => p.status === 'UNDERPAID');
      const failed = all.filter((p) => p.status === 'FAILED' || p.status === 'REJECTED' || p.status === 'INVALID_CODE');
      const manualReview = all.filter((p) => p.status === 'MANUAL_REVIEW');
      const duplicate = all.filter((p) => p.status === 'DUPLICATE');

      const totalRevenue = verified.reduce((sum, p) => sum + (p.receivedAmount || p.expectedAmount), 0);
      const allRequests = await PaymentStore.getAllPaymentRequests();
      const approvedCount = allRequests.filter((r) => r.status === 'APPROVED').length;

      res.json({
        totalReaders: verified.length + approvedCount,
        verifiedPurchases: verified.length,
        pendingPayments: pending.length,
        underpaidPayments: underpaid.length,
        failedPayments: failed.length,
        manualReviewPayments: manualReview.length,
        duplicatePayments: duplicate.length,
        revenue: totalRevenue,
        activeEntitlements: verified.length + approvedCount,
        offlineUsers: 0,
        recentPurchases: all.slice(0, 15),
      });
    } catch (err: any) {
      console.error('[ADMIN STATS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to compute admin statistics' });
    }
  });

  // Section 46: SMS Monitoring Logs
  app.get('/api/admin/sms-logs', requireAdminAuth, (req, res) => {
    res.json({ logs: NotificationService.getRecentLogs() });
  });

  // Section 37: Customer Email Confirmation Logs
  app.get('/api/admin/email-logs', requireAdminAuth, (req, res) => {
    res.json({ logs: EmailConfirmationService.getRecentEmailLogs() });
  });

  // Section 44: Admin Book Management
  app.post('/api/admin/book-config', requireAdminAuth, (req, res) => {
    const { title, subtitle, priceKes, activeVersion, publisher } = req.body;
    if (priceKes) {
      PaymentStore.setConfiguredPrice(Number(priceKes));
    }
    res.json({
      success: true,
      message: 'Book configuration updated successfully.',
      currentConfig: {
        title: title || MANUSCRIPT_V1.metadata.title,
        subtitle: subtitle || MANUSCRIPT_V1.metadata.subtitle,
        priceKes: PaymentStore.getConfig().priceKes,
        activeVersion: activeVersion || 1,
        publisher: publisher || MANUSCRIPT_V1.metadata.publisher,
      },
    });
  });

  // Admin: View all payments and audit logs
  app.get('/api/admin/payments', requireAdminAuth, async (req, res) => {
    try {
      const all = await PaymentStore.getAllPayments();
      res.json({
        payments: all,
        totalCount: all.length,
        verifiedCount: all.filter((p) => p.status === 'VERIFIED').length,
        underpaidCount: all.filter((p) => p.status === 'UNDERPAID').length,
        duplicateCount: all.filter((p) => p.status === 'DUPLICATE').length,
      });
    } catch (err: any) {
      console.error('[ADMIN PAYMENTS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to load payments' });
    }
  });

  // Admin: View Pochi verification requests queue
  app.get('/api/admin/payment-requests', requireAdminAuth, async (req, res) => {
    try {
      const requests = await PaymentStore.getAllPaymentRequests();
      const pending = requests.filter((r) => r.status === 'PENDING_REVIEW');
      const approved = requests.filter((r) => r.status === 'APPROVED');
      const rejected = requests.filter((r) => r.status === 'REJECTED');

      res.json({
        success: true,
        requests,
        counts: {
          total: requests.length,
          pending: pending.length,
          approved: approved.length,
          rejected: rejected.length,
        },
      });
    } catch (err: any) {
      console.error('[ADMIN PAYMENT REQUESTS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to load payment requests' });
    }
  });

  // Admin: Get total number of mapped users
  app.get('/api/admin/mapped-users', requireAdminAuth, async (req, res) => {
    try {
      const allRequests = await PaymentStore.getAllPaymentRequests();
      const approvedRequests = allRequests.filter((r) => r.status === 'APPROVED');

      const mappedUsers = approvedRequests.map((r) => ({
        email: r.email,
        sms: r.submittedSms,
        transactionalCode: r.transactionCode,
        timeBought: r.transactionTime || r.submittedAt,
        submittedAt: r.submittedAt,
        approvedAt: r.reviewedAt || r.submittedAt,
        adminWhoApproved: r.reviewedBy || 'Super Admin',
        amount: r.amount,
        customerName: r.customerName,
        senderPhone: r.senderPhone,
        requestId: r.requestId,
        entitlementId: r.entitlementId,
      }));

      res.json({
        success: true,
        totalMappedUsers: mappedUsers.length,
        users: mappedUsers,
      });
    } catch (err: any) {
      console.error('[ADMIN MAPPED USERS ERROR]', err.message);
      res.status(500).json({ error: 'Failed to load mapped users' });
    }
  });

  // Admin: Notification Toggle for Pending Approvals
  app.get('/api/admin/notifications/toggle', requireAdminAuth, async (req, res) => {
    res.json({
      success: true,
      pendingApprovalsNotificationsEnabled: await NotificationService.isPendingApprovalsNotificationsEnabled(),
    });
  });

  app.post('/api/admin/notifications/toggle', requireAdminAuth, async (req, res) => {
    const { enabled } = req.body;
    const newState = await NotificationService.setPendingApprovalsNotificationsEnabled(Boolean(enabled));
    res.json({
      success: true,
      pendingApprovalsNotificationsEnabled: newState,
      message: newState
        ? 'Pending approvals notifications activated! Email & SMS alerts enabled for Mark, Gerishon, and Alvis.'
        : 'Pending approvals notifications paused. Email & SMS alerts are now muted.',
    });
  });

  // Admin: Approve a payment verification request
  app.post('/api/admin/payment-requests/:requestId/approve', requireAdminAuth, async (req, res) => {
    const { requestId } = req.params;
    const verifiedAdmin = (req as any).adminUser?.email || (req.body.adminEmail as string) || 'Authorized Admin';
    const cleanAdminEmail = verifiedAdmin.trim().toLowerCase();
    const notes = req.body.notes;

    try {
      const host = req.headers['x-forwarded-host'] || req.get('host');
      const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
      const baseUrl = (req.body.baseUrl as string) || (host ? `${proto}://${host}` : undefined);
      const result = await PaymentStore.approvePaymentRequest(requestId, cleanAdminEmail, notes, baseUrl);
      res.json({
        success: true,
        message: `Payment request approved by ${cleanAdminEmail}. Reader entitlement granted.`,
        request: result.request,
        entitlement: result.entitlement,
      });
    } catch (err: any) {
      console.error('[POCHI APPROVE ERROR]', err.message);
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Admin: Reject a payment verification request
  app.post('/api/admin/payment-requests/:requestId/reject', requireAdminAuth, async (req, res) => {
    const { requestId } = req.params;
    const verifiedAdmin = (req as any).adminUser?.email || (req.body.adminEmail as string) || 'Authorized Admin';
    const cleanAdminEmail = verifiedAdmin.trim().toLowerCase();
    const reason = req.body.reason || 'Payment could not be verified in Pochi records.';

    try {
      const result = await PaymentStore.rejectPaymentRequest(requestId, cleanAdminEmail, reason);
      res.json({
        success: true,
        message: `Payment request rejected by ${cleanAdminEmail}. Access remains locked.`,
        request: result.request,
      });
    } catch (err: any) {
      console.error('[POCHI REJECT ERROR]', err.message);
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Admin: Reassign or update the exact administrator email mapped with an approval
  app.post('/api/admin/payment-requests/:requestId/reassign-approver', requireAdminAuth, async (req, res) => {
    const { requestId } = req.params;
    const { adminEmail } = req.body;
    if (!adminEmail) {
      return res.status(400).json({ error: 'adminEmail is required' });
    }
    const cleanAdminEmail = (adminEmail as string).trim().toLowerCase();
    try {
      const updated = await PaymentStore.updateRequestApprover(requestId, cleanAdminEmail);
      res.json({
        success: true,
        message: `Approval attribution updated to ${cleanAdminEmail}`,
        request: updated,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message });
    }
  });

  // Admin: Permanently Revoke & Expunge User
  app.post('/api/admin/users/delete', requireAdminAuth, async (req, res) => {
    const { userIdentifier, email, uid, requestId } = req.body;
    const verifiedAdmin = (req as any).adminUser?.email || (req.body.adminEmail as string) || 'Authorized Admin';
    const target = userIdentifier || email || uid || requestId;

    if (!target) {
      return res.status(400).json({ success: false, error: 'User identifier (email, uid, or requestId) is required for deletion.' });
    }

    try {
      const result = await PaymentStore.deleteAndRevokeUser(target, verifiedAdmin);
      res.json(result);
    } catch (err: any) {
      console.error('[ADMIN DELETE USER ERROR]', err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.delete('/api/admin/users/:userIdentifier', requireAdminAuth, async (req, res) => {
    const { userIdentifier } = req.params;
    const verifiedAdmin = (req as any).adminUser?.email || 'Authorized Admin';
    try {
      const result = await PaymentStore.deleteAndRevokeUser(userIdentifier, verifiedAdmin);
      res.json(result);
    } catch (err: any) {
      console.error('[ADMIN DELETE USER ERROR]', err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Admin: Update Pochi la Biashara configuration
  app.post('/api/admin/config/pochi', requireAdminAuth, (req, res) => {
    const { pochiPhone, pochiName, priceKes, instructions } = req.body;
    PaymentStore.updatePochiConfig({
      pochiPhone,
      pochiName,
      priceKes: priceKes ? Number(priceKes) : undefined,
      instructions,
    });
    res.json({
      success: true,
      message: 'Pochi la Biashara configuration updated.',
      config: PaymentStore.getPochiConfig(),
    });
  });

  // Admin / Versioning API
  app.get('/api/admin/versions', (req, res) => {
    res.json({
      bookId: 'dating-wrong',
      activeVersion: 1,
      versions: [
        {
          version: 1,
          label: 'Version 1.0 (Official First Edition)',
          pageCount: MANUSCRIPT_V1.metadata.pageCount,
          wordCount: MANUSCRIPT_V1.metadata.wordCount,
          publishedAt: MANUSCRIPT_V1.metadata.publishedAt,
          active: true,
          storagePath: 'books/dating-wrong/v1',
          sectionsCount: MANUSCRIPT_V1.sections.length,
          copyright: MANUSCRIPT_V1.metadata.copyright,
          publisher: MANUSCRIPT_V1.metadata.publisher,
        },
      ],
    });
  });

  // Frontend hosting is handled by Vercel's static output in production.
  // Only attach Vite/Express static middleware when running the standalone server.
  if (serveFrontend && process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else if (serveFrontend) {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  return app;
}

async function startServer() {
  const app = await createApp({ serveFrontend: true });
  const PORT = Number(process.env.PORT) || 3000;
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Dating Wrong platform running on http://0.0.0.0:${PORT}`);
    console.log('Daraja M-PESA STK Push gateway initialized for Mark & Alvis Publishers');
    console.log('Admin alert dispatch active for Gerishon Wanyeki, Alvis Njagi, and Mark');
  });
  server.on('error', (err: any) => {
    if (err.code === 'EADDRINUSE') console.warn(`[SERVER WARNING] Port ${PORT} already bound or in use by dev supervisor.`);
    else console.error('[SERVER ERROR]', err);
  });
}

if (process.env.VERCEL !== '1') {
  void startServer();
}
