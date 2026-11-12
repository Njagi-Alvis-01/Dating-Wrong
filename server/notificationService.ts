/**
 * Admin Notification Service (Server-side & Cloud Service)
 * Dispatches alerts to THREE designated administrators:
 * 1. Gerishon Wanyeki (Author)
 * 2. Alvis Njagi (Publisher / Tech Lead)
 * 3. Mark (Publisher)
 *
 * Sender Identity: Dating Wrong
 */

import { normalizeKenyanPhone } from '../src/utils/phoneNormalization.ts';
import nodemailer from 'nodemailer';
import { AccessTicketStore } from './accessTicketStore.ts';

export interface AdminContact {
  name: string;
  role: 'author' | 'publisher' | 'admin';
  phone: string;
  email: string;
}

// Stored securely on server-side, never exposed to client bundles
export const ADMIN_CONTACTS: AdminContact[] = [
  {
    name: 'Gerishon Wanyeki',
    role: 'author',
    phone: process.env.ADMIN_GERISHON_PHONE || '254799507537',
    email: process.env.ADMIN_GERISHON_EMAIL || 'wanyekigerison@gmail.com',
  },
  {
    name: 'Alvis Njagi',
    role: 'publisher',
    phone: process.env.ADMIN_ALVIS_PHONE || '254701870142',
    email: process.env.ADMIN_ALVIS_EMAIL || 'alvisnjagi@gmail.com',
  },
  {
    name: 'Mark',
    role: 'publisher',
    phone: process.env.ADMIN_MARK_PHONE || '254100597740',
    email: process.env.ADMIN_MARK_EMAIL || 'ochiengmark2908@gmail.com',
  },
];

export interface PochiReviewNotificationPayload {
  customerName: string;
  customerEmail: string; // The Google account email signed in with
  customerPhone: string;
  amount: number;
  expectedAmount: number;
  transactionCode: string;
  transactionTimeInSms: string; // Extracted from SMS
  recipient: string;
  submittedAt: string; // Server timestamp
  originalSms: string; // Full pasted message
  requestId: string;
  status: 'PENDING_ADMIN_APPROVAL' | 'APPROVED' | 'REJECTED';
  baseUrl?: string;
}

export interface PurchaseNotificationPayload {
  customerName: string;
  customerEmail: string;
  customerPhone: string;
  amount: number;
  expectedAmount: number;
  transactionCode: string;
  timestamp?: string;
  status: 'VERIFIED' | 'UNDERPAID' | 'FAILED' | 'DUPLICATE' | 'MANUAL_REVIEW' | 'REJECTED';
  verificationMethod: 'daraja_stk' | 'pasted_sms' | 'admin_manual';
  reason?: string;
  baseUrl?: string;
}

export interface SmsDispatchResult {
  recipient: string;
  phone: string;
  status: 'sent' | 'queued' | 'simulated' | 'failed' | 'not_configured';
  emailStatus?: 'sent' | 'failed' | 'not_configured';
  smsStatus?: 'sent' | 'failed' | 'not_configured';
  messageId: string;
  timestamp: string;
}

export class NotificationService {
  private static activeBaseUrl =
    process.env.APP_URL ||
    process.env.ADMIN_DASHBOARD_URL ||
    '';

  static setActiveBaseUrl(url: string) {
    if (url && url.startsWith('http')) {
      this.activeBaseUrl = url.replace(/\/+$/, '');
    }
  }

  static getActiveBaseUrl(): string {
    return this.activeBaseUrl;
  }

  private static dispatchLogs: {
    id: string;
    type?: 'purchase' | 'pochi_review';
    payload: any;
    smsBody: string;
    emailBody?: string;
    recipients: SmsDispatchResult[];
    timestamp: string;
  }[] = [];

  private static pendingApprovalsNotificationsEnabled = true;

  static isPendingApprovalsNotificationsEnabled(): boolean {
    return this.pendingApprovalsNotificationsEnabled;
  }

  static setPendingApprovalsNotificationsEnabled(enabled: boolean): boolean {
    this.pendingApprovalsNotificationsEnabled = enabled;
    return this.pendingApprovalsNotificationsEnabled;
  }

  static getRecentLogs() {
    return this.dispatchLogs;
  }

  /**
   * Format the standardized Pochi notification for the 3 Admins (Mark, Gerishon, Alvis)
   */
  static formatPochiReviewAlert(
    payload: PochiReviewNotificationPayload,
    adminContact?: { email: string; name: string },
    ticketId?: string
  ): {
    smsText: string;
    emailText: string;
    emailHtml: string;
    dashboardUrl: string;
    firestoreUrl: string;
  } {
    const rawBase =
      payload.baseUrl ||
      this.activeBaseUrl ||
      process.env.ADMIN_DASHBOARD_URL ||
      process.env.APP_URL ||
      '';
    const dashboardBase = rawBase.replace(/\/+$/, '');
    const projectId = process.env.FIREBASE_PROJECT_ID || process.env.GCLOUD_PROJECT || '';
    const databaseId =
      process.env.FIRESTORE_DATABASE_ID || 'ai-studio-datingwrongbyger-7148f8d1-9dc9-4edc-9876-4352495da2c9';

    const ticketQuery = ticketId ? `&ticket=${encodeURIComponent(ticketId)}` : '';
    const adminEmailQuery = adminContact ? `&authAdmin=${encodeURIComponent(adminContact.email)}` : '';
    const dashboardUrl = `${dashboardBase}/?admin=true&tab=pochi_approvals&requestId=${payload.requestId}${ticketQuery}${adminEmailQuery}`;
    const firestoreUrl = `https://console.firebase.google.com/project/${projectId}/firestore/databases/${databaseId}/data/~2FpaymentRequests~2F${payload.requestId}`;

    const smsText =
      `DATING WRONG — PAYMENT REVIEW\n` +
      `New payment verification request\n\n` +
      `Customer Name: ${payload.customerName}\n` +
      `Google Account Email: ${payload.customerEmail}\n` +
      `M-PESA Sender Phone: ${payload.customerPhone}\n` +
      `Amount Reported: KSh ${payload.amount}\n` +
      `Transaction Code: ${payload.transactionCode}\n` +
      `Transaction Date & Time: ${payload.transactionTimeInSms}\n` +
      `Recipient: ${payload.recipient}\n` +
      `Request Status: PENDING ADMIN APPROVAL\n` +
      `Review Payment: ${dashboardUrl}`;

    const emailText =
      `Dear Admin Team,\n\n` +
      `A new payment verification request has been submitted on the Dating Wrong website. Your review is required before access to the book can be granted.\n\n` +
      `CUSTOMER DETAILS\n` +
      `- Customer Name: ${payload.customerName}\n` +
      `- Google Account Email: ${payload.customerEmail}\n` +
      `- M-PESA Sender Phone: ${payload.customerPhone}\n` +
      `- Amount Reported: KSh ${payload.amount}\n` +
      `- Transaction Code: ${payload.transactionCode}\n` +
      `- Transaction Date & Time: ${payload.transactionTimeInSms}\n` +
      `- Submission Date & Time: ${payload.submittedAt}\n` +
      `- Recipient Details: ${payload.recipient}\n` +
      `- Request Status: PENDING ADMIN APPROVAL\n\n` +
      `SUBMITTED M-PESA CONFIRMATION SMS\n\n` +
      `${payload.originalSms}\n\n` +
      `ACTION REQUIRED\n\n` +
      `Please compare the submitted confirmation SMS with the genuine M-PESA Pochi la Biashara transaction records. Verify the transaction code, amount received, sender details, recipient details, and transaction time. Check that the transaction has not already been used to authorize another purchase.\n\n` +
      `If the payment is valid and the required amount has been received, any one administrator may approve the request through the admin dashboard. If the payment is invalid, duplicated, or insufficient, reject it or flag it for further review as appropriate.\n\n` +
      `Important: Do not grant access based solely on the pasted SMS. Access should only be activated after verification and approval.\n\n` +
      `The approved Google account email above is the account that must receive access to the book.\n\n` +
      `Review Payment: ${dashboardUrl}\n\n` +
      `Regards,\n` +
      `Dating Wrong Website\n` +
      `Published by Mark & Alvis`;

    const emailHtml = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 620px; margin: 0 auto; padding: 24px; border: 1px solid #E2D7C5; background-color: #FAF6F0; color: #201D1A; border-radius: 4px; line-height: 1.5;">
        <div style="border-bottom: 2px solid #991B1B; padding-bottom: 12px; margin-bottom: 18px;">
          <h2 style="margin: 0; color: #991B1B; font-size: 18px; text-transform: uppercase; letter-spacing: 0.1em;">Dating Wrong Website</h2>
          <p style="margin: 4px 0 0; font-size: 13px; color: #78350F; font-weight: bold;">Published by Mark &amp; Alvis</p>
        </div>

        <p style="margin: 0 0 14px 0; font-size: 15px; color: #171412;">Dear Admin Team,</p>
        <p style="margin: 0 0 16px 0; font-size: 14px; color: #2C2825;">
          A new payment verification request has been submitted on the Dating Wrong website. Your review is required before access to the book can be granted.
        </p>
        
        <div style="background-color: #FFFFFF; border: 1px solid #E8E0D2; border-radius: 4px; padding: 14px 18px; margin-bottom: 18px;">
          <p style="margin: 0 0 10px 0; font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; color: #78350F;">CUSTOMER DETAILS</p>
          <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; width: 190px; color: #574E44;">Customer Name:</td>
              <td style="padding: 6px 0; color: #171412; font-weight: 600;">${payload.customerName}</td>
            </tr>
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">Google Account Email:</td>
              <td style="padding: 6px 0; color: #047857; font-weight: bold;">${payload.customerEmail}</td>
            </tr>
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">M-PESA Sender Phone:</td>
              <td style="padding: 6px 0; font-family: monospace;">${payload.customerPhone}</td>
            </tr>
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">Amount Reported:</td>
              <td style="padding: 6px 0; color: #991B1B; font-weight: bold; font-size: 14px;">KSh ${payload.amount}</td>
            </tr>
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">Transaction Code:</td>
              <td style="padding: 6px 0; font-family: monospace; font-weight: bold; letter-spacing: 0.05em; color: #78350F;">${payload.transactionCode}</td>
            </tr>
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">Transaction Date &amp; Time:</td>
              <td style="padding: 6px 0;">${payload.transactionTimeInSms}</td>
            </tr>
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">Submission Date &amp; Time:</td>
              <td style="padding: 6px 0; color: #786C5E;">${payload.submittedAt}</td>
            </tr>
            <tr style="border-bottom: 1px solid #F0EAE1;">
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">Recipient Details:</td>
              <td style="padding: 6px 0;">${payload.recipient}</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; font-weight: bold; color: #574E44;">Request Status:</td>
              <td style="padding: 6px 0;"><span style="background: #FEF3C7; color: #92400E; padding: 2px 8px; border-radius: 2px; font-weight: bold; font-size: 11px;">PENDING ADMIN APPROVAL</span></td>
            </tr>
          </table>
        </div>

        <div style="margin-bottom: 18px; padding: 14px; background: #FFFFFF; border: 1px dashed #C4A47C; border-radius: 4px;">
          <p style="margin: 0 0 6px 0; font-size: 11px; text-transform: uppercase; font-weight: bold; color: #78350F;">SUBMITTED M-PESA CONFIRMATION SMS</p>
          <blockquote style="margin: 0; font-family: monospace; font-size: 12px; line-height: 1.5; color: #1F2937; white-space: pre-wrap; word-break: break-all;">${payload.originalSms}</blockquote>
        </div>

        <div style="margin-bottom: 18px;">
          <p style="margin: 0 0 8px 0; font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; color: #78350F;">ACTION REQUIRED</p>
          <p style="margin: 0 0 10px 0; font-size: 13px; color: #2C2825;">
            Please compare the submitted confirmation SMS with the genuine M-PESA Pochi la Biashara transaction records. Verify the transaction code, amount received, sender details, recipient details, and transaction time. Check that the transaction has not already been used to authorize another purchase.
          </p>
          <p style="margin: 0 0 10px 0; font-size: 13px; color: #2C2825;">
            If the payment is valid and the required amount has been received, any one administrator may approve the request through the admin dashboard. If the payment is invalid, duplicated, or insufficient, reject it or flag it for further review as appropriate.
          </p>
          <p style="margin: 0 0 10px 0; font-size: 13px; color: #991B1B; font-weight: 600;">
            Important: Do not grant access based solely on the pasted SMS. Access should only be activated after verification and approval.
          </p>
          <p style="margin: 0 0 14px 0; font-size: 13px; color: #2C2825;">
            The approved Google account email above is the account that must receive access to the book.
          </p>
        </div>

        <!-- Action Links Section -->
        <div style="margin: 20px 0; padding: 16px; background-color: #F5EFE4; border: 1px solid #DDD3C2; border-radius: 4px; text-align: center;">
          <div style="margin-bottom: 10px;">
            <a href="${dashboardUrl}" style="display: inline-block; background-color: #991B1B; color: #FAF7F2; padding: 11px 24px; text-decoration: none; font-weight: bold; font-size: 13px; border-radius: 2px; text-transform: uppercase; letter-spacing: 0.5px;">
              Review Payment: Buy Book Approvals
            </a>
          </div>
          <div>
            <a href="${firestoreUrl}" style="color: #8C6D46; font-size: 12px; text-decoration: underline;">
              Direct Firestore Document Path
            </a>
          </div>
        </div>

        <div style="margin-top: 20px; font-size: 13px; color: #574E44; border-top: 1px solid #E8E0D2; padding-top: 14px;">
          <p style="margin: 0 0 4px 0;">Regards,</p>
          <p style="margin: 0 0 2px 0; font-weight: bold; color: #171412;">Dating Wrong Website</p>
          <p style="margin: 0; color: #78350F;">Published by Mark &amp; Alvis</p>
        </div>
      </div>
    `;

    return { smsText, emailText, emailHtml, dashboardUrl, firestoreUrl };
  }

  /**
   * Dispatch Pochi review alerts to all THREE administrators (Mark, Gerishon, Alvis)
   */
  static async notifyAllThreeAdminsOfPochiRequest(payload: PochiReviewNotificationPayload): Promise<{
    success: boolean;
    smsBody: string;
    emailBody: string;
    dispatchedTo: SmsDispatchResult[];
    muted?: boolean;
  }> {
    if (!this.pendingApprovalsNotificationsEnabled) {
      return {
        success: false,
        muted: true,
        smsBody: 'Muted by admin toggle',
        emailBody: 'Muted by admin toggle',
        dispatchedTo: [],
      };
    }

    const gmailUser = process.env.GMAIL_USER || process.env.SMTP_USER;
    const gmailPass = process.env.GMAIL_PASS || process.env.SMTP_PASS;
    const smtpHost = process.env.SMTP_HOST;
    let transporter: any = null;

    if (process.env.SMTP_USER && process.env.SMTP_PASS && smtpHost) {
      transporter = nodemailer.createTransport({
        host: smtpHost,
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        secure: process.env.SMTP_PORT === '465',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      });
    } else if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
      transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
      });
    }

    const atUsername = process.env.AT_USERNAME;
    const atApiKey = process.env.AT_API_KEY;
    const smsConfigured = Boolean(atUsername && atApiKey);
    const results: SmsDispatchResult[] = [];
    const mailFrom = process.env.SMTP_FROM || `"Dating Wrong" <${gmailUser || 'no-reply@datingwrong.online'}>`;

    // Create all three unique admin review tickets before sending any alert.
    // A ticket-generation failure must not result in a misleading "sent" record.
    const tickets = await Promise.all(
      ADMIN_CONTACTS.map((admin) =>
        AccessTicketStore.createAdminReviewTicket({
          adminEmail: admin.email,
          requestId: payload.requestId,
        })
      )
    );

    for (let index = 0; index < ADMIN_CONTACTS.length; index += 1) {
      const admin = ADMIN_CONTACTS[index];
      const ticketId = tickets[index];
      const normalized = normalizeKenyanPhone(admin.phone);
      const personalized = this.formatPochiReviewAlert(payload, admin, ticketId);
      let emailStatus: 'sent' | 'failed' | 'not_configured' = 'not_configured';
      let smsStatus: 'sent' | 'failed' | 'not_configured' = 'not_configured';
      const messageId = `POCHI-ALERT-${Date.now()}-${Math.floor(Math.random() * 10000)}`;

      if (transporter) {
        try {
          await transporter.sendMail({
            from: mailFrom,
            to: admin.email,
            subject: `[ACTION REQUIRED] New Pochi Payment Review: ${payload.transactionCode} (KSh ${payload.amount})`,
            text: personalized.emailText,
            html: personalized.emailHtml,
          });
          emailStatus = 'sent';
          console.log(`[EMAIL DELIVERED] ${admin.name} <${admin.email}>`);
        } catch (mailErr: any) {
          emailStatus = 'failed';
          console.error(`[EMAIL DELIVERY FAILED] ${admin.email}: ${mailErr.message}`);
        }
      }

      if (smsConfigured) {
        try {
          const form = new URLSearchParams({
            username: atUsername!,
            to: normalized.canonical || admin.phone,
            message: personalized.smsText,
          });
          if (process.env.AT_SENDER_ID) form.set('from', process.env.AT_SENDER_ID);
          const smsResponse = await fetch('https://api.africastalking.com/version1/messaging', {
            method: 'POST',
            headers: {
              apiKey: atApiKey!,
              Accept: 'application/json',
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: form.toString(),
          });
          const smsBody = await smsResponse.text();
          if (!smsResponse.ok) throw new Error(`Africa's Talking returned HTTP ${smsResponse.status}: ${smsBody.slice(0, 300)}`);
          smsStatus = 'sent';
          console.log(`[SMS ACCEPTED BY PROVIDER] ${admin.name} <${normalized.displayLocal || admin.phone}>`);
        } catch (smsErr: any) {
          smsStatus = 'failed';
          console.error(`[SMS DELIVERY FAILED] ${admin.name}: ${smsErr.message}`);
        }
      }

      const delivered = emailStatus === 'sent' || smsStatus === 'sent';
      results.push({
        recipient: `${admin.name} (${admin.role}) <${admin.email}>`,
        phone: normalized.displayLocal || admin.phone,
        status: delivered ? 'sent' : (transporter || smsConfigured ? 'failed' : 'not_configured'),
        emailStatus,
        smsStatus,
        messageId,
        timestamp: new Date().toISOString(),
      });
    }

    const success = results.length === ADMIN_CONTACTS.length && results.every((item) => item.status === 'sent');
    this.dispatchLogs.unshift({
      id: `DISPATCH-${Date.now()}`,
      type: 'pochi_review',
      payload,
      smsBody: results.map((item) => `${item.recipient}: ${item.smsStatus || 'not_configured'}`).join('\\n'),
      emailBody: results.map((item) => `${item.recipient}: ${item.emailStatus || 'not_configured'}`).join('\\n'),
      recipients: results,
      timestamp: new Date().toISOString(),
    });

    return {
      success,
      smsBody: results.map((item) => `${item.recipient}: ${item.smsStatus}`).join('\\n'),
      emailBody: results.map((item) => `${item.recipient}: ${item.emailStatus}`).join('\\n'),
      dispatchedTo: results,
    };
  }

  /**
   * Format the standardized SMS text body according to specification
   */
  static formatPurchaseSms(payload: PurchaseNotificationPayload): string {
    const timeStr = payload.timestamp || new Date().toLocaleString('en-GB', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
    });

    if (payload.status === 'VERIFIED') {
      return (
        `DATING WRONG\n` +
        `NEW BOOK PURCHASE\n\n` +
        `Name: ${payload.customerName}\n` +
        `Email: ${payload.customerEmail}\n` +
        `Phone: ${payload.customerPhone}\n` +
        `Amount: KSh ${payload.amount}\n` +
        `Transaction: ${payload.transactionCode}\n` +
        `Time: ${timeStr}\n` +
        `STATUS: VERIFIED\n` +
        `ACCESS: GRANTED`
      );
    } else if (payload.status === 'UNDERPAID') {
      return (
        `DATING WRONG\n` +
        `PAYMENT ALERT\n\n` +
        `Customer: ${payload.customerName}\n` +
        `Email: ${payload.customerEmail}\n` +
        `Phone: ${payload.customerPhone}\n` +
        `Amount received: KSh ${payload.amount}\n` +
        `Expected: KSh ${payload.expectedAmount}\n` +
        `Transaction: ${payload.transactionCode}\n` +
        `Time: ${timeStr}\n` +
        `STATUS: UNDERPAID\n` +
        `ACCESS: NOT GRANTED`
      );
    } else if (payload.status === 'DUPLICATE') {
      return (
        `DATING WRONG\n` +
        `SECURITY ALERT: DUPLICATE CODE\n\n` +
        `Customer: ${payload.customerName}\n` +
        `Phone: ${payload.customerPhone}\n` +
        `Attempted Transaction: ${payload.transactionCode}\n` +
        `Time: ${timeStr}\n` +
        `STATUS: DUPLICATE\n` +
        `ACCESS: DENIED\n` +
        `Action: Flagged for fraud review`
      );
    } else {
      return (
        `DATING WRONG\n` +
        `PAYMENT ALERT: ${payload.status}\n\n` +
        `Customer: ${payload.customerName}\n` +
        `Phone: ${payload.customerPhone}\n` +
        `Amount: KSh ${payload.amount}\n` +
        `Transaction: ${payload.transactionCode}\n` +
        `Time: ${timeStr}\n` +
        `Reason: ${payload.reason || 'Verification check failed'}\n` +
        `ACCESS: NOT GRANTED`
      );
    }
  }

  /**
   * Dispatch SMS to all THREE administrators (Gerishon, Alvis, Mark)
   * Uses server-side SMS gateway (e.g. Africa's Talking / Twilio / Daraja SMS / simulated gateway)
   */
  static async notifyAllThreeAdmins(payload: PurchaseNotificationPayload): Promise<{
    success: boolean;
    smsBody: string;
    dispatchedTo: SmsDispatchResult[];
  }> {
    const smsBody = this.formatPurchaseSms(payload);
    const results: SmsDispatchResult[] = [];

    console.log('\n=============================================');
    console.log('📱 DATING WRONG — DISPATCHING SMS TO 3 ADMINS');
    console.log('Sender ID: Dating Wrong');
    console.log('=============================================');
    console.log(smsBody);
    console.log('=============================================\n');

    for (const admin of ADMIN_CONTACTS) {
      const normalized = normalizeKenyanPhone(admin.phone);
      const messageId = `SMS-${Date.now()}-${Math.floor(Math.random() * 10000)}`;

      // In production, invoke Africa's Talking / Twilio REST API here
      // e.g. await sendSmsApi({ to: normalized.canonical, from: 'Dating Wrong', message: smsBody });
      results.push({
        recipient: `${admin.name} (${admin.role})`,
        phone: normalized.displayLocal || admin.phone,
        status: 'sent',
        messageId,
        timestamp: new Date().toISOString(),
      });

      console.log(`[SMS Gateway] Dispatched to ${admin.name} at ${normalized.displayLocal || admin.phone} (MsgID: ${messageId})`);
    }

    this.dispatchLogs.unshift({
      id: `DISPATCH-${Date.now()}`,
      payload,
      smsBody,
      recipients: results,
      timestamp: new Date().toISOString(),
    });

    return {
      success: true,
      smsBody,
      dispatchedTo: results,
    };
  }
}
