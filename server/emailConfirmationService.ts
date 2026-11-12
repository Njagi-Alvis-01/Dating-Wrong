/**
 * Customer Email Confirmation Service (Section 37)
 *
 * Dispatches formal purchase confirmation to customer:
 * - Subject: Your Dating Wrong book is ready
 * - Message contains:
 *   - purchase confirmed
 *   - amount
 *   - transaction reference
 *   - account email
 *   - book access
 *   - READ THE BOOK button
 *
 * Critical: DO NOT send the actual master PDF as an email attachment.
 */

import nodemailer from 'nodemailer';
import { AccessTicketStore } from './accessTicketStore.ts';
import { fsQuery, fsSetDoc } from './firestoreAdapter.ts';

export interface EmailConfirmationParams {
  customerEmail: string;
  customerName: string;
  amount: number;
  currency: string;
  transactionReference: string;
  accessUrl: string;
  purchasedAt: string;
}

export interface EmailLogEntry {
  id: string;
  to: string;
  subject: string;
  sentAt: string;
  transactionReference: string;
  status: 'SENT' | 'SIMULATED' | 'FAILED';
  bodyText: string;
  bodyHtml: string;
}

export class EmailConfirmationService {
  private static emailLogs: EmailLogEntry[] = [];
  private static activeBaseUrl =
    process.env.APP_URL ||
    '';

  static setActiveBaseUrl(url: string) {
    if (url && url.startsWith('http')) {
      this.activeBaseUrl = url.replace(/\/+$/, '');
    }
  }

  static getActiveBaseUrl(): string {
    return this.activeBaseUrl;
  }

  private static getTransporter(): any {
    const gmailUser = process.env.GMAIL_USER || process.env.SMTP_USER;
    const gmailPass = process.env.GMAIL_PASS || process.env.SMTP_PASS;

    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
      try {
        return nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port: parseInt(process.env.SMTP_PORT || '587', 10),
          secure: process.env.SMTP_PORT === '465',
          auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });
      } catch (err) {
        console.warn('[Customer Email Confirmation SMTP Transport Warning]', err);
      }
    } else if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
      try {
        return nodemailer.createTransport({
          service: 'gmail',
          auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
        });
      } catch (err) {
        console.warn('[Customer Email Confirmation Gmail Transport Warning]', err);
      }
    }
    return null;
  }

  static async sendBookReadyEmail(params: EmailConfirmationParams): Promise<{ success: boolean; log: EmailLogEntry }> {
    const subject = 'Good news! Your payment for Dating Wrong has been verified and approved';
    const amountVal = params.amount || 750;
    const cleanUrl =
      params.accessUrl && !params.accessUrl.includes('datingwrong.ke')
        ? params.accessUrl.replace(/\/+$/, '')
        : this.activeBaseUrl;

    // Cryptographically generated single-use OTP token strictly mapped to this customer's email
    const ticketToken = await AccessTicketStore.createCustomerReaderTicket({
      email: params.customerEmail,
      requestId: params.transactionReference,
      transactionCode: params.transactionReference,
    });
    const readerUrl = `${cleanUrl}/?reader=true&email=${encodeURIComponent(params.customerEmail)}&ticket=${ticketToken}`;

    const bodyText = `
Dear ${params.customerName},

Good news! Your payment for Dating Wrong has been verified and approved.

Thank you for purchasing Dating Wrong by Gerishon Wanyeki. Your payment has been accepted, and access to the book has been activated for your Google account:

Account email: ${params.customerEmail}
Amount paid: KSh ${amountVal}
M-PESA transaction code: ${params.transactionReference}

You can now sign in to the Dating Wrong website using the same Google account and click Read the Book to begin reading.

We hope this book gives you meaningful insights into love, relationships, personal growth, and the wisdom of choosing well.

Thank you for supporting Dating Wrong and being part of this journey.

Warm regards,
The Dating Wrong Team
Published by Mark & Alvis
    `.trim();

    const bodyHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Newsreader', Georgia, serif; background-color: #F5F2EA; color: #201D1A; padding: 32px 16px; margin: 0; line-height: 1.6; }
    .container { max-width: 580px; margin: 0 auto; background-color: #FCFAF6; border: 1px solid #E2D7C5; padding: 40px; border-radius: 4px; }
    .header { text-align: center; border-bottom: 1px solid #E8E0D2; padding-bottom: 24px; margin-bottom: 28px; }
    .logo { font-size: 18px; font-weight: bold; letter-spacing: 2px; color: #78350F; text-transform: uppercase; font-family: sans-serif; }
    .h1 { font-size: 24px; font-weight: normal; margin: 12px 0 6px 0; color: #1C1917; }
    .subtitle { font-size: 13px; color: #2E6B34; font-weight: bold; }
    .content { font-size: 15px; color: #2C2825; }
    .box { background-color: #F5EFE4; border: 1px solid #DFD5C3; padding: 18px 20px; border-radius: 2px; margin: 24px 0; font-family: sans-serif; font-size: 13px; }
    .row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px dashed #DDD2BE; }
    .row:last-child { border-bottom: none; }
    .btn-container { text-align: center; margin: 32px 0; }
    .btn { display: inline-block; background-color: #78350F; color: #FAF7F2 !important; text-decoration: none; padding: 14px 34px; font-family: sans-serif; font-size: 13px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; border-radius: 2px; }
    .footer { font-size: 13px; color: #574E44; text-align: left; margin-top: 32px; border-top: 1px solid #E8E0D2; padding-top: 20px; font-family: 'Newsreader', Georgia, serif; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">Dating Wrong</div>
      <h1 class="h1">Payment Verified &amp; Approved</h1>
      <p class="subtitle">Access activated for your Google account</p>
    </div>

    <div class="content">
      <p>Dear ${params.customerName},</p>
      
      <p><strong>Good news! Your payment for Dating Wrong has been verified and approved.</strong></p>
      
      <p>Thank you for purchasing <em>Dating Wrong</em> by Gerishon Wanyeki. Your payment has been accepted, and access to the book has been activated for your Google account:</p>
      
      <div class="box">
        <div class="row"><span>Account email:</span><strong>${params.customerEmail}</strong></div>
        <div class="row"><span>Amount paid:</span><strong style="color: #78350F;">KSh ${amountVal}</strong></div>
        <div class="row"><span>M-PESA transaction code:</span><strong style="font-family: monospace;">${params.transactionReference}</strong></div>
      </div>

      <p>You can now sign in to the Dating Wrong website using the same Google account and click <strong>Read the Book</strong> to begin reading.</p>

      <div class="btn-container">
        <a href="${readerUrl}" class="btn">Read the Book</a>
      </div>

      <p>We hope this book gives you meaningful insights into love, relationships, personal growth, and the wisdom of choosing well.</p>

      <p>Thank you for supporting Dating Wrong and being part of this journey.</p>
    </div>

    <div class="footer">
      <p style="margin: 0 0 4px 0;">Warm regards,</p>
      <p style="margin: 0 0 2px 0; font-weight: bold; color: #171412;">The Dating Wrong Team</p>
      <p style="margin: 0; color: #78350F;">Published by Mark &amp; Alvis</p>
    </div>
  </div>
</body>
</html>
    `.trim();

    let dispatchStatus: 'SENT' | 'SIMULATED' | 'FAILED' = process.env.VERCEL === '1' ? 'FAILED' : 'SIMULATED';
    const transporter = this.getTransporter();
    const mailUser = process.env.GMAIL_USER || process.env.SMTP_USER || 'orders@datingwrong.ke';
    const fromAddress = process.env.SMTP_FROM || `"Dating Wrong" <${mailUser}>`;

    if (transporter) {
      try {
        await transporter.sendMail({
          from: fromAddress,
          to: params.customerEmail,
          subject,
          text: bodyText,
          html: bodyHtml,
        });
        dispatchStatus = 'SENT';
        console.log(`[Email Confirmation Delivered] Real approval email sent to ${params.customerEmail} from ${fromAddress}`);
      } catch (err: any) {
        dispatchStatus = 'FAILED';
        console.warn(`[Email Confirmation Delivery Failed to ${params.customerEmail}]`, err.message);
      }
    }

    const log: EmailLogEntry = {
      id: `EMAIL-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      to: params.customerEmail,
      subject,
      sentAt: new Date().toISOString(),
      transactionReference: params.transactionReference,
      status: dispatchStatus,
      bodyText,
      bodyHtml,
    };

    await this.recordEmailLog(log);
    console.log(`[Email Confirmation] Recorded "${subject}" to ${params.customerEmail} for ref ${params.transactionReference} (Status: ${dispatchStatus})`);

    return { success: dispatchStatus === 'SENT', log };
  }

  /**
   * Customer Rejection Email Notification
   * Dispatched to the customer whenever an administrator rejects a payment request.
   */
  static async sendPaymentRejectionEmail(params: {
    customerEmail: string;
    customerName: string;
    rejectionReason: string;
    supportUrl?: string;
  }): Promise<{ success: boolean; log: EmailLogEntry }> {
    const subject = 'Dating Wrong — Payment Verification Unsuccessful';
    const effectiveReason = params.rejectionReason || 'Payment could not be verified in official M-PESA records.';
    const supportLink = params.supportUrl || 'https://datingwrong.ke';

    const bodyText = `
Dear ${params.customerName},

Unfortunately, your M-PESA payment could not be verified, and access to Dating Wrong has not been granted.

Reason: ${effectiveReason}

If you believe this decision was made in error, please contact our support team for assistance.

Thank you for your understanding.

Regards,
Dating Wrong Team
Published by Mark & Alvis
    `.trim();

    const bodyHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Newsreader', Georgia, serif; background-color: #F5F2EA; color: #201D1A; padding: 32px 16px; margin: 0; line-height: 1.6; }
    .container { max-width: 580px; margin: 0 auto; background-color: #FCFAF6; border: 1px solid #E2D7C5; padding: 40px; border-radius: 4px; }
    .header { text-align: center; border-bottom: 1px solid #E8E0D2; padding-bottom: 24px; margin-bottom: 28px; }
    .logo { font-size: 18px; font-weight: bold; letter-spacing: 2px; color: #991B1B; text-transform: uppercase; font-family: sans-serif; }
    .h1 { font-size: 22px; font-weight: normal; margin: 12px 0 6px 0; color: #1C1917; }
    .subtitle { font-size: 13px; color: #991B1B; font-weight: bold; }
    .content { font-size: 15px; color: #2C2825; }
    .reason-box { background-color: #FEF2F2; border: 1px solid #FECACA; padding: 18px 20px; border-radius: 4px; margin: 22px 0; font-family: sans-serif; }
    .reason-label { font-size: 11px; text-transform: uppercase; font-weight: bold; color: #991B1B; letter-spacing: 0.05em; margin-bottom: 6px; }
    .reason-text { font-size: 14px; color: #7F1D1D; font-weight: 600; margin: 0; }
    .footer { font-size: 13px; color: #574E44; text-align: left; margin-top: 32px; border-top: 1px solid #E8E0D2; padding-top: 20px; font-family: 'Newsreader', Georgia, serif; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">Dating Wrong</div>
      <h1 class="h1">Payment Verification Unsuccessful</h1>
      <p class="subtitle">Access has not been granted</p>
    </div>

    <div class="content">
      <p>Dear ${params.customerName},</p>
      
      <p>Unfortunately, your M-PESA payment could not be verified, and access to Dating Wrong has not been granted.</p>
      
      <div class="reason-box">
        <div class="reason-label">Reason:</div>
        <p class="reason-text">${effectiveReason}</p>
      </div>

      <p>If you believe this decision was made in error, please contact our support team for assistance.</p>

      <p>Thank you for your understanding.</p>
    </div>

    <div class="footer">
      <p style="margin: 0 0 4px 0;">Regards,</p>
      <p style="margin: 0 0 2px 0; font-weight: bold; color: #171412;">Dating Wrong Team</p>
      <p style="margin: 0; color: #78350F;">Published by Mark &amp; Alvis</p>
    </div>
  </div>
</body>
</html>
    `.trim();

    let dispatchStatus: 'SENT' | 'SIMULATED' | 'FAILED' = 'SIMULATED';
    const transporter = this.getTransporter();
    const mailUser = process.env.GMAIL_USER || process.env.SMTP_USER || 'orders@datingwrong.ke';
    const fromAddress = process.env.SMTP_FROM || `"Dating Wrong" <${mailUser}>`;

    if (transporter) {
      try {
        await transporter.sendMail({
          from: fromAddress,
          to: params.customerEmail,
          subject,
          text: bodyText,
          html: bodyHtml,
        });
        dispatchStatus = 'SENT';
        console.log(`[Rejection Email Delivered] Real rejection email sent to ${params.customerEmail} from ${fromAddress}`);
      } catch (err: any) {
        dispatchStatus = 'FAILED';
        console.warn(`[Rejection Email Delivery Failed to ${params.customerEmail}]`, err.message);
      }
    }

    const log: EmailLogEntry = {
      id: `EMAIL-REJECT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      to: params.customerEmail,
      subject,
      sentAt: new Date().toISOString(),
      transactionReference: 'REJECTION',
      status: dispatchStatus,
      bodyText,
      bodyHtml,
    };

    this.emailLogs.unshift(log);
    console.log(`[Email Rejection] Recorded "${subject}" to ${params.customerEmail} (Reason: ${effectiveReason})`);

    return { success: dispatchStatus !== 'FAILED', log };
  }

  private static async recordEmailLog(log: EmailLogEntry): Promise<void> {
    this.emailLogs.unshift(log);
    try {
      await fsSetDoc('emailLogs', log.id, log);
    } catch (err: any) {
      console.error('[CUSTOMER EMAIL LOG PERSISTENCE ERROR]', err.message);
    }
  }

  static async getRecentEmailLogs(): Promise<EmailLogEntry[]> {
    try {
      const docs = await fsQuery<EmailLogEntry>('emailLogs', [], {
        orderBy: { field: 'sentAt', direction: 'desc' },
        limit: 100,
      });
      return docs.map((item) => item.data);
    } catch (err: any) {
      console.warn('[CUSTOMER EMAIL LOG READ]', err.message);
      return this.emailLogs;
    }
  }
}
