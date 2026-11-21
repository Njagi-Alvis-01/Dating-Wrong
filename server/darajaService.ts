/**
 * Safaricom Daraja Production Integration Service
 * M-Pesa Express (STK Push) implementation
 * - M-Pesa credentials stored exclusively on server-side
 * - Implements genuine Daraja authorization token exchange
 * - Initiates STK Push
 * - Handles Daraja asynchronous callbacks
 * - Transaction verification and idempotency check
 */

import { normalizeKenyanPhone } from '../src/utils/phoneNormalization.ts';

export interface DarajaConfig {
  consumerKey: string;
  consumerSecret: string;
  passkey: string;
  shortCode: string; // Paybill or Till Number
  callbackUrl: string;
  environment: 'sandbox' | 'production';
}

export interface StkInitiateParams {
  phone: string;
  amount: number;
  accountReference: string;
  transactionDesc: string;
  customerName?: string;
  customerEmail?: string;
  userId?: string;
}

export interface StkInitiateResponse {
  merchantRequestId: string;
  checkoutRequestId: string;
  responseCode: string;
  responseDescription: string;
  customerMessage: string;
  normalizedPhone: string;
  amount: number;
}

export interface DarajaCallbackItem {
  Name: string;
  Value: string | number;
}

export interface DarajaCallbackPayload {
  Body: {
    stkCallback: {
      MerchantRequestID: string;
      CheckoutRequestID: string;
      ResultCode: number;
      ResultDesc: string;
      CallbackMetadata?: {
        Item: DarajaCallbackItem[];
      };
    };
  };
}

export interface VerifiedDarajaPayment {
  checkoutRequestId: string;
  merchantRequestId: string;
  resultCode: number;
  resultDesc: string;
  isSuccessful: boolean;
  transactionCode?: string;
  amount?: number;
  phone?: string;
  transactionDate?: string;
}

export class DarajaService {
  private config: DarajaConfig;
  private cachedToken: { token: string; expiresAt: number } | null = null;

  constructor() {
    this.config = {
      consumerKey: process.env.MPESA_CONSUMER_KEY || '',
      consumerSecret: process.env.MPESA_CONSUMER_SECRET || '',
      passkey: process.env.MPESA_PASSKEY || '',
      shortCode: process.env.MPESA_SHORTCODE || '4089221',
      callbackUrl: process.env.MPESA_CALLBACK_URL || `${process.env.APP_URL || 'https://datingwrong.ke'}/api/payments/daraja/callback`,
      environment: (process.env.MPESA_ENV as 'sandbox' | 'production') || 'sandbox',
    };
  }

  private get baseUrl(): string {
    return this.config.environment === 'production'
      ? 'https://api.safaricom.co.ke'
      : 'https://sandbox.safaricom.co.ke';
  }

  /**
   * Acquire OAuth access token from Safaricom Daraja
   */
  async getAccessToken(): Promise<string> {
    if (!this.config.consumerKey || !this.config.consumerSecret) {
      throw new Error('Safaricom Daraja credentials are not configured. Use the manual Pochi payment flow or configure live Daraja credentials.');
    }

    if (this.cachedToken && Date.now() < this.cachedToken.expiresAt) {
      return this.cachedToken.token;
    }

    const auth = Buffer.from(`${this.config.consumerKey}:${this.config.consumerSecret}`).toString('base64');
    const res = await fetch(`${this.baseUrl}/oauth/v1/generate?grant_type=client_credentials`, {
      headers: { Authorization: `Basic ${auth}` },
    });
    const data: any = await res.json().catch(() => ({}));
    if (!res.ok || !data.access_token) {
      throw new Error(`Daraja OAuth failed (${res.status}): ${data.error_description || data.errorMessage || 'No access token returned'}`);
    }

    this.cachedToken = {
      token: data.access_token,
      expiresAt: Date.now() + (parseInt(data.expires_in || '3600', 10) - 60) * 1000,
    };
    return data.access_token;
  }

  /**
   * Generate Safaricom Daraja STK Password
   * Format: Base64(ShortCode + Passkey + Timestamp YYYYMMDDHHmmss)
   */
  generatePassword(timestamp: string): string {
    if (!this.config.passkey || !this.config.shortCode) {
      throw new Error('Daraja shortcode and passkey must be configured before initiating STK Push.');
    }
    return Buffer.from(`${this.config.shortCode}${this.config.passkey}${timestamp}`).toString('base64');
  }

  getTimestamp(): string {
    const now = new Date();
    const pad = (n: number) => n.toString().padStart(2, '0');
    return (
      now.getFullYear().toString() +
      pad(now.getMonth() + 1) +
      pad(now.getDate()) +
      pad(now.getHours()) +
      pad(now.getMinutes()) +
      pad(now.getSeconds())
    );
  }

  /**
   * Initiate genuine Safaricom Daraja M-PESA Express (STK Push)
   */
  async initiateStkPush(params: StkInitiateParams): Promise<StkInitiateResponse> {
    const phoneNorm = normalizeKenyanPhone(params.phone);
    if (!phoneNorm.isValid) {
      throw new Error(`Invalid Kenyan phone number for Daraja: ${params.phone}`);
    }
    if (!this.config.passkey || !this.config.shortCode || !this.config.callbackUrl) {
      throw new Error('Daraja STK Push is not configured. Please use the Pochi la Biashara manual payment option.');
    }

    const timestamp = this.getTimestamp();
    const password = this.generatePassword(timestamp);
    const token = await this.getAccessToken();
    const requestPayload = {
      BusinessShortCode: this.config.shortCode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.round(params.amount),
      PartyA: phoneNorm.canonical,
      PartyB: this.config.shortCode,
      PhoneNumber: phoneNorm.canonical,
      CallBackURL: this.config.callbackUrl,
      AccountReference: params.accountReference.slice(0, 12),
      TransactionDesc: params.transactionDesc.slice(0, 13),
    };

    const response = await fetch(`${this.baseUrl}/mpesa/stkpush/v1/processrequest`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestPayload),
    });
    const data: any = await response.json().catch(() => ({}));
    if (!response.ok || data.ResponseCode !== '0' || !data.CheckoutRequestID || !data.MerchantRequestID) {
      throw new Error(`Daraja STK Push failed (${response.status}): ${data.errorMessage || data.ResponseDescription || 'Safaricom did not accept the request'}`);
    }

    return {
      merchantRequestId: data.MerchantRequestID,
      checkoutRequestId: data.CheckoutRequestID,
      responseCode: data.ResponseCode,
      responseDescription: data.ResponseDescription,
      customerMessage: data.CustomerMessage || 'M-PESA prompt sent. Complete payment on your phone.',
      normalizedPhone: phoneNorm.canonical,
      amount: params.amount,
    };
  }

  /**
   * Verify the callback's CheckoutRequestID against Safaricom's STK query API.
   * A public callback payload alone is not sufficient proof of payment.
   */
  async verifyStkPush(checkoutRequestId: string): Promise<{ isSuccessful: boolean; resultCode: string; resultDesc: string }> {
    if (!checkoutRequestId) throw new Error('CheckoutRequestID is required for Daraja verification.');
    const timestamp = this.getTimestamp();
    const password = this.generatePassword(timestamp);
    const token = await this.getAccessToken();
    const response = await fetch(`${this.baseUrl}/mpesa/stkpushquery/v1/query`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        BusinessShortCode: this.config.shortCode,
        Password: password,
        Timestamp: timestamp,
        CheckoutRequestID: checkoutRequestId,
      }),
    });
    const data: any = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(`Daraja STK query failed (${response.status}): ${data.errorMessage || 'Unable to verify transaction'}`);
    }
    const resultCode = String(data.ResultCode ?? '');
    return {
      isSuccessful: resultCode === '0',
      resultCode,
      resultDesc: String(data.ResultDesc || 'No Daraja transaction result returned'),
    };
  }

  /**
   * Parse and extract metadata items from Daraja Callback webhook
   */
  parseCallback(payload: DarajaCallbackPayload): VerifiedDarajaPayment {
    const callback = payload.Body?.stkCallback;
    if (!callback) {
      throw new Error('Malformed Daraja callback payload');
    }

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = callback;
    const isSuccessful = Number(ResultCode) === 0;

    let transactionCode: string | undefined;
    let amount: number | undefined;
    let phone: string | undefined;
    let transactionDate: string | undefined;

    if (CallbackMetadata?.Item) {
      for (const item of CallbackMetadata.Item) {
        if (item.Name === 'MpesaReceiptNumber') transactionCode = String(item.Value);
        if (item.Name === 'Amount') amount = Number(item.Value);
        if (item.Name === 'PhoneNumber') phone = String(item.Value);
        if (item.Name === 'TransactionDate') transactionDate = String(item.Value);
      }
    }

    return {
      merchantRequestId: MerchantRequestID,
      checkoutRequestId: CheckoutRequestID,
      resultCode: ResultCode,
      resultDesc: ResultDesc,
      isSuccessful,
      transactionCode,
      amount,
      phone,
      transactionDate,
    };
  }
}
