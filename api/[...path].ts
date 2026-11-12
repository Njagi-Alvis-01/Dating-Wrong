import type { VercelRequest, VercelResponse } from '@vercel/node';
import type { Express } from 'express';
import { createApp } from '../server.ts';

let appPromise: Promise<Express> | undefined;

export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    // Reuse one initialized Express app per warm serverless instance.
    // createApp hydrates Firestore once and does not open a listening socket.
    appPromise ??= createApp({ serveFrontend: false });
    const app = await appPromise;
    return app(req, res);
  } catch (error: any) {
    console.error('[VERCEL API INITIALIZATION ERROR]', error?.message || error);
    appPromise = undefined;
    if (!res.headersSent) {
      return res.status(503).json({
        success: false,
        error: 'Dating Wrong services are temporarily unavailable. Please try again shortly.',
      });
    }
  }
}
