import type { VercelRequest, VercelResponse } from '@vercel/node';
import type { Express } from 'express';
import { createApp } from './server.ts';

let appPromise: Promise<Express> | undefined;

/**
 * Shared Vercel entry point used by the depth-specific API route files.
 * The runtime bundle is generated during the Vercel build so all local
 * TypeScript modules are included in the function dependency graph.
 */
export default async function handleApiRequest(req: VercelRequest, res: VercelResponse) {
  try {
    appPromise ??= createApp({ serveFrontend: false });
    const app = await appPromise;
    return (app as any)(req as any, res as any);
  } catch (error: any) {
    console.error('[VERCEL API INITIALIZATION ERROR]', error?.stack || error?.message || error);
    appPromise = undefined;
    if (!res.headersSent) {
      return res.status(503).json({
        success: false,
        error: 'Dating Wrong services are temporarily unavailable. Please try again shortly.',
      });
    }
  }
}
