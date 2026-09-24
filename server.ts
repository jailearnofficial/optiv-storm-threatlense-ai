/**
 * OPTIV S.T.O.R.M · ThreatLense AI
 * Node.js Server Entry Point
 */

import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from './server/config.js';
import { createApp } from './server/app.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = createApp();

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';
  const port = config.port;

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`[OPTIV S.T.O.R.M ThreatLense AI] Server running on http://0.0.0.0:${port}`);
  });
}

startServer();
