/**
 * Modular Express App setup for OPTIV S.T.O.R.M · ThreatLense AI
 * Used by server.ts (for dev/full-stack standalone) and api/index.ts (for Vercel Serverless)
 */

import express, { Request, Response } from 'express';
import crypto from 'crypto';
import multer from 'multer';
import { getProviderHealth } from './config.js';
import { detectIndicatorType } from './detect.js';
import { orchestrator } from './orchestrator.js';
import { runGeminiTriage } from './ai/gemini.js';
import { db } from './db.js';
import { generateHtmlReport, generateIOCsCsv, generateSTIXBundle } from './report/generator.js';
import { userAuth } from './auth.js';

export function createApp() {
  const app = express();

  // Disable x-powered-by to prevent fingerprinting
  app.disable('x-powered-by');

  const upload = multer({
    limits: { fileSize: 32 * 1024 * 1024 }, // 32MB limit per Section 3
    storage: multer.memoryStorage()
  });

  // JSON and URL-encoded middleware with strict payload caps
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Helper to sanitize analyst name and prevent injection
  function sanitizeAnalystName(name?: any): string | undefined {
    if (typeof name !== 'string') return undefined;
    const clean = name.replace(/[<>'"&]/g, '').trim();
    return clean.length > 0 ? clean.substring(0, 64) : undefined;
  }

  // Helper to validate alphanumeric ID parameters
  function isValidId(id?: any): boolean {
    return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(id);
  }

  // Security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader(
      'Content-Security-Policy',
      "frame-ancestors 'self' https://*.google.com https://*.run.app https://*.googleusercontent.com https://*.vercel.app;"
    );
    next();
  });

  // Authentication Endpoints for @optiv.com and @gmail.com
  app.post('/api/auth/register', (req: Request, res: Response) => {
    const { email, password, displayName } = req.body || {};
    try {
      if (!email || typeof email !== 'string') {
        res.status(400).json({ error: 'Email address is required.' });
        return;
      }
      if (!password || typeof password !== 'string') {
        res.status(400).json({ error: 'Password is required.' });
        return;
      }
      const user = userAuth.register(email, password, displayName);
      res.status(201).json({ success: true, user });
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Registration failed.' });
    }
  });

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { email, password } = req.body || {};
    try {
      if (!email || typeof email !== 'string') {
        res.status(400).json({ error: 'Email address is required.' });
        return;
      }
      if (!password || typeof password !== 'string') {
        res.status(400).json({ error: 'Password is required.' });
        return;
      }
      const user = userAuth.login(email, password);
      res.json({ success: true, user });
    } catch (err: any) {
      res.status(401).json({ error: err.message || 'Authentication failed.' });
    }
  });

  // 1. Health Endpoint
  app.get('/api/health', (req: Request, res: Response) => {
    const health = getProviderHealth();
    res.json({
      status: 'online',
      timestamp: new Date().toISOString(),
      providers: health
    });
  });

  // 2. Recent History Endpoint (Strict 24-Hour Active Retention)
  app.get('/api/history', (req: Request, res: Response) => {
    const limit = parseInt((req.query.limit as string) || '50', 10);
    const history = db.listRecentLookups(limit);
    res.json({
      retention_window_hours: 24,
      total: history.length,
      history
    });
  });

  // Force purge records older than 24 hours
  app.post('/api/history/purge', (req: Request, res: Response) => {
    const purged = db.purgeOldRecords();
    res.json({ message: '24-hour retention purge executed successfully', purged_count: purged });
  });

  // 3. Lookup Endpoint
  app.post('/api/lookup', async (req: Request, res: Response) => {
    try {
      const { indicator, type, submit, analyst_name } = req.body;

      if (!indicator || typeof indicator !== 'string') {
        return res.status(422).json({
          error: { code: 'INVALID_INDICATOR', message: 'Indicator string is required.' }
        });
      }

      const detection = detectIndicatorType(indicator, type);
      if (!detection.valid) {
        return res.status(422).json({
          error: { code: 'VALIDATION_FAILED', message: detection.error || 'Invalid indicator' }
        });
      }

      const cleanAnalyst = sanitizeAnalystName(analyst_name);
      const evidence = await orchestrator.runLookup(
        detection.normalized,
        detection.type,
        Boolean(submit),
        undefined,
        cleanAnalyst
      );

      res.json({
        lookup_id: evidence.id,
        indicator: evidence.indicator,
        analyst_name: evidence.analyst_name,
        providers: evidence.providers,
        rule_score: evidence.rule_score,
        related: evidence.related,
        mitre_hints: evidence.mitre_hints,
        collected_at: evidence.collected_at
      });
    } catch (err: any) {
      console.error('Lookup failed:', err);
      res.status(500).json({
        error: { code: 'LOOKUP_FAILED', message: err.message || 'Internal error processing lookup.' }
      });
    }
  });

  // 4. SSE Stream Lookup Endpoint
  app.get('/api/lookup/stream', async (req: Request, res: Response) => {
    const indicator = req.query.indicator as string;
    const type = req.query.type as string;
    const analystName = sanitizeAnalystName(req.query.analyst_name);

    if (!indicator) {
      return res.status(422).json({ error: { code: 'MISSING_INDICATOR', message: 'Indicator required.' } });
    }

    const detection = detectIndicatorType(indicator, type);
    if (!detection.valid) {
      return res.status(422).json({ error: { code: 'VALIDATION_FAILED', message: detection.error } });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (event: string, data: any) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent('start', { indicator: detection.normalized, type: detection.type });

    try {
      const evidence = await orchestrator.runLookup(
        detection.normalized,
        detection.type,
        false,
        (providerResult) => {
          sendEvent('provider_update', providerResult);
        },
        analystName
      );

      sendEvent('complete', evidence);
      res.end();
    } catch (err: any) {
      sendEvent('error', { message: err.message });
      res.end();
    }
  });

  // 5. Submit Endpoint (File / URL submission flow)
  app.post('/api/submit', upload.single('file'), async (req: Request, res: Response) => {
    try {
      const analystName = sanitizeAnalystName(req.body.analyst_name);

      if (req.file) {
        const buffer = req.file.buffer;
        const md5 = crypto.createHash('md5').update(buffer).digest('hex');
        const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
        const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

        const evidence = await orchestrator.runLookup(
          sha256,
          'hash',
          true,
          undefined,
          analystName,
          {
            buffer,
            originalname: req.file.originalname,
            mimetype: req.file.mimetype
          }
        );

        evidence.related.hashes = [sha256, sha1, md5];

        const savedLookup = db.getLookup(evidence.id);
        if (savedLookup) {
          savedLookup.analystName = analystName || 'SOC Analyst';
          savedLookup.fileName = req.file.originalname;
          savedLookup.fileSize = req.file.size;
          savedLookup.actionType = 'file_submission';
          savedLookup.hashes = { md5, sha1, sha256 };
          savedLookup.evidence = evidence;
          db.saveLookup(savedLookup);
        }

        return res.json({
          lookup_id: evidence.id,
          analyst_name: evidence.analyst_name,
          file_info: {
            original_name: req.file.originalname,
            size_bytes: req.file.size,
            md5,
            sha1,
            sha256
          },
          evidence
        });
      }

      const { url, visibility } = req.body;
      if (url) {
        const detection = detectIndicatorType(url, 'url');
        if (!detection.valid) {
          return res.status(422).json({ error: { code: 'INVALID_URL', message: detection.error } });
        }

        const evidence = await orchestrator.runLookup(
          detection.normalized,
          'url',
          true,
          undefined,
          analystName
        );
        return res.json({
          lookup_id: evidence.id,
          analyst_name: evidence.analyst_name,
          visibility: visibility || 'unlisted',
          evidence
        });
      }

      return res.status(422).json({
        error: { code: 'EMPTY_SUBMISSION', message: 'No file or URL submitted for analysis.' }
      });
    } catch (err: any) {
      console.error('Submit error:', err);
      res.status(500).json({ error: { code: 'SUBMIT_FAILED', message: err.message } });
    }
  });

  // 6. Fetch Lookup by ID
  app.get('/api/lookup/:id', (req: Request, res: Response) => {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: { code: 'INVALID_ID', message: 'Invalid identifier format.' } });
    }
    const lookup = db.getLookup(req.params.id);
    if (!lookup) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Lookup record not found.' } });
    }
    res.json(lookup.evidence);
  });

  // 6b. VirusTotal Details & Graph Endpoint
  app.get('/api/virustotal/details/:id', (req: Request, res: Response) => {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: { code: 'INVALID_ID', message: 'Invalid identifier format.' } });
    }
    const lookup = db.getLookup(req.params.id);
    if (!lookup) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Lookup record not found.' } });
    }

    const vtResult = lookup.evidence.providers.find((p) => p.name === 'virustotal');
    if (!vtResult) {
      return res.status(404).json({ error: { code: 'VT_NOT_FOUND', message: 'VirusTotal intelligence not found.' } });
    }

    res.json({
      indicator: lookup.indicator,
      type: lookup.type,
      headline: vtResult.headline,
      score: vtResult.score,
      vt_details: vtResult.vt_details,
      vt_graph: vtResult.vt_graph || vtResult.vt_details?.vt_graph
    });
  });

  // 6c. Hybrid Analysis Details Endpoint
  app.get('/api/hybrid-analysis/details/:id', (req: Request, res: Response) => {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: { code: 'INVALID_ID', message: 'Invalid identifier format.' } });
    }
    const lookup = db.getLookup(req.params.id);
    if (!lookup) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Lookup record not found.' } });
    }

    const haResult = lookup.evidence.providers.find((p) => p.name === 'hybrid_analysis');
    if (!haResult) {
      return res.status(404).json({ error: { code: 'HA_NOT_FOUND', message: 'Hybrid Analysis intelligence not found.' } });
    }

    res.json({
      indicator: lookup.indicator,
      type: lookup.type,
      headline: haResult.headline,
      score: haResult.score,
      ha_details: haResult.ha_details
    });
  });

  // 6d. AlienVault OTX Details Endpoint
  app.get('/api/alienvault-otx/details/:id', (req: Request, res: Response) => {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: { code: 'INVALID_ID', message: 'Invalid identifier format.' } });
    }
    const lookup = db.getLookup(req.params.id);
    if (!lookup) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Lookup record not found.' } });
    }

    const otxResult = lookup.evidence.providers.find((p) => p.name === 'alienvault_otx');
    if (!otxResult) {
      return res.status(404).json({ error: { code: 'OTX_NOT_FOUND', message: 'AlienVault OTX intelligence not found.' } });
    }

    res.json({
      indicator: lookup.indicator,
      type: lookup.type,
      headline: otxResult.headline,
      score: otxResult.score,
      otx_details: otxResult.otx_details
    });
  });

  // 7. Analyze AI Endpoint
  app.post('/api/analyze', async (req: Request, res: Response) => {
    try {
      const { lookup_id, refresh, analyst_name } = req.body;
      if (!lookup_id || !isValidId(lookup_id)) {
        return res.status(422).json({ error: { code: 'INVALID_LOOKUP_ID', message: 'Valid lookup_id is required.' } });
      }

      const lookup = db.getLookup(lookup_id);
      if (!lookup) {
        return res.status(404).json({ error: { code: 'LOOKUP_NOT_FOUND', message: 'Lookup record not found.' } });
      }

      const cleanAnalyst = sanitizeAnalystName(analyst_name);
      if (cleanAnalyst) {
        lookup.analystName = cleanAnalyst;
        lookup.evidence.analyst_name = cleanAnalyst;
      }

      if (!refresh) {
        const existing = db.getAnalysisByLookupId(lookup_id);
        if (existing) {
          if (cleanAnalyst) {
            existing.analystName = cleanAnalyst;
            existing.verdict.analyst_name = cleanAnalyst;
          }
          return res.json(existing.verdict);
        }
      }

      const verdict = await runGeminiTriage(lookup.evidence);
      if (cleanAnalyst) {
        verdict.analyst_name = cleanAnalyst;
      } else if (lookup.analystName) {
        verdict.analyst_name = lookup.analystName;
      }

      db.saveAnalysis({
        id: verdict.id,
        lookupId: lookup_id,
        verdict,
        model: verdict.model,
        createdAt: verdict.created_at,
        analystName: verdict.analyst_name
      });

      res.json(verdict);
    } catch (err: any) {
      console.error('AI analysis error:', err);
      res.status(500).json({
        error: { code: 'AI_ANALYSIS_FAILED', message: err.message || 'Gemini analysis encountered an error.' }
      });
    }
  });

  // 8. Download / Print PDF Report
  const handleReportRequest = (req: Request, res: Response) => {
    const rawId = req.params.analysis_id?.replace(/\.pdf$/, '');
    if (!isValidId(rawId)) {
      return res.status(400).send('Invalid analysis ID format');
    }

    const analysisRecord = db.getAnalysis(rawId);
    if (!analysisRecord) {
      return res.status(404).send('Analysis record not found');
    }

    const lookup = db.getLookup(analysisRecord.lookupId);
    if (!lookup) {
      return res.status(404).send('Underlying lookup record not found');
    }

    const cleanAnalyst = sanitizeAnalystName(req.query.analyst_name);
    if (cleanAnalyst) {
      analysisRecord.verdict.analyst_name = cleanAnalyst;
    }

    const html = generateHtmlReport(analysisRecord.verdict, lookup);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  };

  app.get('/api/report/:analysis_id.pdf', handleReportRequest);
  app.get('/api/report/html/:analysis_id', handleReportRequest);
  app.get('/api/report/:analysis_id', handleReportRequest);

  // 9. Export IOCs in CSV or STIX JSON
  app.get('/api/iocs/:analysis_id', (req: Request, res: Response) => {
    const format = (req.query.format as string) || 'csv';
    if (!isValidId(req.params.analysis_id)) {
      return res.status(400).json({ error: { code: 'INVALID_ID', message: 'Invalid analysis identifier' } });
    }

    const analysisRecord = db.getAnalysis(req.params.analysis_id);
    if (!analysisRecord) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Analysis not found' } });
    }

    const lookup = db.getLookup(analysisRecord.lookupId);
    if (!lookup) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Lookup not found' } });
    }

    const verdict = analysisRecord.verdict;

    if (format === 'csv') {
      const csv = generateIOCsCsv(verdict);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="IOCs_${lookup.type}_${verdict.id}.csv"`);
      return res.send(csv);
    } else {
      const stix = generateSTIXBundle(verdict, lookup);
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="STIX_${lookup.type}_${verdict.id}.json"`);
      return res.json(stix);
    }
  });

  return app;
}
