import 'dotenv/config';
import { serve } from '@hono/node-server';
import { api } from './api/routes.js';
import { initDb } from './db/init.js';
import { Hono } from 'hono';

const app = new Hono();

app.route('/', api);

app.get('/', (c) => {
  return c.json({
    name: 'Trace — Incident Timeline Correlation Engine',
    version: '1.0.0',
    description: 'Correlates IOCs, findings, anomalies, and reports into unified incident timelines',
    ecosystem: {
      iris: 'Ingest threat IOCs as timeline events',
      sentry: 'Ingest detection findings as timeline events',
      phishkit: 'Ingest phishing reports as timeline events',
      packetwatch: 'Ingest network anomalies as timeline events',
    },
    docs: {
      health: 'GET /health',
      createEvent: 'POST /events { source, sourceEventId, eventType, severity, title, occurred_at }',
      batchEvents: 'POST /events/batch { events: [...] }',
      getEvents: 'GET /events?source=&severity=&incidentId=',
      ingestAll: 'POST /ingest/all',
      ingestSource: 'POST /ingest/:source',
      correlate: 'POST /correlate',
      createIncident: 'POST /incidents { title, severity, description, eventIds, tags }',
      getIncidents: 'GET /incidents?status=&severity=',
      getIncident: 'GET /incidents/:id',
      updateIncident: 'PATCH /incidents/:id { status, title, description }',
      export: 'GET /export',
      dashboard: 'GET /dashboard',
    },
  });
});

const PORT = Number(process.env.PORT) || 3004;

initDb();

console.log(`[trace] Starting server on port ${PORT}`);
serve({ fetch: app.fetch, port: PORT });

export default app;
