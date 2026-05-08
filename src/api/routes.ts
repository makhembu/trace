import { Hono } from 'hono';
import { getDb } from '../db/init.js';
import {
  ingestEvent, batchIngestEvents,
  ingestFromIris, ingestFromSentry, ingestFromPhishKit, ingestFromPacketWatch,
  correlateAndGroup, exportTimeline,
} from '../correlation/engine.js';
import { EventSource, EventType, EventSeverity } from '../types.js';

export const api = new Hono();

api.get('/health', (c) => {
  const db = getDb();
  try {
    const events = (db.prepare('SELECT COUNT(*) as c FROM events').get() as { c: number }).c;
    const incidents = (db.prepare('SELECT COUNT(*) as c FROM incidents').get() as { c: number }).c;
    db.close();
    return c.json({ status: 'ok', events, incidents, uptime: process.uptime() });
  } catch (err) {
    db.close();
    return c.json({ status: 'error', error: String(err) }, 500);
  }
});

api.post('/events', async (c) => {
  const body = await c.req.json() as {
    source: EventSource;
    sourceEventId: string;
    eventType: EventType;
    severity: EventSeverity;
    title: string;
    description?: string;
    sourceData?: Record<string, unknown>;
    occurred_at: string;
    tags?: string[];
  };

  if (!body.source || !body.sourceEventId || !body.eventType || !body.title || !body.occurred_at) {
    return c.json({ error: 'source, sourceEventId, eventType, title, and occurred_at are required' }, 400);
  }

  const event = ingestEvent(body);
  return c.json(event, 201);
});

api.post('/events/batch', async (c) => {
  const body = await c.req.json() as { events: Parameters<typeof ingestEvent>[0][] };
  if (!body.events || !Array.isArray(body.events) || body.events.length === 0) {
    return c.json({ error: 'events array is required' }, 400);
  }
  const ingested = batchIngestEvents(body.events);
  return c.json({ ingested: ingested.length, events: ingested }, 201);
});

api.get('/events', (c) => {
  const db = getDb();
  const source = c.req.query('source');
  const severity = c.req.query('severity');
  const incidentId = c.req.query('incidentId');
  const limit = Math.min(Number(c.req.query('limit')) || 100, 1000);
  const offset = Number(c.req.query('offset')) || 0;

  let where = 'WHERE 1=1';
  const params: unknown[] = [];

  if (source) { where += ' AND source = ?'; params.push(source); }
  if (severity) { where += ' AND severity = ?'; params.push(severity); }
  if (incidentId) { where += ' AND incident_id = ?'; params.push(incidentId); }

  const total = (db.prepare(`SELECT COUNT(*) as c FROM events ${where}`).get(...params) as { c: number }).c;
  const rows = db.prepare(`SELECT * FROM events ${where} ORDER BY occurred_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
  db.close();

  return c.json({ events: rows, total, query: { source, severity, incidentId, limit, offset } });
});

api.post('/ingest/all', async (c) => {
  const iris = await ingestFromIris();
  const sentry = await ingestFromSentry();
  const phishkit = await ingestFromPhishKit();
  const packetwatch = await ingestFromPacketWatch();

  return c.json({
    message: 'Ingestion complete',
    sources: {
      iris: iris.length,
      sentry: sentry.length,
      phishkit: phishkit.length,
      packetwatch: packetwatch.length,
    },
    total: iris.length + sentry.length + phishkit.length + packetwatch.length,
  });
});

api.post('/ingest/:source', async (c) => {
  const source = c.req.param('source');
  let events: any[];
  switch (source) {
    case 'iris': events = await ingestFromIris(); break;
    case 'sentry': events = await ingestFromSentry(); break;
    case 'phishkit': events = await ingestFromPhishKit(); break;
    case 'packetwatch': events = await ingestFromPacketWatch(); break;
    default: return c.json({ error: `Unknown source: ${source}` }, 400);
  }
  return c.json({ source, ingested: events.length });
});

api.post('/correlate', (c) => {
  const results = correlateAndGroup();
  return c.json({ message: 'Correlation complete', ...results });
});

api.post('/incidents', async (c) => {
  const body = await c.req.json() as {
    title: string;
    description?: string;
    severity: string;
    status?: string;
    eventIds?: string[];
    tags?: string[];
  };

  if (!body.title || !body.severity) {
    return c.json({ error: 'title and severity are required' }, 400);
  }

  const db = getDb();
  const id = `inc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO incidents (id, title, description, severity, status, first_event_at, last_event_at, event_count, sources, tags, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    body.title,
    body.description || '',
    body.severity,
    body.status || 'open',
    now, now, 0, '[]',
    JSON.stringify(body.tags || []),
    now, now,
  );

  if (body.eventIds && body.eventIds.length > 0) {
    for (const eid of body.eventIds) {
      db.prepare('UPDATE events SET incident_id = ? WHERE id = ?').run(id, eid);
    }
    const count = (db.prepare('SELECT COUNT(*) as c FROM events WHERE incident_id = ?').get(id) as { c: number }).c;
    const rows = db.prepare('SELECT DISTINCT source FROM events WHERE incident_id = ?').all(id) as { source: string }[];
    const sources = JSON.stringify(rows.map(r => r.source));
    const first = (db.prepare("SELECT occurred_at FROM events WHERE incident_id = ? ORDER BY occurred_at ASC LIMIT 1").get(id) as any)?.occurred_at || now;
    const last = (db.prepare("SELECT occurred_at FROM events WHERE incident_id = ? ORDER BY occurred_at DESC LIMIT 1").get(id) as any)?.occurred_at || now;
    db.prepare('UPDATE incidents SET event_count = ?, sources = ?, first_event_at = ?, last_event_at = ? WHERE id = ?').run(count, sources, first, last, id);
  }

  db.close();
  return c.json({ id, title: body.title, severity: body.severity, status: body.status || 'open', event_count: body.eventIds?.length || 0 }, 201);
});

api.get('/incidents', (c) => {
  const db = getDb();
  const status = c.req.query('status');
  const severity = c.req.query('severity');
  const limit = Math.min(Number(c.req.query('limit')) || 50, 500);
  const offset = Number(c.req.query('offset')) || 0;

  let where = 'WHERE 1=1';
  const params: unknown[] = [];

  if (status) { where += ' AND status = ?'; params.push(status); }
  if (severity) { where += ' AND severity = ?'; params.push(severity); }

  const total = (db.prepare(`SELECT COUNT(*) as c FROM incidents ${where}`).get(...params) as { c: number }).c;
  const rows = db.prepare(`SELECT * FROM incidents ${where} ORDER BY severity DESC, created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
  db.close();

  return c.json({ incidents: rows, total, query: { status, severity, limit, offset } });
});

api.get('/incidents/:id', (c) => {
  const db = getDb();
  const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(c.req.param('id'));
  if (!incident) { db.close(); return c.json({ error: 'Incident not found' }, 404); }
  const events = db.prepare('SELECT * FROM events WHERE incident_id = ? ORDER BY occurred_at').all(c.req.param('id'));
  db.close();
  return c.json({ incident, events });
});

api.patch('/incidents/:id', async (c) => {
  const body = await c.req.json() as { status?: string; title?: string; description?: string };
  const db = getDb();

  if (body.status) {
    db.prepare("UPDATE incidents SET status = ?, updated_at = datetime('now') WHERE id = ?").run(body.status, c.req.param('id'));
  }
  if (body.title) {
    db.prepare("UPDATE incidents SET title = ?, updated_at = datetime('now') WHERE id = ?").run(body.title, c.req.param('id'));
  }
  if (body.description) {
    db.prepare("UPDATE incidents SET description = ?, updated_at = datetime('now') WHERE id = ?").run(body.description, c.req.param('id'));
  }

  db.close();
  return c.json({ status: 'updated' });
});

api.get('/export', (c) => {
  const { incidents, events } = exportTimeline();
  return c.json({
    incidents,
    events,
    generated_at: new Date().toISOString(),
    totalIncidents: incidents.length,
    totalEvents: events.length,
  });
});

api.get('/dashboard', (c) => {
  const db = getDb();

  const totalEvents = (db.prepare('SELECT COUNT(*) as c FROM events').get() as { c: number }).c;
  const totalIncidents = (db.prepare('SELECT COUNT(*) as c FROM incidents').get() as { c: number }).c;
  const openIncidents = (db.prepare("SELECT COUNT(*) as c FROM incidents WHERE status NOT IN ('resolved','dismissed')").get() as { c: number }).c;

  const eventsBySource = db.prepare('SELECT source, COUNT(*) as count FROM events GROUP BY source ORDER BY count DESC').all();
  const eventsBySeverity = db.prepare('SELECT severity, COUNT(*) as count FROM events GROUP BY severity ORDER BY count DESC').all();
  const incidentsByStatus = db.prepare('SELECT status, COUNT(*) as count FROM incidents GROUP BY status ORDER BY count DESC').all();
  const recentEvents = db.prepare('SELECT * FROM events ORDER BY occurred_at DESC LIMIT 20').all();
  const recentIncidents = db.prepare("SELECT * FROM incidents WHERE status NOT IN ('resolved','dismissed') ORDER BY severity DESC, created_at DESC LIMIT 10").all();

  db.close();

  return c.json({
    events: { total: totalEvents, bySource: eventsBySource, bySeverity: eventsBySeverity, recent: recentEvents },
    incidents: { total: totalIncidents, open: openIncidents, byStatus: incidentsByStatus, recent: recentIncidents },
  });
});
