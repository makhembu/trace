import { getDb } from '../db/init.js';
import { TimelineEvent, Incident, EventSource, EventType, EventSeverity } from '../types.js';

function generateId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
}

export function ingestEvent(event: {
  source: EventSource;
  sourceEventId: string;
  eventType: EventType;
  severity: EventSeverity;
  title: string;
  description?: string;
  sourceData?: Record<string, unknown>;
  occurred_at: string;
  tags?: string[];
}): TimelineEvent {
  const db = getDb();
  const id = generateId('evt');

  db.prepare(`
    INSERT OR IGNORE INTO events (id, source, source_event_id, event_type, severity, title, description, source_data, occurred_at, ingested_at, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
  `).run(
    id, event.source, event.sourceEventId, event.eventType, event.severity,
    event.title, event.description || '', JSON.stringify(event.sourceData || {}),
    event.occurred_at, JSON.stringify(event.tags || [])
  );

  db.close();

  return {
    id,
    source: event.source,
    sourceEventId: event.sourceEventId,
    eventType: event.eventType,
    severity: event.severity,
    title: event.title,
    description: event.description || '',
    sourceData: event.sourceData || {},
    occurred_at: event.occurred_at,
    ingested_at: new Date().toISOString(),
    tags: event.tags || [],
  };
}

export function batchIngestEvents(events: Parameters<typeof ingestEvent>[0][]): TimelineEvent[] {
  const db = getDb();
  const ingested: TimelineEvent[] = [];
  const now = new Date().toISOString();

  const insert = db.prepare(`
    INSERT OR IGNORE INTO events (id, source, source_event_id, event_type, severity, title, description, source_data, occurred_at, ingested_at, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const tx = db.transaction(() => {
    for (const event of events) {
      const id = generateId('evt');
      insert.run(
        id, event.source, event.sourceEventId, event.eventType, event.severity,
        event.title, event.description || '', JSON.stringify(event.sourceData || {}),
        event.occurred_at, now, JSON.stringify(event.tags || [])
      );
      ingested.push({
        id, source: event.source, sourceEventId: event.sourceEventId,
        eventType: event.eventType, severity: event.severity,
        title: event.title, description: event.description || '',
        sourceData: event.sourceData || {}, occurred_at: event.occurred_at,
        ingested_at: now, tags: event.tags || [],
      });
    }
  });

  tx();
  db.close();
  return ingested;
}

export function ingestFromIris(): Promise<TimelineEvent[]> {
  return ingestFromApi('iris', process.env.IRIS_API_URL, '/alerts', 'threat_alert');
}

export function ingestFromSentry(): Promise<TimelineEvent[]> {
  return ingestFromApi('sentry', process.env.SENTRY_API_URL, '/findings', 'finding_generated');
}

export function ingestFromPhishKit(): Promise<TimelineEvent[]> {
  return ingestFromApi('phishkit', process.env.PHISHKIT_API_URL, '/reports?minScore=0.3', 'phishing_report');
}

export function ingestFromPacketWatch(): Promise<TimelineEvent[]> {
  return ingestFromApi('packetwatch', process.env.PACKETWATCH_API_URL, '/anomalies?acknowledged=false', 'anomaly_detected');
}

async function ingestFromApi(
  source: EventSource,
  baseUrl: string | undefined,
  path: string,
  eventType: EventType,
): Promise<TimelineEvent[]> {
  if (!baseUrl) {
    console.log(`[trace] Skipping ${source}: API URL not configured`);
    return [];
  }

  try {
    const res = await fetch(`${baseUrl}${path}`);
    if (!res.ok) {
      console.warn(`[trace] ${source} API returned ${res.status}`);
      return [];
    }

    const data = await res.json() as any;
    const items = data.alerts || data.findings || data.anomalies || data.reports || data.iocs || [];

    const events: Parameters<typeof ingestEvent>[0][] = [];

    for (const item of (Array.isArray(items) ? items : (items || []))) {
      events.push({
        source,
        sourceEventId: item.id || item.ioc_id || '',
        eventType,
        severity: (item.severity || 'medium').toLowerCase() as EventSeverity,
        title: item.rule_name || item.message || item.phishScore || item.value || `${source} event`,
        description: item.message || item.match_reason || item.description || '',
        sourceData: item,
        occurred_at: item.created_at || item.detected_at || item.last_seen || new Date().toISOString(),
        tags: item.tags || [],
      });
    }

    return batchIngestEvents(events);
  } catch (err: any) {
    console.warn(`[trace] Failed to ingest from ${source}: ${err.message}`);
    return [];
  }
}

export function correlateAndGroup(): { incidentsCreated: number; eventsGrouped: number } {
  const db = getDb();
  const rules = db.prepare('SELECT * FROM correlation_rules WHERE enabled = 1').all() as any[];
  let incidentsCreated = 0;
  let eventsGrouped = 0;

  for (const rule of rules) {
    const windowStart = new Date(Date.now() - rule.group_window_minutes * 60 * 1000).toISOString();

    const events = db.prepare(
      `SELECT * FROM events WHERE source = ? AND incident_id IS NULL AND occurred_at >= ? ORDER BY occurred_at DESC LIMIT 100`
    ).all(rule.source, windowStart) as any[];

    if (events.length < 2) continue;

    const grouped = new Map<string, any[]>();
    for (const event of events) {
      const sourceData = JSON.parse(event.source_data || '{}');
      const matchValue = String(sourceData[rule.match_field] || sourceData[rule.match_pattern] || '').toLowerCase();
      if (!matchValue) continue;
      if (!grouped.has(matchValue)) grouped.set(matchValue, []);
      grouped.get(matchValue)!.push(event);
    }

    for (const [value, group] of grouped) {
      if (group.length < 2) continue;

      const incidentId = generateId('inc');
      const sorted = group.sort((a: any, b: any) => a.occurred_at.localeCompare(b.occurred_at));
      const sources = [...new Set(group.map((e: any) => e.source))];
      const tags = [...new Set(group.flatMap((e: any) => JSON.parse(e.tags || '[]')))];

      db.prepare(`
        INSERT INTO incidents (id, title, description, severity, status, first_event_at, last_event_at, event_count, sources, tags, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).run(
        incidentId,
        `Incident: ${value}`,
        `Auto-created from ${group.length} correlated ${rule.source} events matching "${value}"`,
        rule.severity,
        sorted[0].occurred_at,
        sorted[sorted.length - 1].occurred_at,
        group.length,
        JSON.stringify(sources),
        JSON.stringify(tags),
      );

      const updateStmt = db.prepare('UPDATE events SET incident_id = ? WHERE id = ?');
      for (const event of group) {
        updateStmt.run(incidentId, event.id);
      }

      db.prepare('INSERT INTO correlation_matches (rule_id, source_a_event_id, matched_value, incident_id) VALUES (?, ?, ?, ?)')
        .run(rule.id, group[0].id, value, incidentId);

      incidentsCreated++;
      eventsGrouped += group.length;
    }
  }

  db.close();
  console.log(`[trace] Correlation complete: ${incidentsCreated} incidents, ${eventsGrouped} events grouped`);
  return { incidentsCreated, eventsGrouped };
}

export function exportTimeline(): { incidents: any[]; events: any[] } {
  const db = getDb();
  const incidents = db.prepare('SELECT * FROM incidents ORDER BY severity DESC, created_at DESC').all();
  const events = db.prepare("SELECT * FROM events ORDER BY occurred_at DESC LIMIT 1000").all();
  db.close();
  return { incidents: incidents as any[], events: events as any[] };
}
