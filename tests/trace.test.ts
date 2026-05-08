import { describe, it } from 'node:test';
import assert from 'node:assert';
import Database from 'better-sqlite3';
import { getSchema } from '../src/db/schema.js';
import path from 'path';
import fs from 'fs';

const TEST_DB = path.join(import.meta.dirname, '..', 'data', 'test_trace.db');

function setupDb() {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  const dbDir = path.dirname(TEST_DB);
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
  const db = new Database(TEST_DB);
  db.pragma('journal_mode = WAL');
  db.exec(getSchema());
  return db;
}

describe('trace', () => {

  describe('database schema', () => {
    it('creates all required tables', () => {
      const db = setupDb();
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[];
      const names = tables.map(t => t.name);
      assert.ok(names.includes('events'));
      assert.ok(names.includes('incidents'));
      assert.ok(names.includes('correlation_rules'));
      assert.ok(names.includes('correlation_matches'));
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });

    it('inserts an event with all fields', () => {
      const db = setupDb();
      db.prepare(`
        INSERT INTO events (id, source, source_event_id, event_type, severity, title, description, source_data, occurred_at, ingested_at, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
      `).run('evt_001', 'iris', 'ioc_123', 'ioc_ingested', 'high', 'Malicious IP detected', '8.8.8.8 from abuse.ch', '{"value":"8.8.8.8","confidence":0.9}', '2026-05-08T12:00:00Z', '["c2","malware"]');

      const row = db.prepare('SELECT * FROM events WHERE id = ?').get('evt_001') as any;
      assert.strictEqual(row.source, 'iris');
      assert.strictEqual(row.event_type, 'ioc_ingested');
      assert.strictEqual(row.severity, 'high');
      assert.strictEqual(row.title, 'Malicious IP detected');
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });

    it('unique constraint on (source, source_event_id)', () => {
      const db = setupDb();
      db.prepare(`
        INSERT INTO events (id, source, source_event_id, event_type, severity, title, occurred_at, tags)
        VALUES ('e1', 'iris', 'same_id', 'ioc_ingested', 'low', 'First', '2026-01-01', '[]')
      `).run();

      assert.throws(() => {
        db.prepare(`
          INSERT INTO events (id, source, source_event_id, event_type, severity, title, occurred_at, tags)
          VALUES ('e2', 'iris', 'same_id', 'ioc_ingested', 'low', 'Duplicate', '2026-01-01', '[]')
        `).run();
      });
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });

    it('creates an incident with events', () => {
      const db = setupDb();
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO incidents (id, title, description, severity, status, first_event_at, last_event_at, event_count, sources, tags, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).run('inc_001', 'Test Incident', 'Auto-created from 3 events', 'high', now, now, 3, '["iris","sentry"]', '["c2"]');

      const row = db.prepare('SELECT * FROM incidents WHERE id = ?').get('inc_001') as any;
      assert.strictEqual(row.title, 'Test Incident');
      assert.strictEqual(row.severity, 'high');
      assert.strictEqual(row.status, 'open');
      assert.strictEqual(row.event_count, 3);
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });

    it('links events to an incident', () => {
      const db = setupDb();
      db.prepare(`
        INSERT INTO incidents (id, title, severity, status, sources, tags) VALUES ('inc_002', 'Linked', 'medium', 'open', '[]', '[]')
      `).run();

      const eventId = 'evt_linked';
      db.prepare(`
        INSERT INTO events (id, source, source_event_id, event_type, severity, title, occurred_at, incident_id, tags)
        VALUES (?, 'sentry', 'f1', 'finding_generated', 'high', 'Linked finding', '2026-05-08', ?, '[]')
      `).run(eventId, 'inc_002');

      const row = db.prepare("SELECT incident_id FROM events WHERE id = ?").get(eventId) as any;
      assert.strictEqual(row.incident_id, 'inc_002');
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });
  });

  describe('correlation rules', () => {
    it('seeds default correlation rules', () => {
      const db = setupDb();
      const rules: { name: string; source: string; matchField: string }[] = [
        { name: 'IOC to Finding', source: 'iris', matchField: 'value' },
        { name: 'Anomaly to IOC', source: 'packetwatch', matchField: 'source' },
        { name: 'PhishKit URL to IOC', source: 'phishkit', matchField: 'url' },
      ];

      for (const r of rules) {
        const id = `cr_${r.name.toLowerCase().replace(/\s+/g, '_')}`;
        db.prepare('INSERT OR IGNORE INTO correlation_rules (id, name, description, source, match_field, match_pattern, severity, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, 1)')
          .run(id, r.name, 'Auto-generated', r.source, r.matchField, 'value', 'high');
      }

      const count = (db.prepare('SELECT COUNT(*) as c FROM correlation_rules').get() as { c: number }).c;
      assert.strictEqual(count, 3);
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });
  });
});
