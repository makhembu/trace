import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { getSchema } from './schema.js';
import { EventSource, EventSeverity } from '../types.js';

const DB_PATH = process.env.DB_PATH || './data/trace.db';

export function getDb(): Database.Database {
  const dbDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

export function initDb(): void {
  const db = getDb();
  db.exec(getSchema());

  const rules: { name: string; description: string; source: EventSource; matchField: string; matchPattern: string; severity: EventSeverity }[] = [
    { name: 'IOC to Finding', description: 'Correlate iris IOC with sentry finding by IOC value', source: 'iris', matchField: 'value', matchPattern: 'ioc_value', severity: 'high' },
    { name: 'Anomaly to IOC', description: 'Correlate packetwatch anomaly source with iris IOC source', source: 'packetwatch', matchField: 'source', matchPattern: 'source', severity: 'medium' },
    { name: 'PhishKit URL to IOC', description: 'Correlate phishkit report URL with iris IOC', source: 'phishkit', matchField: 'url', matchPattern: 'value', severity: 'high' },
  ];

  const insert = db.prepare(`
    INSERT OR IGNORE INTO correlation_rules (id, name, description, source, match_field, match_pattern, severity, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
  `);

  for (const rule of rules) {
    const id = `cr_${rule.name.toLowerCase().replace(/\s+/g, '_')}`;
    insert.run(id, rule.name, rule.description, rule.source, rule.matchField, rule.matchPattern, rule.severity);
  }

  console.log('[trace] Database initialized at', DB_PATH);
  db.close();
}

if (process.argv[1]?.endsWith('init.ts') || process.argv[1]?.endsWith('init.js')) {
  initDb();
}
