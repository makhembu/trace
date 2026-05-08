# Trace — Incident Timeline Correlation Engine

Correlates IOCs, detection findings, phishing reports, and network anomalies into unified incident timelines. The top-level correlation layer of the iris ecosystem.

## Quick Start

```bash
git clone https://github.com/makhembu/trace
cd trace
cp .env.example .env
npm install
npm run build
npm start
# Server running at http://localhost:3004
```

## Ingest from Ecosystem

```bash
# Ingest from all configured sources at once
curl -X POST http://localhost:3004/ingest/all

# Or per-source
curl -X POST http://localhost:3004/ingest/iris
curl -X POST http://localhost:3004/ingest/sentry
curl -X POST http://localhost:3004/ingest/phishkit
curl -X POST http://localhost:3004/ingest/packetwatch
```

## API

### Events

```
POST /events       { source, sourceEventId, eventType, severity, title, occurred_at }
POST /events/batch { events: [...] }
GET  /events?source=&severity=&incidentId=
```

### Incidents

```
GET    /incidents?status=open&severity=high
GET    /incidents/:id
PATCH  /incidents/:id { status, title, description }
```

### Correlation

```
POST /correlate
```

### Export

```
GET /export
GET /dashboard
```

## Correlation Rules

Events are correlated into incidents using configurable rules:

| Rule | Source | Match | Group Window |
|------|--------|-------|-------------|
| IOC to Finding | iris | IOC value matches finding IOC value | 60 min |
| Anomaly to IOC | packetwatch | Source matches IOC source | 60 min |
| PhishKit URL to IOC | phishkit | URL matches IOC value | 60 min |

## Why

Security tools generate isolated alerts. Trace connects them: an iris IOC becomes a timeline event, a sentry finding referencing the same value gets grouped into an incident, a packetwatch anomaly on the same source adds network context. Analysts get a single timeline instead of five dashboards.

## Stack

- TypeScript
- Hono
- better-sqlite3
- Multi-source API ingestion
- Cloudflare Workers + D1 ready

## Roadmap

- [x] Event ingestion from iris, sentry, phishkit, packetwatch
- [x] Incident auto-creation from correlated events
- [x] Correlation rules engine
- [x] Timeline export (JSON)
- [x] Incident management (status, severity)
- [ ] MITRE ATT&CK mapping
- [ ] Timeline rendering (Gantt-style)
- [ ] Alert forwarding (email, Slack, PagerDuty)
- [ ] STIX export
