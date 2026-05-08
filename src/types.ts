export type EventSource = 'iris' | 'sentry' | 'phishkit' | 'packetwatch' | 'manual';

export type EventType =
  | 'ioc_ingested'
  | 'threat_alert'
  | 'finding_generated'
  | 'phishing_report'
  | 'anomaly_detected'
  | 'baseline_computed'
  | 'correlation_match'
  | 'incident_created'
  | 'manual_note';

export type EventSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'dismissed';

export interface TimelineEvent {
  id: string;
  source: EventSource;
  sourceEventId: string;
  eventType: EventType;
  severity: EventSeverity;
  title: string;
  description: string;
  sourceData: Record<string, unknown>;
  occurred_at: string;
  ingested_at: string;
  tags: string[];
  incidentId?: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: EventSeverity;
  status: IncidentStatus;
  firstEventAt: string;
  lastEventAt: string;
  eventCount: number;
  sources: EventSource[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  source: EventSource;
  matchField: string;
  matchPattern: string;
  severity: EventSeverity;
  groupWindowMinutes: number;
  enabled: number;
}

export interface TimelineExport {
  incidents: Incident[];
  events: TimelineEvent[];
  generated_at: string;
  totalIncidents: number;
  totalEvents: number;
}
