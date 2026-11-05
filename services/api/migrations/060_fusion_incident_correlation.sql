-- Persist Fusion incident correlation on each alert.
-- Existing alerts remain valid with NULL values.

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS incident_id UUID;

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS fusion_decision TEXT;

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_incident
    ON public.alerts (tenant_id, incident_id)
    WHERE incident_id IS NOT NULL;

COMMENT ON COLUMN public.alerts.incident_id IS
    'Fusion incident identifier associated with this alert.';

COMMENT ON COLUMN public.alerts.fusion_decision IS
    'Fusion processing decision: new_alert, duplicate, correlated, or new_incident.';
