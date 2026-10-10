-- golden_image_schema.sql — the Golden Image governed-drift tables.
--
-- Idempotent: safe to run on every install and on every playbook start.
--
-- Until this file existed these three tables were created only by the demo
-- seed (aac-demos demos/golden_image/playbooks/seed_golden_image_workflow.yml),
-- so a product install that had not run the demo seed had none of them and
-- Golden Image Check / Rollback / Notify Help Desk failed at their first query
-- (sales.demos#883). The seed keeps its own CREATE TABLE IF NOT EXISTS; both
-- sides must stay identical.
--
-- helpdesk_tickets is the single help-desk surface for the whole product:
-- patch_change_schema.sql extends it with the change-record columns
-- (cve_id, change_provider, external_ref, phase, outcome) and must run AFTER
-- this file.

-- ---------------------------------------------------------------------------
-- golden_image_baselines — the approved "known good" file contents per host.
-- golden_files JSONB keys: sshd_config, auditd_conf, audit_rules, sysctl_conf,
-- selinux_config. One current row per hostname (is_current = true).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS golden_image_baselines (
    id             SERIAL       PRIMARY KEY,
    hostname       VARCHAR(255) NOT NULL,
    baseline_label VARCHAR(100) NOT NULL,
    captured_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    is_current     BOOLEAN      NOT NULL DEFAULT true,
    golden_files   JSONB        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_golden_hostname ON golden_image_baselines (hostname);
CREATE INDEX IF NOT EXISTS idx_golden_current  ON golden_image_baselines (hostname, is_current) WHERE is_current = true;

-- ---------------------------------------------------------------------------
-- helpdesk_tickets — tickets raised by Notify Help Desk (golden_image_drift)
-- and, through patch_change_schema.sql, the patch lifecycle's change records.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS helpdesk_tickets (
    id              SERIAL       PRIMARY KEY,
    hostname        VARCHAR(255) NOT NULL,
    incident_type   VARCHAR(50),
    severity        VARCHAR(20),
    description     TEXT,
    triggered_by    VARCHAR(100),
    aap_job_id      INTEGER,
    rollback_status VARCHAR(50),
    status          VARCHAR(20)  NOT NULL DEFAULT 'open',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tickets_hostname ON helpdesk_tickets (hostname);

-- ---------------------------------------------------------------------------
-- remediation_log — what a rollback changed, before and after, per control.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediation_log (
    id             SERIAL       PRIMARY KEY,
    hostname       VARCHAR(255) NOT NULL,
    control_id     VARCHAR(50),
    control_name   VARCHAR(255),
    action_taken   VARCHAR(100),
    result         VARCHAR(50),
    playbook_name  VARCHAR(255),
    before_state   JSONB,
    after_state    JSONB,
    performed_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remediation_log_hostname ON remediation_log (hostname);

-- Read-only access for the reporting role, mirroring inventory_catalog_schema.sql.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'compliance_reader') THEN
        GRANT SELECT ON golden_image_baselines, helpdesk_tickets, remediation_log TO compliance_reader;
    END IF;
END
$$;
