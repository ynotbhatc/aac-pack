-- patch_change_schema.sql — change-record, traffic and assurance state for the
-- patch remediation lifecycle. Idempotent: safe to run on every playbook start.
--
-- Implements docs/patch_remediation_lifecycle.md Stages 5 (change record),
-- 7 (traffic drain) and 10 (assurance ladder).
--
-- Design position (§10): ticketing and traffic management are ADAPTERS with
-- CONTRACTS, not integrations. Every adapter ships a stub provider so the whole
-- flow is testable with no customer systems attached.

-- ---------------------------------------------------------------------------
-- Change record — extends the existing helpdesk_tickets table rather than
-- forking a parallel one, so the Golden Image demo and the patch lifecycle
-- share a single help-desk surface.
-- ---------------------------------------------------------------------------
ALTER TABLE helpdesk_tickets ADD COLUMN IF NOT EXISTS cve_id          varchar(50);
ALTER TABLE helpdesk_tickets ADD COLUMN IF NOT EXISTS change_provider varchar(50) DEFAULT 'native';
ALTER TABLE helpdesk_tickets ADD COLUMN IF NOT EXISTS external_ref    varchar(100);
ALTER TABLE helpdesk_tickets ADD COLUMN IF NOT EXISTS phase           varchar(40);
ALTER TABLE helpdesk_tickets ADD COLUMN IF NOT EXISTS outcome         varchar(40);

CREATE INDEX IF NOT EXISTS idx_tickets_cve
    ON helpdesk_tickets (cve_id) WHERE cve_id IS NOT NULL;

COMMENT ON COLUMN helpdesk_tickets.outcome IS
  'Terminal outcome: patched | patch_failed | service_failed_after_patch | rolled_back | rejected. '
  'patch_failed and service_failed_after_patch are DIFFERENT recovery levels (R1 vs R2/R3) — '
  'recording which one occurred is what makes the closure meaningful.';

-- ---------------------------------------------------------------------------
-- Traffic state — one row per transition, so the CURRENT state is derivable
-- and an asset left drained is detectable.
--
-- "Undrain is mandatory on every exit path including failure. A drained asset
--  left drained is the most common operational mistake." (§10)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_traffic_state (
    id         bigserial PRIMARY KEY,
    hostname   varchar(255) NOT NULL,
    provider   varchar(50)  NOT NULL DEFAULT 'stub',
    pool       varchar(255),
    state      varchar(20)  NOT NULL,   -- in_service | draining | drained | returning | failed
    ticket_id  integer,
    detail     text,
    changed_at timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_traffic_host
    ON patch_traffic_state (hostname, changed_at DESC);

-- Latest state per host
CREATE OR REPLACE VIEW patch_traffic_current AS
SELECT DISTINCT ON (hostname)
       hostname, provider, pool, state, ticket_id, detail, changed_at
  FROM patch_traffic_state
 ORDER BY hostname, changed_at DESC;

-- The safety query: anything still out of service. Should always be empty at
-- the end of a run. If it is not, a host is carrying no traffic and nobody knows.
CREATE OR REPLACE VIEW patch_traffic_stranded AS
SELECT *, EXTRACT(EPOCH FROM (now() - changed_at))/3600 AS hours_out_of_service
  FROM patch_traffic_current
 WHERE state IN ('draining', 'drained', 'failed');

-- ---------------------------------------------------------------------------
-- Assurance results — the A-ladder. A0 version compare is built; A1 service
-- health is added here. A2-A4 (functional, integration, compliance re-assess)
-- remain gaps and must not be reported as passing.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_assurance_results (
    id         bigserial PRIMARY KEY,
    hostname   varchar(255) NOT NULL,
    cve_id     varchar(50),
    ticket_id  integer,
    level      varchar(4)   NOT NULL,   -- A0 | A1 | A2
    check_name varchar(120) NOT NULL,
    passed     boolean      NOT NULL,
    detail     text,
    checked_at timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assurance_host
    ON patch_assurance_results (hostname, checked_at DESC);

-- ---------------------------------------------------------------------------
-- Pre-change backup manifest — Stage 7 baseline. A package manifest is the
-- documented minimum backup depth; deeper depths (snapshot, config archive)
-- are risk-tier driven and are NOT built.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_backup_manifests (
    id          bigserial PRIMARY KEY,
    hostname    varchar(255) NOT NULL,
    ticket_id   integer,
    cve_id      varchar(50),
    depth       varchar(30)  NOT NULL DEFAULT 'package_manifest',
    manifest    jsonb        NOT NULL,
    package_count integer,
    captured_at timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_backup_host
    ON patch_backup_manifests (hostname, captured_at DESC);
