-- patch_risk_schema.sql — risk scoring and heat-map aggregation for patch exposure
--
-- Implements docs/patch_remediation_lifecycle.md §5 (aggregation / heat map) and
-- Stage 6 (risk tiering). Idempotent.
--
-- ===========================================================================
-- WHY A RISK AXIS AT ALL
-- ===========================================================================
-- The Technical Debt & Coverage Heat Map today is a COST surface: hours x rate,
-- driven by compliance violations. Patch exposure adds something cost cannot
-- express. A KEV CVE is being actively exploited right now; the question is not
-- "what does it cost to fix" but "what does it cost NOT to fix".
--
-- ===========================================================================
-- NO SEVENTH CATEGORY
-- ===========================================================================
-- Patch findings fold into the EXISTING debt categories:
--     CVE with an available fix  -> security
--     EOL / no fix will ever come -> technology_lifecycle
--     OT / BES asset              -> critical_infrastructure
-- One cell, one owner, one budget line. A separate "patching" category would
-- create a second queue competing with the first for the same engineers.
--
-- `technology_lifecycle` has been DECLARED since the debt policy was written and
-- has never been fed by anything. This is what fills it.
--
-- ===========================================================================
-- THE FOUR VALLEY TYPES (§5)
-- ===========================================================================
--   coverage — never assessed. We do not know.
--   currency — assessed, but the data is stale.
--   exposure — a fix EXISTS and we are past the SLA. Inexcusable.
--   support  — no fix will EVER exist. Permanent; risk never decays.

-- ---------------------------------------------------------------------------
-- Risk model parameters. Table-driven so they are auditable and tunable
-- without editing code — an auditor can ask "why is this 8.5" and be shown
-- the row rather than a hardcoded constant.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_risk_parameters (
    param_group varchar(40)  NOT NULL,
    param_key   varchar(60)  NOT NULL,
    param_value numeric      NOT NULL,
    rationale   text,
    source      varchar(200),
    PRIMARY KEY (param_group, param_key)
);

INSERT INTO patch_risk_parameters (param_group, param_key, param_value, rationale, source) VALUES
  ('severity_weight', 'CRITICAL', 10.0, 'CVSS 9.0-10.0', 'CVSS v3.1'),
  ('severity_weight', 'HIGH',      7.0, 'CVSS 7.0-8.9',  'CVSS v3.1'),
  ('severity_weight', 'MEDIUM',    4.0, 'CVSS 4.0-6.9',  'CVSS v3.1'),
  ('severity_weight', 'LOW',       1.0, 'CVSS 0.1-3.9',  'CVSS v3.1'),
  ('severity_weight', 'UNKNOWN',   4.0, 'Unscored defaults to MEDIUM — fail-closed', 'AAC policy'),

  ('kev_multiplier', 'kev',        2.5, 'Actively exploited in the wild. Not theoretical.', 'CISA KEV catalog'),
  ('kev_multiplier', 'non_kev',    1.0, 'No known active exploitation', 'CISA KEV catalog'),

  -- SLA clocks are REAL REGULATORY DEADLINES, not invented thresholds.
  ('sla_days', 'kev',             14.0, 'KEV CVEs published 2021+ must be remediated in 14 days', 'CISA BOD 22-01'),
  ('sla_days', 'critical',        30.0, 'Critical/high vulnerabilities within one month',        'PCI DSS v4.0 6.3.3'),
  ('sla_days', 'high',            35.0, 'Evaluate 35 days, then apply or mitigate within 35',    'NERC CIP-007-6 R2.2/R2.3'),
  ('sla_days', 'medium',          90.0, 'Moderate findings',                                     'FedRAMP ConMon'),
  ('sla_days', 'low',            180.0, 'Low findings',                                          'FedRAMP ConMon'),

  ('age_factor', 'max',            4.0, 'Cap so ancient debt cannot swamp everything else', 'AAC policy'),
  ('breadth',    'max',            3.0, 'Cap so estate-wide findings do not swamp targeted ones', 'AAC policy'),

  ('risk_tier', 'tier3_min',      75.0, 'Tier 3: highest ceremony, deepest backup, full approval', 'AAC policy'),
  ('risk_tier', 'tier2_min',      50.0, 'Tier 2', 'AAC policy'),
  ('risk_tier', 'tier1_min',      25.0, 'Tier 1', 'AAC policy')
ON CONFLICT (param_group, param_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Per-finding risk scores
--
-- risk = severity_weight x kev_multiplier x age_factor x breadth
--
-- age_factor is measured from when the FIX became available, NOT from CVE
-- publication. The clock starts when action became possible. A CVE published
-- three years ago whose fix shipped last week is one week of exposure, not
-- three years — and stale backlog with an available fix grows louder over time,
-- which is the behaviour we want.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_risk_scores (
    id                bigserial PRIMARY KEY,
    scored_at         timestamptz NOT NULL DEFAULT now(),
    hostname          varchar(255) NOT NULL,
    cve_id            varchar(50)  NOT NULL,
    product           varchar(255),
    installed_version varchar(100),
    severity          varchar(20),
    kev_member        boolean      NOT NULL DEFAULT false,

    -- the four factors, stored so a score can always be explained
    severity_weight   numeric,
    kev_multiplier    numeric,
    age_factor        numeric,
    breadth_factor    numeric,

    fix_available_at  timestamptz,
    days_since_fix    integer,
    sla_days          integer,
    sla_state         varchar(12),        -- attained | at_risk | breached | no_fix
    valley_type       varchar(12),        -- coverage | currency | exposure | support
    debt_category     varchar(40),        -- folds into the EXISTING categories
    risk_score        numeric      NOT NULL,
    risk_tier         smallint     NOT NULL,
    is_simulated      boolean      NOT NULL DEFAULT false,
    simulation_note   text
);

CREATE INDEX IF NOT EXISTS idx_risk_host ON patch_risk_scores (hostname, scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_cve  ON patch_risk_scores (cve_id);
CREATE INDEX IF NOT EXISTS idx_risk_sim  ON patch_risk_scores (is_simulated);

COMMENT ON COLUMN patch_risk_scores.is_simulated IS
  'TRUE when any input was synthesized rather than measured — typically fix_available_at '
  'and fixed_version, which vendor remediation enrichment does not yet supply. '
  'Simulated rows must never be presented as measured exposure.';

COMMENT ON COLUMN patch_risk_scores.risk_tier IS
  'Stage 6 risk tier 0-3. Drives backup depth, assurance depth and approval ceremony. '
  'Tier is a POLICY decision, not a fixed procedure.';

-- ---------------------------------------------------------------------------
-- Heat map cells — the aggregation surface. One row per (category, host group).
-- Carries BOTH axes: cost (hours x rate) and risk. They answer different
-- questions and neither substitutes for the other.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_heatmap_cells (
    id             bigserial PRIMARY KEY,
    generated_at   timestamptz NOT NULL DEFAULT now(),
    debt_category  varchar(40) NOT NULL,
    valley_type    varchar(12),
    hosts          integer     NOT NULL DEFAULT 0,
    findings       integer     NOT NULL DEFAULT 0,
    kev_findings   integer     NOT NULL DEFAULT 0,
    unpatched      integer     NOT NULL DEFAULT 0,
    effort_hours   numeric     NOT NULL DEFAULT 0,
    cost_usd       numeric     NOT NULL DEFAULT 0,
    risk_total     numeric     NOT NULL DEFAULT 0,
    risk_max       numeric     NOT NULL DEFAULT 0,
    sla_breached   integer     NOT NULL DEFAULT 0,
    exposure_days  numeric     NOT NULL DEFAULT 0,
    is_simulated   boolean     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_heat_gen ON patch_heatmap_cells (generated_at DESC);

-- Latest generation only
CREATE OR REPLACE VIEW patch_heatmap_latest AS
SELECT * FROM patch_heatmap_cells
 WHERE generated_at = (SELECT max(generated_at) FROM patch_heatmap_cells);

-- The unpatched-systems view the PDF renders
CREATE OR REPLACE VIEW patch_unpatched_systems AS
SELECT r.hostname,
       count(*)                                   AS findings,
       count(*) FILTER (WHERE r.kev_member)       AS kev_findings,
       count(*) FILTER (WHERE r.sla_state = 'breached') AS sla_breached,
       round(sum(r.risk_score), 1)                AS risk_total,
       round(max(r.risk_score), 1)                AS risk_max,
       max(r.risk_tier)                           AS max_tier,
       string_agg(DISTINCT r.debt_category, ', ' ORDER BY r.debt_category) AS categories,
       bool_or(r.is_simulated)                    AS any_simulated
  FROM patch_risk_scores r
 WHERE r.scored_at = (SELECT max(scored_at) FROM patch_risk_scores)
 GROUP BY r.hostname;
