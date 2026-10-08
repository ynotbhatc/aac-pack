-- ai_action_log_schema.sql — the persisted decision log for the AI-agent
-- governance plane. Idempotent: safe to run on every playbook start.
--
-- These three tables were referenced by ai_governance_check.yml since the
-- action layer landed, but never defined anywhere — every INSERT silently
-- failed under ignore_errors. This file is their first real DDL; the MCP
-- server (services/mcp-server/server_opa.py) also writes ai_action_log
-- directly, one row per OPA decision, allows AND denies.
--
-- ai_action_log is APPEND-ONLY, enforced by trigger: the decision log is the
-- audit trail for what agents did and tried to do. A log an agent (or anyone)
-- can rewrite is not evidence. ai_approval_requests permits UPDATE (approval
-- status resolves in place); ai_systems is ordinary reference data.

-- ---------------------------------------------------------------------------
-- Registered AI systems / agent identities
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_systems (
    id                serial PRIMARY KEY,
    system_id         varchar(100) NOT NULL UNIQUE,
    role              varchar(50)  NOT NULL DEFAULT 'ai_reader',
    enabled           boolean      NOT NULL DEFAULT true,
    production_access boolean      NOT NULL DEFAULT false,
    description       text,
    created_at        timestamptz  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- The decision log — one row per governance decision, three channels:
--   channel = 'mcp'          → per-tool-call verdicts from the governed MCP server
--   channel = 'action_layer' → named-action verdicts from ai_governance_check.yml
--   channel = 'ao_gate'      → workflow-level policy-gate verdicts recorded by
--                              ansible/playbooks/record_ai_decision.yml (an
--                              override of the agent's recommendation lands
--                              with allow=false — on the denies index).
-- ai_system_id is nullable: the MCP channel logs by agent_identity string and
-- an identity may (deliberately) not be registered — an unregistered identity
-- showing up in the log is itself a finding, not an insert failure.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_action_log (
    id             bigserial PRIMARY KEY,
    trace_id       uuid         NOT NULL,
    channel        varchar(20)  NOT NULL DEFAULT 'action_layer',
    ai_system_id   integer      REFERENCES ai_systems(id),
    agent_identity varchar(200),
    tool           varchar(200),
    action         varchar(200),
    arguments_hash varchar(64),
    risk_level     varchar(20),
    decision       varchar(30)  NOT NULL,
    allow          boolean,
    reason         text,
    environment    varchar(50),
    reasoning      text,
    policy_sha     varchar(64),
    created_at     timestamptz  NOT NULL DEFAULT now()
);

-- Reference back to the policy engine's own decision record (OPA decision_id)
-- so a logged verdict can be replayed against the exact evaluation. Additive
-- and nullable; ALTER guarded for pre-existing installs (this file reruns on
-- every playbook start).
ALTER TABLE ai_action_log ADD COLUMN IF NOT EXISTS decision_ref varchar(64);

CREATE INDEX IF NOT EXISTS idx_ai_action_log_trace   ON ai_action_log (trace_id);
CREATE INDEX IF NOT EXISTS idx_ai_action_log_agent   ON ai_action_log (agent_identity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_action_log_denies  ON ai_action_log (created_at DESC) WHERE allow IS false;

COMMENT ON TABLE ai_action_log IS
  'Append-only governance decision log: every agent action verdict, allows and denies. '
  'Denies are signal, not noise — a rising denial rate for an identity is the alarm.';

-- Append-only guard: UPDATE and DELETE are refused at the database, matching
-- the evidence-store posture. Corrections are new rows, never rewrites.
CREATE OR REPLACE FUNCTION ai_action_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ai_action_log is append-only (% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ai_action_log_append_only ON ai_action_log;
CREATE TRIGGER trg_ai_action_log_append_only
    BEFORE UPDATE OR DELETE ON ai_action_log
    FOR EACH ROW EXECUTE FUNCTION ai_action_log_append_only();

-- ---------------------------------------------------------------------------
-- Approval requests — status resolves in place (pending → approved/denied/expired)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_approval_requests (
    id                 bigserial PRIMARY KEY,
    trace_id           uuid         NOT NULL,
    ai_action_log_id   bigint       REFERENCES ai_action_log(id),
    action             varchar(200) NOT NULL,
    risk_level         varchar(20),
    justification      text,
    required_approvers integer      NOT NULL DEFAULT 1,
    status             varchar(20)  NOT NULL DEFAULT 'pending',
    expires_at         timestamptz,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    resolved_at        timestamptz,
    resolved_by        varchar(200)
);

CREATE INDEX IF NOT EXISTS idx_ai_approval_pending
    ON ai_approval_requests (created_at DESC) WHERE status = 'pending';
