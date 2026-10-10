-- cve_cache_schema.sql — the AAC-side CVE cache: what the patch-intelligence
-- playbooks match the installed inventory against.
--
-- Idempotent: safe to run on every install and on every playbook start.
--
-- OWNERSHIP. These two tables belong to the AAC evidence database (this role),
-- not to the customer portal. The portal keeps its own `cve_events` and its own
-- `cve_vendor_remediations` (keyed by vendor_id, api/migrations/005 there) in
-- its own database; it DELIVERS rows into this cache over the bridge. The two
-- `cve_vendor_remediations` share a name and nothing else: this one carries
-- the vendor as text and is keyed (cve_id, vendor), which is what
-- identify_affected_components.yml and simulate_patch_lifecycle.yml join on.
-- They never live in the same database, so there is one owner per table.
--
-- Populated by: the portal bridge, the EDA CVE webhook, or — for a demo —
-- ansible/files/demo_cve_fixture.sql (synthetic ids, source='demo_seed').
-- identify_affected_components.yml refuses to run on an empty cache: zero
-- CVEs would report "clean" when it means "never looked".

-- ---------------------------------------------------------------------------
-- cve_events_received — local cache of CVEs delivered to this AAC instance
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_events_received (
    cve_id                 varchar(50)  PRIMARY KEY,
    cvss_v3                numeric(3,1),
    severity               varchar(20),
    kev_member             boolean      DEFAULT false,
    published_at           timestamptz,
    vendor                 varchar(255),
    product                varchar(255),
    affected_versions      text[],
    affected_cpes          text[],
    description            text,
    cve_references         jsonb        DEFAULT '[]'::jsonb,
    suggested_playbook_ref varchar(255),
    source                 varchar(50),
    received_at            timestamptz  NOT NULL DEFAULT now(),
    source_event_payload   jsonb
);

CREATE INDEX IF NOT EXISTS idx_cve_severity_received
    ON cve_events_received (severity, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_kev
    ON cve_events_received (kev_member) WHERE kev_member = true;
CREATE INDEX IF NOT EXISTS idx_cve_published
    ON cve_events_received (published_at DESC);

-- ---------------------------------------------------------------------------
-- cve_vendor_remediations — the published fix per (CVE, vendor), if any.
-- A CVE with no row here is still reported by the matcher (you are affected
-- whether or not a fix exists); it carries fix_match='none'.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_vendor_remediations (
    id                  bigserial    PRIMARY KEY,
    cve_id              varchar(50)  NOT NULL REFERENCES cve_events_received(cve_id) ON DELETE CASCADE,
    vendor              varchar(255) NOT NULL,
    vendor_advisory_id  varchar(100),
    fix_version         varchar(100),
    patch_url           text,
    patch_description   text,
    available_at        timestamptz,
    received_at         timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (cve_id, vendor)
);

CREATE INDEX IF NOT EXISTS idx_vendor_rem_advisory
    ON cve_vendor_remediations (vendor_advisory_id) WHERE vendor_advisory_id IS NOT NULL;

-- Read-only access for the reporting role, mirroring inventory_catalog_schema.sql.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'compliance_reader') THEN
        GRANT SELECT ON cve_events_received, cve_vendor_remediations TO compliance_reader;
    END IF;
END
$$;
