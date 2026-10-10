-- patch_worklist_schema.sql — the customer-side landing zone for the Portal
-- patch manifest, resolved down to individual hosts.
--
-- Tables created here:
--   patch_manifest_raw  — staging: one row holding the last pulled manifest JSON
--   patch_worklist      — the resolved, per-host, per-CVE patch work list
--
-- The AAC Customer Portal serves an inventory-keyed patch manifest at
--   GET /portal/v1/tenants/{tenant_id}/patches
-- carrying, per CVE: severity + KEV membership, the affected {vendor, product,
-- installed_version} tuples with a HOST COUNT, and one or more fixes with the
-- package coordinates and install command needed to obtain and apply them.
--
-- The Portal deliberately never receives hostnames — `inventory_catalog`
-- aggregates them away before the bridge serves it. So the manifest can say
-- "12 hosts affected" but not WHICH 12. That last resolution happens here,
-- locally, against `installed_inventory`, which still holds the per-host rows
-- the catalog was grouped from. Hostnames never leave the customer.
--
-- The Portal hosts no patch binaries; `artifact_url` is carried through as
-- NULL by design. The download path is the coordinates + install command +
-- advisory, fetched by the customer from their own entitled source.

-- ── patch_manifest_raw ───────────────────────────────────────────────────────
-- Staging for the pulled manifest, one JSONB row per pull, so the whole
-- resolution runs as one set-based INSERT..SELECT rather than a per-item loop.
--
-- APPEND-ONLY: every run inserts a row and patch_worklist_resolve.sql reads
-- only the newest (ORDER BY id DESC LIMIT 1). Earlier rows are retained
-- deliberately — they are the provenance record of what the Portal actually
-- said at each pull, which is what lets an auditor reconstruct why a given
-- work item existed. Nothing prunes them automatically; a nightly pull of a
-- large manifest will grow this table, so add a retention job if that matters
-- in your environment (the worklist itself is rebuilt each run, not appended).
CREATE TABLE IF NOT EXISTS patch_manifest_raw (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT,
    pulled_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    item_count  INTEGER,
    manifest    JSONB NOT NULL
);

-- ── patch_worklist ───────────────────────────────────────────────────────────
-- One row per (CVE × host × affected product). This is the artifact an operator
-- or an AAP job consumes: what to patch, where it is needed, how critical it is,
-- and the exact command that applies it.
CREATE TABLE IF NOT EXISTS patch_worklist (
    id                BIGSERIAL PRIMARY KEY,
    pulled_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Criticality — straight from the CVE record in the manifest.
    cve_id            VARCHAR(32)  NOT NULL,
    severity          VARCHAR(16),
    kev_member        BOOLEAN      NOT NULL DEFAULT false,

    -- Where it is needed.
    hostname          VARCHAR(255) NOT NULL,
    os_family         VARCHAR(50),

    -- What is affected (inventory namespace: vendor = package_vendor).
    vendor            VARCHAR(255) NOT NULL,
    product           VARCHAR(255) NOT NULL,
    installed_version VARCHAR(100),

    -- The address: how to obtain and apply the fix.
    fix_vendor        VARCHAR(255),   -- CVE vendor namespace (redhat, nodejs, …)
    fixed_version     VARCHAR(100),
    package_manager   VARCHAR(32),
    install_command   TEXT,
    patch_source      VARCHAR(32),    -- vendor_entitled | os_repo | registry | advisory_reference
    advisory_id       VARCHAR(128),
    advisory_url      TEXT,
    artifact_url      TEXT,           -- always NULL: the Portal hosts no binaries

    -- Provenance of the two joins we had to make.
    host_resolution   VARCHAR(16) NOT NULL,  -- auto | manual
    fix_match         VARCHAR(16) NOT NULL,  -- os_family | sole | ambiguous | none

    UNIQUE (cve_id, hostname, vendor, product, installed_version)
);

CREATE INDEX IF NOT EXISTS idx_worklist_host     ON patch_worklist (hostname);
CREATE INDEX IF NOT EXISTS idx_worklist_cve      ON patch_worklist (cve_id);
CREATE INDEX IF NOT EXISTS idx_worklist_priority ON patch_worklist (kev_member DESC, severity);
CREATE INDEX IF NOT EXISTS idx_worklist_pulled   ON patch_worklist (pulled_at);

-- Read-only access for the reporting role, mirroring inventory_catalog_schema.sql.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'compliance_reader') THEN
        GRANT SELECT ON patch_worklist, patch_manifest_raw TO compliance_reader;
    END IF;
END
$$;
