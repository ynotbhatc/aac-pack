-- inventory_catalog_schema.sql — AAC software-inventory / patch-intelligence schema
--
-- Feeds the AAC Portal Bridge (GET /api/aac/v1/inventory_catalog), which the
-- AAC Customer Portal pulls per tenant into tenant_inventory_catalog and matches
-- against CVE feeds. Derives a normalized {vendor, product, version, cpe} catalog
-- from the host_facts installed-package inventory, plus operator-declared products.
--
-- Objects:
--   installed_inventory          — per-host installed package rows (from host_facts)
--   manual_product_declarations  — operator-declared products not visible to package_facts
--   inventory_catalog (matview)  — the normalized, host-count-aggregated catalog the bridge serves
--
-- Idempotent — all DDL uses IF NOT EXISTS. Apply once per compliance DB.

-- ── installed_inventory ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS installed_inventory (
    id              BIGSERIAL PRIMARY KEY,
    hostname        VARCHAR(255) NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    package_version VARCHAR(100) NOT NULL,
    package_vendor  VARCHAR(255),
    cpe             TEXT,
    os_family       VARCHAR(50),
    os_version      VARCHAR(50),
    architecture    VARCHAR(20),
    source          VARCHAR(50) DEFAULT 'package_facts',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- ── Row identity ─────────────────────────────────────────────────────────────
-- The original UNIQUE (hostname, package_name) predates application-layer
-- collection and is wrong now. The SAME name legitimately exists at both
-- layers: an RHEL host carries the RPM `rpm` AND the Python distribution `rpm`
-- shipped by python3-rpm — genuinely different facts about the same host.
-- Observed collisions on a real host include rpm, kmod, nftables, cockpit,
-- perf, sos, pcp and libcomps.
--
-- Identity is therefore host + LAYER + name + version. Including version also
-- lets two interpreters legitimately report different versions of the same
-- distribution.
ALTER TABLE installed_inventory
    DROP CONSTRAINT IF EXISTS installed_inventory_hostname_package_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_identity
    ON installed_inventory (hostname, source, package_name, package_version);

-- PURL — canonical identity for APPLICATION dependencies.
-- CPE is unusable at library level; PURL is what OSV, Lightwell coordinates and
-- every SBOM format speak natively. NULL for OS packages, which are adequately
-- identified by (vendor, name, version).
ALTER TABLE installed_inventory ADD COLUMN IF NOT EXISTS purl TEXT;
CREATE INDEX IF NOT EXISTS idx_inventory_purl ON installed_inventory (purl) WHERE purl IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_inventory_vendor_product ON installed_inventory (package_vendor, package_name);
CREATE INDEX IF NOT EXISTS idx_inventory_cpe            ON installed_inventory (cpe) WHERE cpe IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_inventory_last_seen      ON installed_inventory (last_seen_at);

-- ── manual_product_declarations ──────────────────────────────────────────────
-- Products the operator knows are present but package_facts can't see: appliance
-- firmware, network-OS versions, container image components, agents, etc.
CREATE TABLE IF NOT EXISTS manual_product_declarations (
    id              BIGSERIAL PRIMARY KEY,
    vendor          VARCHAR(255) NOT NULL,
    product         VARCHAR(255) NOT NULL,
    version         VARCHAR(100) NOT NULL,
    cpe             TEXT,
    affected_hosts  TEXT[] DEFAULT ARRAY[]::TEXT[],
    notes           TEXT,
    declared_by     VARCHAR(255),
    declared_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (vendor, product, version)
);

-- ── inventory_catalog (materialized view) ────────────────────────────────────
-- The normalized catalog the AAC Portal Bridge serves. Auto rows aggregate the
-- installed inventory to {vendor, product, version} with a host_count; manual
-- rows add operator declarations. REFRESH after each inventory rebuild.
CREATE MATERIALIZED VIEW IF NOT EXISTS inventory_catalog AS
WITH auto AS (
    SELECT COALESCE(package_vendor, 'unknown'::VARCHAR) AS vendor,
           package_name    AS product,
           package_version AS version,
           cpe,
           count(DISTINCT hostname) AS host_count,
           min(first_seen_at) AS first_seen_at,
           max(last_seen_at)  AS last_seen_at,
           'auto'::TEXT AS source
      FROM installed_inventory
     GROUP BY package_vendor, package_name, package_version, cpe
),
manual AS (
    SELECT vendor, product, version, cpe,
           COALESCE(array_length(affected_hosts, 1), 0) AS host_count,
           declared_at AS first_seen_at,
           declared_at AS last_seen_at,
           'manual'::TEXT AS source
      FROM manual_product_declarations
)
SELECT * FROM auto
UNION ALL
SELECT * FROM manual;

-- Unique index enables REFRESH MATERIALIZED VIEW CONCURRENTLY.
CREATE UNIQUE INDEX IF NOT EXISTS idx_catalog_unique ON inventory_catalog (vendor, product, version, source);
CREATE INDEX IF NOT EXISTS idx_catalog_cpe ON inventory_catalog (cpe) WHERE cpe IS NOT NULL;

-- The bridge reads read-only; grant SELECT to the compliance_reader role if present.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'compliance_reader') THEN
        GRANT SELECT ON inventory_catalog TO compliance_reader;
        GRANT SELECT ON installed_inventory, manual_product_declarations TO compliance_reader;
    END IF;
END$$;
