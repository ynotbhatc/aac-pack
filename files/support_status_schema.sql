-- support_status_schema.sql — technology support status (end-of-life exposure)
--
-- Fills the `technology_lifecycle` debt category, which has been declared in the
-- debt-scoring policy since it was written but had nothing feeding it.
--
-- The finding this implements: **unsupported technology converts remediation
-- debt into REPLACEMENT debt.** A CVE on a supported product is a patch away
-- from closed. The same CVE on a product past end of support has no patch and
-- never will — its exposure cannot be retired by any patch cycle, and the only
-- remedy is replacement. NERC CIP-007-6 R2.3 recognises exactly this case: where
-- no patch exists, a *dated mitigation plan* is the required (and only lawful)
-- path. Maps to NIST 800-53 SA-22 and CIS Controls v8 Safeguard 2.2.
--
-- Requires no customer integration and no asset register — it runs entirely
-- against the product catalog fact collection already produces.

-- ── product_lifecycle ────────────────────────────────────────────────────────
-- Upstream lifecycle data, one row per (product, release cycle).
--
-- `eol` and `support` in the upstream feed are EITHER an ISO date OR a boolean.
-- A boolean `true` means "already end-of-life, no date given"; `false` means
-- "not end-of-life". Collapsing that to a nullable date would lose the `true`
-- case and silently mark genuinely dead products as unknown — so the boolean is
-- kept in its own column.
CREATE TABLE IF NOT EXISTS product_lifecycle (
    id              BIGSERIAL PRIMARY KEY,
    eol_product     VARCHAR(100) NOT NULL,   -- upstream product identifier
    cycle           VARCHAR(50)  NOT NULL,   -- release series, e.g. '9', '22.04'
    release_date    DATE,
    eol_date        DATE,                    -- NULL when upstream gave a boolean
    eol_is_past     BOOLEAN NOT NULL DEFAULT false,  -- upstream said eol: true
    support_end_date DATE,                   -- end of ACTIVE support (pre-EOL)
    latest          VARCHAR(100),
    source          VARCHAR(50)  NOT NULL DEFAULT 'endoflife.date',
    checked_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (eol_product, cycle)
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_product ON product_lifecycle (eol_product);
CREATE INDEX IF NOT EXISTS idx_lifecycle_eol     ON product_lifecycle (eol_date);

-- ── support_status_map ───────────────────────────────────────────────────────
-- Maps what WE observe to what upstream calls it. Operator-maintained.
--
-- Two match kinds, because the two highest-value signals are different shapes:
--   os      — matched on installed_inventory.os_family + os_version.
--             This is the most valuable row type: "which hosts run an operating
--             system that is past end of support" is the SA-22 / CIS 2.2
--             question, and it is answerable for EVERY host with no extra data.
--   package — matched on installed_inventory.package_name, for runtimes and
--             middleware whose lifecycle matters independently of the OS.
--
-- `cycle_mode` says how to derive the upstream release cycle from the observed
-- version, because products disagree about what a "release" is:
--   major       9.3    -> 9        (RHEL, PostgreSQL, Node)
--   majorminor  22.04  -> 22.04    (Ubuntu, Python)
--   exact       2022   -> 2022     (Windows Server)
CREATE TABLE IF NOT EXISTS support_status_map (
    id          BIGSERIAL PRIMARY KEY,
    match_kind  VARCHAR(10)  NOT NULL CHECK (match_kind IN ('os','package')),
    aac_key     VARCHAR(255) NOT NULL,  -- os_family value, or package_name
    eol_product VARCHAR(100) NOT NULL,
    cycle_mode  VARCHAR(12)  NOT NULL DEFAULT 'major'
                CHECK (cycle_mode IN ('major','majorminor','exact')),
    notes       TEXT,
    UNIQUE (match_kind, aac_key)
);

-- ── host_support_status ──────────────────────────────────────────────────────
-- Derived: one row per host × tracked product.
CREATE TABLE IF NOT EXISTS host_support_status (
    id              BIGSERIAL PRIMARY KEY,
    resolved_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    hostname        VARCHAR(255) NOT NULL,
    match_kind      VARCHAR(10)  NOT NULL,
    product         VARCHAR(255) NOT NULL,  -- as observed by us
    eol_product     VARCHAR(100) NOT NULL,  -- as known upstream
    observed_version VARCHAR(100),
    cycle           VARCHAR(50),
    lifecycle_stage VARCHAR(20)  NOT NULL,
    eol_date        DATE,
    days_to_eol     INTEGER,                -- negative once past
    debt_category   VARCHAR(40)  NOT NULL DEFAULT 'technology_lifecycle',
    UNIQUE (hostname, match_kind, product, observed_version)
);

CREATE INDEX IF NOT EXISTS idx_hss_stage ON host_support_status (lifecycle_stage);
CREATE INDEX IF NOT EXISTS idx_hss_host  ON host_support_status (hostname);

-- ── seed the map ─────────────────────────────────────────────────────────────
-- OS rows first — highest value, cover every host, need no extra collection.
INSERT INTO support_status_map (match_kind, aac_key, eol_product, cycle_mode, notes) VALUES
    ('os','RedHat','rhel','major','os_version 9.3 -> cycle 9'),
    ('os','Debian','debian','major','Debian proper; Ubuntu overridden below'),
    ('os','Ubuntu','ubuntu','majorminor','22.04 is the cycle, not 22'),
    ('os','Suse','sles','majorminor',NULL),
    ('os','Windows','windows-server','exact','os_version is the year, e.g. 2022'),
    ('os','Rocky','rocky-linux','major',NULL),
    ('os','AlmaLinux','almalinux','major',NULL),
    ('os','Amazon','amazon-linux','exact','2023 / 2 are the cycles'),
    ('package','python3','python','majorminor','3.11 is the cycle'),
    ('package','nodejs','nodejs','major',NULL),
    ('package','postgresql','postgresql','major',NULL),
    ('package','openssl','openssl','majorminor',NULL)
ON CONFLICT (match_kind, aac_key) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'compliance_reader') THEN
        GRANT SELECT ON product_lifecycle, support_status_map, host_support_status
            TO compliance_reader;
    END IF;
END
$$;
