-- demo_cve_fixture.sql — labelled demo CVE population for the Mythos patch demo
--
-- ===========================================================================
-- THIS IS A FIXTURE. IT IS NOT REAL VULNERABILITY DATA.
-- ===========================================================================
-- Every row carries source='demo_seed' and a synthetic CVE id in the
-- CVE-2026-9xxxx range that does not correspond to any real advisory.
--
-- Real CVE identifiers are deliberately NOT used. Attaching invented severities,
-- affected versions or fix dates to a genuine CVE id would put false security
-- information into a database that people make decisions from — and it would
-- survive long after this demo, indistinguishable from measured data.
--
-- The ESTATE these match against is real: real hosts, real installed components,
-- real versions, observed by fact collection. Only the vulnerability data is
-- synthetic. That is the honest split, and the demo says so out loud.
--
-- Delete with:  DELETE FROM cve_events_received WHERE source='demo_seed';
--               (cve_vendor_remediations cascades on the FK)
--
-- The fixture deliberately spans the full matrix so the heat map has structure:
--   severity        CRITICAL / HIGH / MEDIUM / LOW
--   KEV             actively exploited vs not
--   SLA state       attained / at_risk / breached  (against REAL regulatory clocks)
--   valley type     exposure / currency / support
--   debt category   security / technology_lifecycle

DELETE FROM cve_events_received WHERE source = 'demo_seed';

-- ---------------------------------------------------------------------------
-- CVE facts
-- ---------------------------------------------------------------------------
INSERT INTO cve_events_received
  (cve_id, cvss_v3, severity, kev_member, published_at, vendor, product,
   affected_versions, description, source)
VALUES
  -- CRITICAL + KEV — the "drop everything" band. CISA BOD 22-01 gives 14 days.
  ('CVE-2026-90001', 9.8, 'CRITICAL', true,  now() - interval '60 days', 'openssl', 'openssl',
   NULL, 'DEMO FIXTURE — remote code execution in TLS handshake handling', 'demo_seed'),
  ('CVE-2026-90002', 9.1, 'CRITICAL', true,  now() - interval '14 days', 'glibc', 'glibc',
   NULL, 'DEMO FIXTURE — heap overflow in name resolution', 'demo_seed'),
  ('CVE-2026-90003', 8.8, 'HIGH',     true,  now() - interval '30 days', 'curl', 'curl',
   ARRAY['8.2.1','7.76.1'], 'DEMO FIXTURE — credential leak on redirect (version-specific)', 'demo_seed'),

  -- CRITICAL, not exploited — PCI DSS v4.0 6.3.3 gives one month
  ('CVE-2026-90004', 9.0, 'CRITICAL', false, now() - interval '75 days', 'openssh', 'openssh',
   NULL, 'DEMO FIXTURE — authentication bypass under specific config', 'demo_seed'),

  -- HIGH — NERC CIP-007-6 R2.2/R2.3 gives 35 days
  ('CVE-2026-90005', 7.5, 'HIGH',   false, now() - interval '30 days', 'systemd', 'systemd',
   NULL, 'DEMO FIXTURE — privilege escalation via unit file parsing', 'demo_seed'),
  ('CVE-2026-90006', 7.8, 'HIGH',   false, now() - interval '55 days', 'bash', 'bash',
   NULL, 'DEMO FIXTURE — command injection in completion handling', 'demo_seed'),
  ('CVE-2026-90013', 7.2, 'HIGH',   false, now() - interval '10 days', 'libcap', 'libcap',
   NULL, 'DEMO FIXTURE — capability inheritance flaw', 'demo_seed'),

  -- HIGH against a product that is UNSUPPORTED on part of the estate.
  -- This is the one that lands in technology_lifecycle: no patch will ever come
  -- for those hosts, so it is REPLACEMENT debt, not remediation debt.
  ('CVE-2026-90010', 7.5, 'HIGH',   false, now() - interval '220 days', 'python3', 'python3',
   NULL, 'DEMO FIXTURE — deserialization flaw; unsupported on part of the estate', 'demo_seed'),

  -- MEDIUM — FedRAMP ConMon 90 days
  ('CVE-2026-90007', 6.5, 'MEDIUM', false, now() - interval '35 days', 'libxml2', 'libxml2',
   NULL, 'DEMO FIXTURE — XML entity expansion denial of service', 'demo_seed'),
  ('CVE-2026-90008', 5.9, 'MEDIUM', false, now() - interval '140 days', 'tar', 'tar',
   NULL, 'DEMO FIXTURE — path traversal on extraction', 'demo_seed'),
  ('CVE-2026-90012', 6.1, 'MEDIUM', false, now() - interval '80 days', 'less', 'less',
   NULL, 'DEMO FIXTURE — escape sequence injection', 'demo_seed'),
  ('CVE-2026-90014', 5.3, 'MEDIUM', false, now() - interval '20 days', 'ca-certificates', 'ca-certificates',
   NULL, 'DEMO FIXTURE — stale trust anchor retained', 'demo_seed'),

  -- LOW — 180 days
  ('CVE-2026-90009', 3.7, 'LOW',    false, now() - interval '70 days', 'rsync', 'rsync',
   NULL, 'DEMO FIXTURE — information disclosure in verbose output', 'demo_seed'),
  ('CVE-2026-90011', 3.1, 'LOW',    false, now() - interval '240 days', 'gzip', 'gzip',
   NULL, 'DEMO FIXTURE — malformed archive causes crash', 'demo_seed');

-- ---------------------------------------------------------------------------
-- Vendor remediations — the table that has been EMPTY and blocks everything
-- downstream (§13 build-sequence #1).
--
-- available_at is the date the FIX shipped, which is what the age factor is
-- measured from. Note it differs from published_at above: the exposure clock
-- starts when action became possible, not when the flaw became known.
--
-- CVE-2026-90010 (python3) deliberately has NO remediation row for the
-- unsupported hosts — that is the "support" valley: no fix will ever exist.
-- ---------------------------------------------------------------------------
INSERT INTO cve_vendor_remediations
  (cve_id, vendor, vendor_advisory_id, fix_version, patch_url, patch_description, available_at)
VALUES
  ('CVE-2026-90001', 'openssl',         'DEMO-SA-0001', '3.2.4',    NULL, 'DEMO FIXTURE', now() - interval '45 days'),
  ('CVE-2026-90002', 'glibc',           'DEMO-SA-0002', '2.40',     NULL, 'DEMO FIXTURE', now() - interval '9 days'),
  ('CVE-2026-90003', 'curl',            'DEMO-SA-0003', '8.13.0',   NULL, 'DEMO FIXTURE', now() - interval '21 days'),
  ('CVE-2026-90004', 'openssh',         'DEMO-SA-0004', '9.9p1',    NULL, 'DEMO FIXTURE', now() - interval '62 days'),
  ('CVE-2026-90005', 'systemd',         'DEMO-SA-0005', '256.8',    NULL, 'DEMO FIXTURE', now() - interval '26 days'),
  ('CVE-2026-90006', 'bash',            'DEMO-SA-0006', '5.3.1',    NULL, 'DEMO FIXTURE', now() - interval '48 days'),
  ('CVE-2026-90013', 'libcap',          'DEMO-SA-0013', '2.76',     NULL, 'DEMO FIXTURE', now() - interval '6 days'),
  ('CVE-2026-90010', 'python3',         'DEMO-SA-0010', '3.13.2',   NULL, 'DEMO FIXTURE — supported branches only', now() - interval '205 days'),
  ('CVE-2026-90007', 'libxml2',         'DEMO-SA-0007', '2.13.6',   NULL, 'DEMO FIXTURE', now() - interval '31 days'),
  ('CVE-2026-90008', 'tar',             'DEMO-SA-0008', '1.36',     NULL, 'DEMO FIXTURE', now() - interval '128 days'),
  ('CVE-2026-90012', 'less',            'DEMO-SA-0012', '669',      NULL, 'DEMO FIXTURE', now() - interval '72 days'),
  ('CVE-2026-90014', 'ca-certificates', 'DEMO-SA-0014', '2026.2.1', NULL, 'DEMO FIXTURE', now() - interval '18 days'),
  ('CVE-2026-90009', 'rsync',           'DEMO-SA-0009', '3.4.1',    NULL, 'DEMO FIXTURE', now() - interval '64 days'),
  ('CVE-2026-90011', 'gzip',            'DEMO-SA-0011', '1.14',     NULL, 'DEMO FIXTURE', now() - interval '232 days')
ON CONFLICT (cve_id, vendor) DO UPDATE
   SET fix_version = EXCLUDED.fix_version,
       available_at = EXCLUDED.available_at;
