# aac_compliance_db

Ansible role that deploys and initializes the containerized PostgreSQL compliance
database for Ansible Automated Compliance (AAC).

## What this role does

1. Pulls the PostgreSQL image and creates the `compliance_pgdata` named volume
2. Recreates the `postgresql` container on port 5432
3. Waits for PostgreSQL to accept connections
4. Creates the compliance schema — 32 tables and 8 views, see below (idempotent — `IF NOT EXISTS`)
5. Creates the `compliance_reader` read-only role with SELECT grants
6. Runs a health check verifying table presence
7. Optionally generates a podman systemd unit for on-boot startup

## Schema created

| Object | Type | Purpose |
|--------|------|---------|
| `compliance_results` | Table | OPA evaluation results (all frameworks) |
| `compliance_facts` | Table | Raw Ansible facts (pre-OPA evaluation) |
| `host_facts` | Table | Nightly gather_facts snapshots (ADR-001) |
| `host_facts_latest` | View | Most recent snapshot per host |
| `sidecar_datasets` | Table | Org context: Digital Sovereignty, NERC-CIP assets |
| `sidecar_datasets_latest` | View | Most recent sidecar per type+entity |
| `technical_debt_items`, `technical_debt_summary`, `technical_debt_summary_latest` | Tables, View | Technical-debt ledger and roll-up |
| `remediation_rates`, `remediation_budgets`, `framework_catalog`, `customer_frameworks` | Tables | Remediation cost model and framework catalog |
| `compliance_certifications` | Table | Signed CAA certifications |
| `ai_systems`, `ai_action_log`, `ai_approval_requests` | Tables | AI governance decision log (`files/ai_action_log_schema.sql`) |
| `installed_inventory`, `manual_product_declarations`, `inventory_catalog` | Tables, Mat. view | Installed-component inventory (`files/inventory_catalog_schema.sql`) |
| `cve_events_received`, `cve_vendor_remediations` | Tables | AAC-side CVE cache (`files/cve_cache_schema.sql`) |
| `patch_manifest_raw`, `patch_worklist` | Tables | Patch worklist (`files/patch_worklist_schema.sql`) |
| `product_lifecycle`, `support_status_map`, `host_support_status` | Tables | Vendor support status (`files/support_status_schema.sql`) |
| `patch_risk_parameters`, `patch_risk_scores`, `patch_heatmap_cells`, `patch_heatmap_latest`, `patch_unpatched_systems` | Tables, Views | Patch risk scoring (`files/patch_risk_schema.sql`) |
| `golden_image_baselines`, `helpdesk_tickets`, `remediation_log` | Tables | Golden Image governed drift (`files/golden_image_schema.sql`) |
| `patch_traffic_state`, `patch_assurance_results`, `patch_backup_manifests`, `patch_traffic_current`, `patch_traffic_stranded` | Tables, Views | Patch change record, traffic and assurance (`files/patch_change_schema.sql`) |

The `files/*.sql` scripts are applied by `tasks/schema.yml` in dependency order,
one `postgresql_script` task per file, no loops and no conditions: the
sales.demos platform parses that task file and replays its statements through
psql as its application role, so a looped or conditional task would render
wrong there. Six of the files are also re-applied at start by the playbooks
that own their tables; `cve_cache_schema.sql` and `golden_image_schema.sql`
are applied by this role only, so re-run the role (schema-only, Template 79)
on an existing database before expecting those tables. A fresh install
creates **32 tables and 8 views** (measured 2026-10-10 against PostgreSQL 15 as
a non-superuser owner, two consecutive runs clean).

All DDL is idempotent — safe to re-run for schema migrations.

**Note:** `compliance_results.policy_version` is `VARCHAR(100)` — widened
from the original `VARCHAR(50)` to accommodate longer OPA policy version strings.

## Defaults

| Variable | Default | Description |
|----------|---------|-------------|
| `aac_db_image` | `registry.access.redhat.com/ubi9/postgresql-15` | PostgreSQL container image |
| `aac_db_container_name` | `postgresql` | Container name |
| `aac_db_volume` | `compliance_pgdata` | Podman named volume |
| `aac_db_port` | `5432` | Host port |
| `aac_db_name` | `compliance` | Database name |
| `aac_db_user` | `postgres` | Superuser account |
| `aac_db_password` | `{{ compliance_db_password }}` | From Ansible Vault |
| `aac_db_reader_user` | `compliance_reader` | Read-only role (Grafana, reports) |
| `aac_db_reader_password` | `{{ compliance_reader_password }}` | From Ansible Vault |
| `aac_db_generate_systemd` | `true` | Generate and enable systemd unit |
| `aac_db_skip_container_deploy` | `false` | Skip container tasks; schema-only |

## Required variables

From `ansible/vars/site_config.yml`:

| Variable | Example | Description |
|----------|---------|-------------|
| `aac_host` | `<aac-host>` | Host where the container runs |
| `pg_host` | `<aac-host>` | PostgreSQL host (for SQL connections) |
| `pg_port` | `5432` | PostgreSQL port |
| `pg_user` | `postgres` | PostgreSQL superuser |
| `pg_db` | `compliance` | Database name |

From `ansible/vars/vault_secrets.yml`:

| Variable | Description |
|----------|-------------|
| `compliance_db_password` | postgres superuser password |
| `compliance_reader_password` | compliance_reader role password |

## Usage

### Full deploy (container + schema) — AAP Template 114

```yaml
- name: Initialize PostgreSQL Container and Schema
  hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - ../vars/site_config.yml
    - ../vars/vault_secrets.yml
  roles:
    - role: aac_compliance_db
```

### Schema-only (container already running) — AAP Template 79

```yaml
- name: Initialize AAC Core Facts Store Schema
  hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - ../vars/vault_secrets.yml
    - ../vars/site_config.yml
  vars:
    aac_db_skip_container_deploy: true
  roles:
    - role: aac_compliance_db
```

### Full infrastructure stack — AAP Template 80

See `ansible/playbooks/deploy_infrastructure.yml` which runs both
`aac_opa_containers` and `aac_compliance_db` in sequence.

## AAP templates that use this role

| Template ID | Name | Notes |
|-------------|------|-------|
| 23 | Initialize PostgreSQL Database | Full container + schema deploy |
| 79 | AAC - Init Facts Schema | Schema-only (`skip_container_deploy: true`) |
| 80 | AAC - Deploy Infrastructure | OPA + DB in one click |

## Bootstrap fallback

For sites where Ansible is not yet installed, the bash bootstrap script
`scripts/install_postgres.sh` performs the same container deployment steps.
The role is authoritative for AAP-managed environments.
