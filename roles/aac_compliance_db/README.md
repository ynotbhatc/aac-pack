# aac_compliance_db

Ansible role that deploys and initializes the containerized PostgreSQL compliance
database for Ansible Automated Compliance (AAC).

## What this role does

1. Pulls the PostgreSQL image and creates the `compliance_pgdata` named volume
2. Recreates the `postgresql` container on port 5432
3. Waits for PostgreSQL to accept connections
4. Creates all four compliance schema tables (idempotent — `IF NOT EXISTS`)
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
