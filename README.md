# aac-pack

**The Ansible Automated Compliance (AAC) pack**: the playbooks, OPA routing
policies, Automation Orchestrator workflow definitions, evidence-database
schema and dashboards that partner demo platforms consume. Published from the
private `ynotbhatc/compliance` repository by its `scripts/export_sales_demos_pack.py`;
this copy is from commit `unknown` (committed unknown).
**Pin a tag.** `main` moves with every sync; a tag never does.

This repository is generated. Edit the source there; a change made here is
overwritten by the next sync. `MANIFEST.yml` lists every file with its source
path and sha256. The export refuses to publish if a lab identifier, a
secret-shaped string or a customer name survives in the tree.

| Directory | What it is |
|---|---|
| `playbooks/` | The AAC playbooks a consuming platform runs as job templates (an AAP project pointed at this repository at a tag, `playbook: playbooks/<name>.yml`) |
| `vars/`, `files/` | What those playbooks read relative to themselves; `vault_secrets.yml` and `site_config.yml` are deliberately absent, the consuming platform's credentials and extra vars supply values |
| `roles/aac_compliance_db/` | The evidence-database schema as the product applies it (`tasks/schema.yml`) |
| `opa-routing/policies/` | The AO decision policies: the policy decides, the model only recommends |
| `ao/workflows/`, `ao/components.yml` | The AO workflow definitions as the AO API returns them, and what each needs, including the agentic nodes' tool-access posture |
| `grafana/` | AAC dashboards over the evidence database |

Consumers: [ericcames/sales.demos](https://github.com/ericcames/sales.demos)
(plan and phases: sales.demos#841; the pin is its `aac_pack_version`).
The vendor-neutral policy library is separate and also public:
[ynotbhatc/rego_policy_libraries](https://github.com/ynotbhatc/rego_policy_libraries).
