# opa-routing — AO decision/routing OPA

The `opa-routing` OPA instance (namespace `aac-policy`, service `opa-routing:8181`,
image `openpolicyagent/opa:0.70.0-static`) is the policy brain the **Automation
Orchestrator** golden-image and GPU-flex workflows call at their decision node. It is
separate from the three assessment OPAs in namespace `aac` (security / compliance / ot)
and holds only AAC-specific *routing* logic — never vendor-neutral library policy, which
lives in the `policies/` submodule.

These are the source-of-truth copies. The running container loads them from the
`routing-policy` ConfigMap; keep this directory and the ConfigMap in sync.

## Policies

| File | Package / entrypoint | Purpose |
|---|---|---|
| `policies/routing.rego` | base routing | shared routing helpers used by the AO demos |
| `policies/drift_routing.rego` | `aac.golden.routing` → `decision` | golden-image drift → `route ∈ {auto, approve, investigate, hold}` |
| `policies/gpuflex_routing.rego` | GPU cross-domain flex | routing for the GPU capacity-dispatch demo |
| `policies/golden_config.json` | `data.aac.golden.config` | editable data the drift policy reads (see below) |
| `policies/tanium_drift_routing.rego` | `aac.tanium.drift_routing` → `decision` | Tanium-comparison governed drift → `route ∈ {compliant, auto_remediate, approve_remediate}`; fail-closed to a human |
| `policies/ami_routing.rego` | `aac.ami.routing` → `decision` | AMI Golden Meter: meter variance + bad-actor triage → rollback / approve / CIP-008 incident |
| `policies/mythos_scoring.rego` | `aac.mythos.scoring` → `validate` | validates each Mythos scoring agent's `{impact, importance, confidence}` before it is trusted |
| `policies/mythos_routing_v2.rego` | `aac.mythos.routing_v2` → `decision` | composed routing over the converged agent scores (Mythos patch demo v2) |

**Captured 2026-10-08:** the last four files existed only in the live `routing-policy` ConfigMap
(deployment revision 15, 2026-10-07) and are now versioned here, byte-identical to what runs. The
six AO workflows that call them are exported under [`../ao/`](../ao/README.md).

## Managed-change / rollback-pause (the `hold` route)

`drift_routing.rego` reads an editable data document, seeded from `golden_config.json`:

```json
{ "aac": { "golden": { "config": {
  "rollback_paused": false,
  "authorized_change_hosts": []
} } } }
```

`route == "hold"` wins over `auto`/`approve`/`investigate` when **either**:

- `rollback_paused` is `true` — a global enforcement freeze (maintenance window), **or**
- the drifting host (`facts.target_host`) is in `authorized_change_hosts` — a per-host
  authorized-change window.

A `hold` means drift was observed but enforcement is intentionally suspended: the AO
workflow **records** it (opens a `HELD_MANAGED_CHANGE` help-desk record) and does **not**
roll back work-in-progress. When the config returns to the default, enforcement resumes
automatically on the next run.

> The policy references the config leaves directly with defaults
> (`default rollback_paused := false` …). Reading the parent `data.aac.golden` would pull
> in this package (which lives under `data.aac.golden.routing`) and raise a recursion error.

## Flipping the pause

Use the job template **"AAC - Golden Image: Set Rollback Pause"**, backed by
`ansible/playbooks/golden_image_set_rollback_pause.yml`. Survey variables:

| Variable | Default | Meaning |
|---|---|---|
| `rollback_paused` | `no` | global freeze on/off |
| `authorized_change_hosts` | `""` | comma-separated hosts under an authorized change |

The playbook writes the document via the OPA Data API (`PUT /v1/data/aac/golden/config`)
— a **live** change, effective immediately, no pod restart — **and**, when the
`OpenShift In-Cluster (aac-demo-runner)` credential is attached to the job, also persists
the same state into the `routing-policy` ConfigMap so it **survives a pod restart**.

**Durability:** the live PUT alone lives in OPA's in-memory store and is lost if the
`opa-routing` pod restarts. The ConfigMap holds the durable copy OPA reloads at startup.
With the OpenShift credential attached, the toggle patches both, so an active
change-window is not silently undone by a restart. Without the credential the toggle
applies the live change and warns that it is not durable.

## Deploy / reload the ConfigMap

**Automated (preferred):** the **"AAC - Load OPA Routing Policies"** job template
(`ansible/playbooks/load_opa_routing.yml`) patches the ConfigMap from the versioned
policies in this directory and rolls `opa-routing` so OPA reloads them — this is what
keeps the running policy from diverging from the repo. It uses the least-privilege RBAC
in `deploy/rbac.yaml` (the `aac-demo-runner` SA may patch **only** the `routing-policy`
ConfigMap and `opa-routing` Deployment). Apply the RBAC once as a cluster-admin:

```bash
oc apply -f ansible/opa-routing/deploy/rbac.yaml
```

**Manual (cluster-admin fallback):**

```bash
oc create configmap routing-policy -n aac-policy \
  --from-file=routing.rego=policies/routing.rego \
  --from-file=drift_routing.rego=policies/drift_routing.rego \
  --from-file=gpuflex_routing.rego=policies/gpuflex_routing.rego \
  --from-file=golden_config.json=policies/golden_config.json \
  --dry-run=client -o yaml | oc apply -f -

oc rollout restart deploy/opa-routing -n aac-policy
```

The deployment loads every file explicitly (order matters — data file last):

```
opa run --server --addr=0.0.0.0:8181 --log-level=info --set=decision_logs.console=true \
  /policies/routing.rego /policies/drift_routing.rego \
  /policies/gpuflex_routing.rego /policies/golden_config.json
```

## Verify

`opa-routing` has no external route and the OPA image has no shell/curl — probe it with a
throwaway pod:

```bash
oc run tmp -n aac-policy --rm -i --restart=Never \
  --image=registry.access.redhat.com/ubi9/ubi-minimal --command -- \
  curl -s http://opa-routing.aac-policy.svc.cluster.local:8181/v1/data/aac/golden/config

# The GET above shows the DEFAULT config (rollback_paused=false, no hosts), under
# which a decision returns "auto" — NOT "hold". To see a hold you must first
# enable a hold condition. Authorize the host (live PUT), then decide:
oc run tmp -n aac-policy --rm -i --restart=Never \
  --image=registry.access.redhat.com/ubi9/ubi-minimal --command -- \
  curl -s -X PUT -d '{"rollback_paused":false,"authorized_change_hosts":["demo-rhel9"]}' \
  http://opa-routing.aac-policy.svc.cluster.local:8181/v1/data/aac/golden/config

# now a decision for that host → expect "hold"
oc run tmp -n aac-policy --rm -i --restart=Never \
  --image=registry.access.redhat.com/ubi9/ubi-minimal --command -- \
  curl -s -X POST -d '{"input":{"facts":{"any_drift":true,"target_host":"demo-rhel9"}}}' \
  http://opa-routing.aac-policy.svc.cluster.local:8181/v1/data/aac/golden/routing/decision

# restore the safe default when done
oc run tmp -n aac-policy --rm -i --restart=Never \
  --image=registry.access.redhat.com/ubi9/ubi-minimal --command -- \
  curl -s -X PUT -d '{"rollback_paused":false,"authorized_change_hosts":[]}' \
  http://opa-routing.aac-policy.svc.cluster.local:8181/v1/data/aac/golden/config
```

> Offline check (no cluster): `opa test ansible/opa-routing/policies/` exercises every
> route — global pause, per-host authorization, hold precedence, approve, investigate
> (fail-closed baseline), and the default.
