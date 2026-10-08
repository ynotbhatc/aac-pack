# aac.gpuflex.routing — GPU cross-domain flex governance gate.
# Two decisions, both consumed by the AO governed workflow:
#   /v1/data/aac/gpuflex/routing/decision -> {route: tier1_mig|tier2_migrate|hold}
#   /v1/data/aac/gpuflex/routing/enter    -> {allow: bool}  (Tier-2 enter-destination gate)
# Facts arrive from AO as templated strings, so booleans are matched as bool OR "true".
package aac.gpuflex.routing

import rego.v1

_facts := object.get(input, "facts", {})

_num(k) := to_number(object.get(_facts, k, 0))

_truthy(k) if object.get(_facts, k, false) == true
_truthy(k) if object.get(_facts, k, false) == "true"

# ── Tier routing: MIG-first, escalate to governed cross-domain move ──────
route := "tier1_mig" if {
	_truthy("mig_capable")
	_num("demand_units") > 0
	_num("demand_units") <= _num("domain_headroom_units")
} else := "tier2_migrate" if {
	_num("demand_units") > 0
	_truthy("cross_domain_available")
} else := "hold"

_reasons := {
	"tier1_mig": "intra-domain MIG headroom covers demand — no ESP crossing",
	"tier2_migrate": "intra-domain headroom exhausted — governed cross-domain node migration",
	"hold": "no capacity path available — queued",
}

decision := {"route": route, "reason": _reasons[route]}

# ── Tier-2 enter-destination gate (CIP-010 R1/R3 + reimage provenance) ───
default enter := {"gate": "deny", "allow": false, "reason": "entry checks incomplete"}

_enter_ok if {
	_truthy("reimage_provenance_valid")
	_truthy("dest_baseline_clean")
	_truthy("vuln_passed")
}

enter := {"gate": "allow", "allow": true, "reason": "reimage provenance + destination baseline + vuln assessment all passed"} if _enter_ok
enter := {"gate": "deny", "allow": false, "reason": "one or more entry checks failed — hold at destination boundary"} if not _enter_ok
