# AAC — Golden-Image governed-drift routing policy
# Entrypoint: data.aac.golden.routing.decision
#   POST /v1/data/aac/golden/routing/decision  body {"input": {...}}
# Input: { agent:{recommended_route}, facts:{any_drift,critical_drift,baseline_compliant,drifted_key,target_host} }
# Output: { route, authority, agent_recommended, overrode_agent, reasons }  route ∈ {auto,approve,investigate,hold}
package aac.golden.routing

import rego.v1

facts := object.get(input, "facts", {})
agent := object.get(input, "agent", {})

# as_bool is TOTAL: every value resolves to exactly one boolean. Without the
# catch-all, a malformed fact (e.g. "yes", 1, []) would make as_bool undefined,
# the derived fact undefined, and -- with `default route := "auto"` -- the whole
# decision would silently collapse to the enforce path. Fail closed to false.
as_bool(v) := v if is_boolean(v)
as_bool(v) if v == "true"
as_bool(v) := false if v == "false"
as_bool(v) := false if v == ""
as_bool(v) := false if is_null(v)

as_bool(v) := false if {
	not is_boolean(v)
	v != "true"
	v != "false"
	v != ""
	not is_null(v)
}

any_drift := as_bool(object.get(facts, "any_drift", false))
critical_drift := as_bool(object.get(facts, "critical_drift", false))

# A MISSING baseline_compliant fact defaults to false (fail closed): with drift
# present we do not auto-roll-back on the strength of a baseline we never saw --
# absent/incomplete baseline evidence routes to investigate, not auto.
baseline_compliant := as_bool(object.get(facts, "baseline_compliant", false))
drifted_key := object.get(facts, "drifted_key", "")

security_keys := {"selinux_config", "sshd_config", "auditd", "firewall", "authorized_keys"}

# Invalid-input gate. as_bool coerces an unrecognized value to false so the
# decision never collapses to undefined -- but coercing a malformed critical /
# drift signal to false would DOWNGRADE it to routine drift and auto-roll-back
# (fail open). So we separately detect when a boolean fact is present but not a
# recognized encoding, and route that to a human (investigate) rather than trust
# the coerced value. Absent keys are fine (they take their documented default).
_recognized_bool(v) if is_boolean(v)
_recognized_bool(v) if v == "true"
_recognized_bool(v) if v == "false"
_recognized_bool(v) if v == ""
_recognized_bool(v) if is_null(v)

_bool_fact_keys := {"any_drift", "critical_drift", "baseline_compliant"}

invalid_input if {
	some k in _bool_fact_keys
	val := facts[k]
	not _recognized_bool(val)
}

# ── Managed-change / rollback-pause overrides (data-driven config) ────
# data.aac.golden.config is an editable data document:
#   { rollback_paused: bool, authorized_change_hosts: [hostname, ...] }
# A "hold" route means drift was observed but enforcement is intentionally
# suspended (a maintenance freeze, or this host is under an authorized change),
# so the workflow records it and does NOT roll back work-in-progress.
# Reference the config data LEAVES directly (with defaults) -- reading the
# parent object.get(data.aac.golden, ...) would pull in this package and recurse.
default rollback_paused := false

rollback_paused := as_bool(data.aac.golden.config.rollback_paused)

default authorized_change_hosts := []

authorized_change_hosts := data.aac.golden.config.authorized_change_hosts

target_host := object.get(facts, "target_host", "")

is_hold if rollback_paused

is_hold if {
	target_host != ""
	target_host in authorized_change_hosts
}

_security_key_drift if drifted_key in security_keys

# Fail closed on baseline: any drift we cannot safely auto-roll-back -- because
# the baseline is absent or non-compliant -- goes to a human to investigate,
# whether or not the drifted key is known. Critical / security-control drift is
# excluded here because it routes to approve (below), not investigate.
is_investigate if {
	any_drift
	not baseline_compliant
	not critical_drift
	not _security_key_drift
}

# Malformed input never auto-rolls-back: route it to a human.
is_investigate if invalid_input

is_approve if {
	any_drift
	critical_drift
}

is_approve if {
	any_drift
	_security_key_drift
}

default route := "auto"

route := "hold" if is_hold

route := "investigate" if {
	is_investigate
	not is_hold
}

route := "approve" if {
	is_approve
	not is_investigate
	not is_hold
}

agent_raw := object.get(agent, "recommended_route", "auto")

default agent_route := "auto"

agent_route := "auto" if agent_raw in {"auto", "auto_rollback", "auto_patch"}
agent_route := "approve" if agent_raw in {"approve", "approve_rollback", "approve_patch"}
agent_route := "investigate" if agent_raw == "investigate"

overrode_agent := route != agent_route

reasons contains "rollback paused - enforcement suspended by data.aac.golden.config.rollback_paused" if rollback_paused

reasons contains sprintf("host %q is under an authorized change - drift observed, not rolled back", [target_host]) if {
	not rollback_paused
	target_host != ""
	target_host in authorized_change_hosts
}

reasons contains "no drift detected - baseline intact" if not any_drift

reasons contains sprintf("drifted key %q is a security control - human approval required to roll back", [drifted_key]) if {
	not is_hold
	any_drift
	drifted_key in security_keys
}

reasons contains "critical drift - human approval required to roll back" if {
	not is_hold
	any_drift
	critical_drift
}

reasons contains "no usable baseline - routing to investigate" if {
	is_investigate
	not invalid_input
}

reasons contains "invalid/unrecognized input fact - routing to human review" if invalid_input

reasons contains "routine drift within policy - auto-rollback permitted" if {
	route == "auto"
	any_drift
}

decision := {
	"route": route,
	"authority": "policy",
	"agent_recommended": agent_route,
	"overrode_agent": overrode_agent,
	"reasons": reasons,
}
