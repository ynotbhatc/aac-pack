# AAC — Tanium-comparison AO demo: drift-remediation routing policy
#
# The governance boundary for the governed-drift workflow. The AI triage agent
# REASONS about the drift and recommends a route; this policy DECIDES the route
# the workflow switch acts on. Agent proposes, policy disposes — the beat no
# endpoint-management product can show, because none of them has a decision
# engine in the remediation path.
#
# Entrypoint: data.aac.tanium.drift_routing.decision
#   POST /v1/data/aac/tanium/drift_routing/decision  body {"input": {...}}
#
# Input contract (from the AO workflow: check set_stats + triage_agent):
#   {
#     "agent": { "recommended_route": "compliant|auto_remediate|approve_remediate",
#                "rationale": "<free text, informational only>" },
#     "facts": { "any_drift":      <bool>,
#                "critical_drift": <bool — selinux/sshd class>,
#                "baseline_compliant":  <bool — baseline verdict from the check>,
#                "change_ticket":  "<authorized change record id, '' if none>",
#                "drift_trigger":  "<changed-file category>" }
#   }
#
# Output (decision): { route, authority, agent_recommended, overrode_agent,
#                      invalid_input, reasons }
#   route ∈ {compliant, auto_remediate, approve_remediate}
#
# FAIL-CLOSED: the default route is approve_remediate (a human). "compliant"
# must be PROVEN (an explicit no-drift fact AND a compliant baseline verdict);
# auto-remediation must be EARNED (drift that is non-critical, unticketed, on a
# non-compliant check). Missing or malformed facts land in front of a human,
# never in silent auto-action — a boolean fact that is present but not a
# recognized encoding ("yes", 1, []) is never coerced to false, because that
# would downgrade a critical signal to routine drift. Thresholds are OWNED BY
# THE OPERATOR, not the model. Demo-specific policy: lives here, never in the
# vendor-neutral rego library.

package aac.tanium.drift_routing

import rego.v1

facts := object.get(input, "facts", {})

# ── Input normalization (set_stats / AO templating may stringify booleans) ──
# as_bool is TOTAL: every value resolves to exactly one boolean, so a derived
# fact is never undefined. Unrecognized encodings coerce to false here AND are
# caught separately by invalid_input below, so they can never earn auto.
as_bool(v) := v if is_boolean(v)

as_bool(v) if {
	is_string(v)
	lower(trim_space(v)) == "true"
}

as_bool(v) := false if {
	is_string(v)
	lower(trim_space(v)) != "true"
}

as_bool(v) := false if is_null(v)

as_bool(v) := false if {
	not is_boolean(v)
	not is_string(v)
	not is_null(v)
}

_recognized_bool(v) if is_boolean(v)

_recognized_bool(v) if {
	is_string(v)
	lower(trim_space(v)) in {"true", "false", ""}
}

_recognized_bool(v) if is_null(v)

_bool_fact_keys := {"any_drift", "critical_drift", "baseline_compliant"}

# A boolean fact that is present but not a recognized encoding.
invalid_input if {
	some k in _bool_fact_keys
	val := facts[k]
	not _recognized_bool(val)
}

default invalid_input := false

_present(k) if k in object.keys(facts)

any_drift := as_bool(object.get(facts, "any_drift", false))

critical_drift := as_bool(object.get(facts, "critical_drift", false))

baseline_compliant := as_bool(object.get(facts, "baseline_compliant", false))

has_change_ticket if {
	is_string(facts.change_ticket)
	trim_space(facts.change_ticket) != ""
}

# ── Route decision — fail-closed to a human ───────────────────────────

default route := "approve_remediate"

# Compliant must be PROVEN: an explicit, well-formed no-drift fact AND the
# baseline verdict agrees. An absent any_drift is not "no drift".
route := "compliant" if {
	not invalid_input
	_present("any_drift")
	not any_drift
	baseline_compliant
}

# Auto-remediation must be earned: well-formed facts, real drift, non-critical
# class, no authorized change ticket on record (an authorized change must never
# be silently reverted — a human decides against the ticket).
route := "auto_remediate" if {
	not invalid_input
	any_drift
	not critical_drift
	not has_change_ticket
	not baseline_compliant
}

# ── Override bookkeeping (the demo's receipt) ─────────────────────────

default agent_route := "absent"

agent_route := input.agent.recommended_route if {
	is_string(input.agent.recommended_route)
}

overrode_agent := route != agent_route

# ── Reasons (evidence + presenter narration) ──────────────────────────

reasons contains "no drift and baseline verdict compliant — record only" if {
	route == "compliant"
}

reasons contains "non-critical drift, no change ticket — auto-remediation permitted" if {
	route == "auto_remediate"
}

reasons contains "invalid/unrecognized input fact — fail-closed to human approval" if invalid_input

reasons contains "critical drift class (selinux/sshd) — human approval required" if {
	not invalid_input
	any_drift
	critical_drift
}

reasons contains sprintf("authorized change ticket %v on record — never silently revert an authorized change; human decides", [facts.change_ticket]) if {
	not invalid_input
	any_drift
	has_change_ticket
}

reasons contains "drift reported but the baseline verdict is compliant — contradictory facts, human decides" if {
	not invalid_input
	any_drift
	baseline_compliant
}

reasons contains "facts incomplete or unproven — fail-closed to human approval" if {
	not invalid_input
	route == "approve_remediate"
	not any_drift
}

# ── The decision object the workflow switch reads ─────────────────────

decision := {
	"route": route,
	"authority": "policy",
	"agent_recommended": object.get(input, ["agent", "recommended_route"], "absent"),
	"overrode_agent": overrode_agent,
	"invalid_input": invalid_input,
	"reasons": reasons,
}
