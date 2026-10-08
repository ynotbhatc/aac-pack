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
# Output (decision): { route, authority, agent_recommended, overrode_agent, reasons }
#   route ∈ {compliant, auto_remediate, approve_remediate}
#
# FAIL-CLOSED: the default route is approve_remediate (a human). "compliant"
# must be PROVEN (no drift AND a compliant baseline verdict); auto-remediation
# must be EARNED (drift that is non-critical, unticketed, on a non-compliant
# check). Missing or malformed facts land in front of a human, never in
# silent auto-action. Thresholds are OWNED BY THE OPERATOR, not the model.
# Demo-specific policy: lives here, never in the vendor-neutral rego library.

package aac.tanium.drift_routing

import rego.v1

# ── Input normalization (set_stats may stringify booleans) ────────────

any_drift if input.facts.any_drift == true
any_drift if input.facts.any_drift == "true"

critical_drift if input.facts.critical_drift == true
critical_drift if input.facts.critical_drift == "true"

baseline_compliant if input.facts.baseline_compliant == true
baseline_compliant if input.facts.baseline_compliant == "true"

has_change_ticket if {
	is_string(input.facts.change_ticket)
	trim_space(input.facts.change_ticket) != ""
}

# ── Route decision — fail-closed to a human ───────────────────────────

default route := "approve_remediate"

# Compliant must be proven: no drift AND the baseline verdict agrees.
route := "compliant" if {
	not any_drift
	baseline_compliant
}

# Auto-remediation must be earned: real drift, non-critical class, no
# authorized change ticket on record (an authorized change must never be
# silently reverted — a human decides against the ticket).
route := "auto_remediate" if {
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

reasons contains "critical drift class (selinux/sshd) — human approval required" if {
	any_drift
	critical_drift
}

reasons contains sprintf("authorized change ticket %v on record — never silently revert an authorized change; human decides", [input.facts.change_ticket]) if {
	any_drift
	has_change_ticket
}

reasons contains "facts incomplete or unproven — fail-closed to human approval" if {
	route == "approve_remediate"
	not any_drift
}

# ── The decision object the workflow switch reads ─────────────────────

decision := {
	"route": route,
	"authority": "policy",
	"agent_recommended": object.get(input, ["agent", "recommended_route"], "absent"),
	"overrode_agent": overrode_agent,
	"reasons": reasons,
}
