# AMI Golden Meter — govern-the-AI routing decision (for the AO workflow's OPA gate)
#
# The AO agent node RECOMMENDS a route; this policy DECIDES it. That split is the
# whole point: the switch routes on THIS verdict, not the model's own output, and
# this policy is strictly more conservative — it can override the agent toward
# safety (auto → approve, or → incident) but never the other way. Fail-closed:
# anything ambiguous routes to a human (approve).
#
# Three routes:
#   "auto"     — auto-remediate (rollback) at machine speed
#   "approve"  — human approval required before remediation
#   "incident" — suspected bad actor → CIP-008 incident, never silent remediation
#
# Composes the asset-criticality gate (data.aac.ami.gate, which reads input.meter
# + the meter registry) with the agent's recommendation and the change ticket.
# Entry: data.aac.ami.routing.decision
#
# Input contract (from the AO workflow's opa_gate node — every value is templated
# in as a STRING, so booleans arrive as "true"/"false", never native):
#   { "agent":  { "recommended_route": "auto_remediate|approve_remediate|investigate|bad_actor",
#                 "bad_actor_suspected": true|false|"true"|"false", "reasoning": "..." },
#     "meter":  { "id": "<meter id>" }, "drift": { "fields": "..." },
#     "change_ticket": "<ticket id or ''>" }
#
# FAIL-CLOSED CONTRACT:
#   * a malformed bad-actor flag ("yes", 1, []) is never coerced to false — it
#     routes to a human (approve) with the reason recorded;
#   * if the asset-criticality gate is not loaded (data.aac.ami.gate absent) the
#     asset is treated as critical — "unknown criticality" never earns auto.

package aac.ami.routing

import rego.v1

_agent := object.get(input, "agent", {})

_authorized if trim_space(object.get(input, "change_ticket", "")) != ""

# ── Bad-actor flag: native OR templated string, fail closed on anything else ─
_bad_actor_raw := object.get(_agent, "bad_actor_suspected", false)

_recognized_bool(v) if is_boolean(v)

_recognized_bool(v) if {
	is_string(v)
	lower(trim_space(v)) in {"true", "false", ""}
}

_recognized_bool(v) if is_null(v)

_bad_actor if _bad_actor_raw == true

_bad_actor if {
	is_string(_bad_actor_raw)
	lower(trim_space(_bad_actor_raw)) == "true"
}

# Malformed input never earns auto: an unrecognized bad-actor encoding, or a
# recommended_route that is not a string, lands in front of a human.
invalid_input if not _recognized_bool(_bad_actor_raw)

invalid_input if {
	"recommended_route" in object.keys(_agent)
	not is_string(_agent.recommended_route)
}

# ── Criticality from the asset gate — unknown is critical ────────────────────
# A critical/ESP/revenue meter, or a security-relevant drift field, makes
# risk_class == "critical". If the gate package is not loaded at all, the
# criticality is unknown and we fail closed: unknown == critical.
_gate_known if is_string(data.aac.ami.gate.decision.risk_class)

_critical if data.aac.ami.gate.decision.risk_class == "critical"

_critical if not _gate_known

# total — never undefined even when input.agent is absent (would collapse decision)
_agent_route := _agent.recommended_route if is_string(_agent.recommended_route)

default _agent_route := "unknown"

# ── the decision — mutually-exclusive guards, fail-closed default ────────────
default route := "approve"

# A suspected bad actor is never remediated silently — override to incident.
route := "incident" if _bad_actor

# Critical asset → a human approves, even if the agent recommended auto.
route := "approve" if {
	not _bad_actor
	_critical
}

# Non-critical but UNAUTHORIZED, and the agent didn't clear it → approve.
route := "approve" if {
	not _bad_actor
	not _critical
	not _authorized
	_agent_route != "auto_remediate"
}

# Auto only when ALL align: well-formed input, not a bad actor, not critical,
# authorized, AND the agent recommended auto. Any one missing falls through to
# the approve default.
route := "auto" if {
	not invalid_input
	not _bad_actor
	not _critical
	_authorized
	_agent_route == "auto_remediate"
}

# Did OPA override the agent's recommendation toward safety? (the govern-the-AI proof)
_norm_agent := "auto" if _agent_route == "auto_remediate"

_norm_agent := "approve" if _agent_route in {"approve_remediate", "investigate"}

_norm_agent := "incident" if _agent_route == "bad_actor"

_norm_agent := "unknown" if not _agent_route in {"auto_remediate", "approve_remediate", "investigate", "bad_actor"}

# total (default false) so the decision object never collapses on the no-override path
default overrode_agent := false

overrode_agent if {
	_agent_route != "unknown"
	route != _norm_agent
}

reasons contains "suspected bad actor — routing to CIP-008 incident, not remediation" if _bad_actor

reasons contains "invalid/unrecognized agent input — human approval required" if {
	not _bad_actor
	invalid_input
}

reasons contains "asset-criticality gate (data.aac.ami.gate) not loaded — treating the asset as critical" if {
	not _bad_actor
	not _gate_known
}

reasons contains sprintf("critical asset (%v) — human approval required", [object.get(object.get(input, "meter", {}), "id", "unknown")]) if {
	not _bad_actor
	_critical
}

reasons contains "unauthorized change (no change ticket) — human approval required" if {
	not _bad_actor
	not _critical
	not _authorized
	_agent_route != "auto_remediate"
}

reasons contains sprintf("OPA overrode the agent (recommended '%v') toward safety", [_agent_route]) if overrode_agent

decision := {
	"route": route,
	"agent_recommended": _agent_route,
	"opa_overrode_agent": overrode_agent,
	"invalid_input": invalid_input,
	"reasons": [r | some r in reasons],
}

default invalid_input := false
