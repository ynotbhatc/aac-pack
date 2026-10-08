# Tests for the AMI Golden Meter routing policy (package aac.ami.routing).
# Run: opa test ansible/opa-routing/policies/ -v
#
# The asset-criticality gate (data.aac.ami.gate) is a separate package; tests
# override its decision leaf. One block runs WITHOUT the override to prove the
# fail-closed behaviour when the gate is not loaded.
package aac.ami.routing_test

import rego.v1

import data.aac.ami.routing

routine := {"risk_class": "routine"}

critical := {"risk_class": "critical"}

# ── auto: everything aligns ───────────────────────────────────────────
test_authorized_routine_agent_auto_autos if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "false"}, "meter": {"id": "M-1"}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
	r.route == "auto"
	r.opa_overrode_agent == false
	r.invalid_input == false
}

test_native_false_bad_actor_autos if {
	routing.route == "auto" with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": false}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
}

# ── incident: suspected bad actor always wins ─────────────────────────
test_bad_actor_native_true_incident if {
	routing.route == "incident" with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": true}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
}

# THE fail-open Copilot flagged: AO templates the flag in as a string.
test_bad_actor_string_true_incident if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "true"}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
	r.route == "incident"
	r.opa_overrode_agent == true
}

test_bad_actor_string_mixed_case_incident if {
	routing.route == "incident" with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": " True "}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
}

test_bad_actor_beats_critical if {
	routing.route == "incident" with input as {"agent": {"recommended_route": "approve_remediate", "bad_actor_suspected": "true"}}
		with data.aac.ami.gate.decision as critical
}

# ── approve: malformed input is never coerced to false ────────────────
test_malformed_bad_actor_approves if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "yes"}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
	r.route == "approve"
	r.invalid_input == true
	"invalid/unrecognized agent input — human approval required" in r.reasons
}

test_numeric_bad_actor_approves if {
	routing.route == "approve" with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": 1}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
}

test_non_string_route_approves if {
	r := routing.decision with input as {"agent": {"recommended_route": ["auto_remediate"], "bad_actor_suspected": "false"}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
	r.route == "approve"
	r.invalid_input == true
	r.agent_recommended == "unknown"
}

# ── approve: critical asset overrides the agent ───────────────────────
test_critical_asset_approves if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "false"}, "meter": {"id": "M-ESP-7"}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as critical
	r.route == "approve"
	r.opa_overrode_agent == true
	"critical asset (M-ESP-7) — human approval required" in r.reasons
}

# ── approve: gate not loaded == unknown criticality == critical ───────
test_gate_absent_approves if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "false"}, "change_ticket": "CHG-100"}
	r.route == "approve"
	"asset-criticality gate (data.aac.ami.gate) not loaded — treating the asset as critical" in r.reasons
}

test_gate_absent_bad_actor_still_incident if {
	routing.route == "incident" with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "true"}, "change_ticket": "CHG-100"}
}

# ── approve: unauthorized change ──────────────────────────────────────
test_unauthorized_agent_approve_approves if {
	r := routing.decision with input as {"agent": {"recommended_route": "approve_remediate", "bad_actor_suspected": "false"}, "change_ticket": ""}
		with data.aac.ami.gate.decision as routine
	r.route == "approve"
	r.opa_overrode_agent == false
	"unauthorized change (no change ticket) — human approval required" in r.reasons
}

test_unauthorized_agent_auto_still_approves if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "false"}, "change_ticket": "   "}
		with data.aac.ami.gate.decision as routine
	r.route == "approve"
	r.opa_overrode_agent == true
}

test_authorized_but_agent_investigate_approves if {
	routing.route == "approve" with input as {"agent": {"recommended_route": "investigate", "bad_actor_suspected": "false"}, "change_ticket": "CHG-100"}
		with data.aac.ami.gate.decision as routine
}

# ── default: no agent at all ──────────────────────────────────────────
test_empty_input_approves if {
	r := routing.decision with input as {}
		with data.aac.ami.gate.decision as routine
	r.route == "approve"
	r.agent_recommended == "unknown"
	r.opa_overrode_agent == false
}

test_decision_shape if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate", "bad_actor_suspected": "false"}, "change_ticket": "CHG-1"}
		with data.aac.ami.gate.decision as routine
	object.keys(r) == {"route", "agent_recommended", "opa_overrode_agent", "invalid_input", "reasons"}
	is_array(r.reasons)
}
