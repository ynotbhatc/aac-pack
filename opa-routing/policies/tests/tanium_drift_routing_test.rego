# Tests for the Tanium-comparison drift routing policy (package aac.tanium.drift_routing).
# Run: opa test ansible/opa-routing/policies/ -v
package aac.tanium.drift_routing_test

import rego.v1

import data.aac.tanium.drift_routing as routing

# ── compliant must be PROVEN ──────────────────────────────────────────
test_no_drift_compliant_baseline_is_compliant if {
	r := routing.decision with input as {"facts": {"any_drift": false, "critical_drift": false, "baseline_compliant": true}}
	r.route == "compliant"
	r.invalid_input == false
}

test_string_booleans_compliant if {
	routing.route == "compliant" with input as {"facts": {"any_drift": "false", "critical_drift": "false", "baseline_compliant": "true"}}
}

# THE fail-open Copilot flagged: an absent any_drift is not "no drift".
test_absent_any_drift_is_not_compliant if {
	r := routing.decision with input as {"facts": {"baseline_compliant": true}}
	r.route == "approve_remediate"
	"facts incomplete or unproven — fail-closed to human approval" in r.reasons
}

test_no_drift_without_baseline_verdict_approves if {
	routing.route == "approve_remediate" with input as {"facts": {"any_drift": false}}
}

test_no_drift_noncompliant_baseline_approves if {
	routing.route == "approve_remediate" with input as {"facts": {"any_drift": false, "baseline_compliant": false}}
}

# ── auto must be EARNED ───────────────────────────────────────────────
test_routine_unticketed_drift_autos if {
	r := routing.decision with input as {"facts": {"any_drift": true, "critical_drift": false, "baseline_compliant": false, "change_ticket": ""}}
	r.route == "auto_remediate"
	"non-critical drift, no change ticket — auto-remediation permitted" in r.reasons
}

test_routine_drift_string_facts_autos if {
	routing.route == "auto_remediate" with input as {"facts": {"any_drift": "true", "critical_drift": "false", "baseline_compliant": "false"}}
}

# ── approve: critical class, ticket on record, contradictory baseline ─
test_critical_drift_approves if {
	r := routing.decision with input as {"facts": {"any_drift": true, "critical_drift": true, "baseline_compliant": false}}
	r.route == "approve_remediate"
	"critical drift class (selinux/sshd) — human approval required" in r.reasons
}

test_ticketed_drift_approves if {
	r := routing.decision with input as {"facts": {"any_drift": true, "critical_drift": false, "baseline_compliant": false, "change_ticket": "CHG-42"}}
	r.route == "approve_remediate"
	"authorized change ticket CHG-42 on record — never silently revert an authorized change; human decides" in r.reasons
}

test_drift_with_compliant_baseline_approves if {
	r := routing.decision with input as {"facts": {"any_drift": true, "critical_drift": false, "baseline_compliant": true}}
	r.route == "approve_remediate"
	"drift reported but the baseline verdict is compliant — contradictory facts, human decides" in r.reasons
}

# ── malformed booleans are never coerced to false ─────────────────────
# THE fail-open Copilot flagged: critical_drift="yes" must not become routine drift.
test_malformed_critical_approves if {
	r := routing.decision with input as {"facts": {"any_drift": true, "critical_drift": "yes", "baseline_compliant": false}}
	r.route == "approve_remediate"
	r.invalid_input == true
	"invalid/unrecognized input fact — fail-closed to human approval" in r.reasons
}

test_malformed_any_drift_approves if {
	routing.route == "approve_remediate" with input as {"facts": {"any_drift": 1, "baseline_compliant": true}}
}

test_malformed_baseline_approves if {
	routing.route == "approve_remediate" with input as {"facts": {"any_drift": false, "baseline_compliant": []}}
}

test_malformed_blocks_compliant if {
	routing.route == "approve_remediate" with input as {"facts": {"any_drift": "nope", "baseline_compliant": true}}
}

# ── empty / absent facts ──────────────────────────────────────────────
test_empty_input_approves if {
	r := routing.decision with input as {}
	r.route == "approve_remediate"
	r.invalid_input == false
	r.agent_recommended == "absent"
}

test_null_facts_approve if {
	routing.route == "approve_remediate" with input as {"facts": {"any_drift": null, "baseline_compliant": null}}
}

# ── override bookkeeping ──────────────────────────────────────────────
test_override_recorded_when_agent_said_compliant if {
	r := routing.decision with input as {"agent": {"recommended_route": "compliant"}, "facts": {"any_drift": true, "critical_drift": true}}
	r.route == "approve_remediate"
	r.agent_recommended == "compliant"
	r.overrode_agent == true
}

test_no_override_when_agent_agrees if {
	r := routing.decision with input as {"agent": {"recommended_route": "auto_remediate"}, "facts": {"any_drift": true, "critical_drift": false, "baseline_compliant": false}}
	r.route == "auto_remediate"
	r.overrode_agent == false
}

test_decision_shape if {
	r := routing.decision with input as {"facts": {"any_drift": false, "baseline_compliant": true}}
	object.keys(r) == {"route", "authority", "agent_recommended", "overrode_agent", "invalid_input", "reasons"}
	r.authority == "policy"
}
