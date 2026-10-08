# Tests for the golden-image drift routing policy (package aac.golden.routing).
# Run: opa test ansible/opa-routing/policies/ -v
#
# Overrides target the config LEAF (data.aac.golden.config) -- overriding the
# parent data.aac.golden would reintroduce the package self-recursion the policy
# is written to avoid.
package aac.golden.routing_test

import rego.v1

import data.aac.golden.routing

# ── hold: global pause wins over everything ──────────────────────────
test_global_pause_holds if {
	routing.route == "hold" with input as {"facts": {"any_drift": true, "critical_drift": true, "drifted_key": "selinux_config"}}
		with data.aac.golden.config as {"rollback_paused": true, "authorized_change_hosts": []}
}

# pause precedence: even critical drift is held, not sent to approve
test_pause_precedence_over_critical if {
	r := routing.decision with input as {"facts": {"any_drift": true, "critical_drift": true}}
		with data.aac.golden.config as {"rollback_paused": true, "authorized_change_hosts": []}
	r.route == "hold"
}

# ── hold: per-host authorized change ─────────────────────────────────
test_authorized_host_holds if {
	routing.route == "hold" with input as {"facts": {"any_drift": true, "target_host": "demo-rhel9"}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": ["demo-rhel9"]}
}

test_unauthorized_host_not_held if {
	routing.route != "hold" with input as {"facts": {"any_drift": true, "critical_drift": true, "target_host": "other-host"}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": ["demo-rhel9"]}
}

# ── approve: critical / security-relevant drift (no pause) ────────────
test_critical_drift_approves if {
	routing.route == "approve" with input as {"facts": {"any_drift": true, "critical_drift": true, "baseline_compliant": true}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

test_security_key_approves if {
	routing.route == "approve" with input as {"facts": {"any_drift": true, "drifted_key": "sshd_config", "baseline_compliant": true}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

# ── auto: routine drift with a known-good baseline ───────────────────
test_routine_drift_with_baseline_autos if {
	routing.route == "auto" with input as {"facts": {"any_drift": true, "drifted_key": "motd", "baseline_compliant": true}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

test_no_drift_autos if {
	routing.route == "auto" with input as {"facts": {"any_drift": false}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

# ── investigate: fail closed on absent / non-compliant baseline ──────
# THE fix: a missing baseline_compliant fact must NOT auto-roll-back.
test_absent_baseline_investigates if {
	routing.route == "investigate" with input as {"facts": {"any_drift": true, "drifted_key": "motd"}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

test_noncompliant_baseline_investigates if {
	routing.route == "investigate" with input as {"facts": {"any_drift": true, "drifted_key": "motd", "baseline_compliant": false}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

# ── invalid input never auto-rolls-back: route to a human ────────────
# A malformed boolean fact must NOT be coerced to false and downgraded to
# routine drift (which would auto-enforce). It routes to investigate.
test_malformed_fact_investigates if {
	r := routing.decision with input as {"facts": {"any_drift": "yes", "critical_drift": 1}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
	is_string(r.route)
	r.route == "investigate"
}

# THE critical fail-open case Copilot flagged: a malformed critical_drift must
# not be cleared to false and routed to auto.
test_malformed_critical_investigates if {
	routing.route == "investigate" with input as {"facts": {"any_drift": true, "critical_drift": "yes", "baseline_compliant": true}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

# ── approve precedence holds even with absent / non-compliant baseline ─
test_critical_absent_baseline_approves if {
	routing.route == "approve" with input as {"facts": {"any_drift": true, "critical_drift": true}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

test_security_key_absent_baseline_approves if {
	routing.route == "approve" with input as {"facts": {"any_drift": true, "drifted_key": "sshd_config"}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

test_critical_noncompliant_baseline_approves if {
	routing.route == "approve" with input as {"facts": {"any_drift": true, "critical_drift": true, "baseline_compliant": false}}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}

# ── default route with no facts at all ───────────────────────────────
test_empty_input_autos if {
	routing.route == "auto" with input as {}
		with data.aac.golden.config as {"rollback_paused": false, "authorized_change_hosts": []}
}
