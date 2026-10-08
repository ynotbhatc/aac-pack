# Tests for the Mythos composed routing decision (package aac.mythos.routing_v2).
# Run: opa test ansible/opa-routing/policies/ -v
#
# Inputs mirror what the AO final_gate node posts: four validated dimension
# assessments (from scoring.validate) plus the identify step's urgency facts.
# Everything the AO body templates in may arrive as a string.
package aac.mythos.routing_v2_test

import rego.v1

import data.aac.mythos.routing_v2 as routing

dim(band) := {"band": band, "valid": true, "impact": 10, "importance": 10, "low_confidence": false, "flags": []}

all_low := {"blast_radius": dim("low"), "patch_known_state": dim("low"), "environment": dim("moderate"), "tech_debt": dim("low")}

fixable := {"kev_present": false, "max_severity": "HIGH", "has_vendor_fix": true, "affected_count": 3}

# ── auto: routine, confidently measured, fixable, not urgent ─────────
test_routine_autos if {
	r := routing.decision with input as {"assessments": all_low, "urgency": fixable}
	r.route == "auto"
	r.critical_state == false
	"all dimensions low/moderate, no urgency signals — auto-eligible per policy" in r.reasons
	count(r.flags) == 0
}

test_string_booleans_auto if {
	routing.route == "auto" with input as {"assessments": object.union(all_low, {"tech_debt": object.union(dim("low"), {"valid": "True", "low_confidence": "False"})}), "urgency": {"kev_present": "false", "max_severity": "high", "has_vendor_fix": "true"}}
}

# ── critical risk state: never auto, approve when fixable ────────────
test_any_critical_dimension_approves if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"environment": dim("critical")}), "urgency": fixable}
	r.route == "approve"
	r.critical_state == true
	"CRITICAL RISK STATE: dimension 'environment' banded critical — auto is off the table" in r.reasons
}

test_critical_plus_kev_still_approves_not_parks if {
	routing.route == "approve" with input as {"assessments": object.union(all_low, {"blast_radius": dim("critical")}), "urgency": object.union(fixable, {"kev_present": true})}
}

test_critical_without_vendor_fix_investigates if {
	routing.route == "investigate" with input as {"assessments": object.union(all_low, {"blast_radius": dim("critical")}), "urgency": object.union(fixable, {"has_vendor_fix": false})}
}

# ── high band or high urgency: a human approves ──────────────────────
test_high_dimension_approves if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"patch_known_state": dim("high")}), "urgency": fixable}
	r.route == "approve"
	r.critical_state == false
	"dimension 'patch_known_state' banded high — human approval required" in r.reasons
}

test_kev_present_approves if {
	r := routing.decision with input as {"assessments": all_low, "urgency": object.union(fixable, {"kev_present": "true"})}
	r.route == "approve"
	"actively exploited (KEV) — urgency requires a human decision now" in r.reasons
}

test_critical_severity_approves if {
	r := routing.decision with input as {"assessments": all_low, "urgency": object.union(fixable, {"max_severity": "critical"})}
	r.route == "approve"
	"max severity CRITICAL — urgency requires a human decision now" in r.reasons
}

# ── low confidence: unmeasured is not safe ───────────────────────────
test_low_confidence_dimension_approves if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"tech_debt": object.union(dim("low"), {"low_confidence": true})}), "urgency": fixable}
	r.route == "approve"
	"dimension 'tech_debt' measured with low confidence — unmeasured is not safe, human review required" in r.reasons
}

test_low_confidence_string_approves if {
	routing.route == "approve" with input as {"assessments": object.union(all_low, {"tech_debt": object.union(dim("low"), {"low_confidence": "true"})}), "urgency": fixable}
}

# ── no vendor fix: investigate, whatever the bands ───────────────────
test_no_vendor_fix_investigates if {
	r := routing.decision with input as {"assessments": all_low, "urgency": object.union(fixable, {"has_vendor_fix": false})}
	r.route == "investigate"
	"no vendor fix exists — investigate/replace, not patch" in r.reasons
}

test_missing_urgency_investigates if {
	routing.route == "investigate" with input as {"assessments": all_low}
}

# ── broken composition: invalid / missing / unknown dimensions ───────
test_invalid_dimension_investigates if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"blast_radius": {"band": "invalid", "valid": false}}), "urgency": fixable}
	r.route == "investigate"
	"assessment for 'blast_radius' was structurally invalid — refusing to route on it" in r.reasons
}

test_invalid_string_false_investigates if {
	routing.route == "investigate" with input as {"assessments": object.union(all_low, {"blast_radius": object.union(dim("low"), {"valid": "false"})}), "urgency": fixable}
}

test_missing_dimension_investigates if {
	r := routing.decision with input as {"assessments": object.remove(all_low, ["tech_debt"]), "urgency": fixable}
	r.route == "investigate"
	r.bands.tech_debt == "missing"
}

test_empty_input_investigates if {
	r := routing.decision with input as {}
	r.route == "investigate"
	count(r.reasons) > 0
}

# THE case Copilot flagged: a band the matrix never produces must not pass as routine.
test_unknown_band_investigates if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"environment": object.union(dim("low"), {"band": "weird"})}), "urgency": fixable}
	r.route == "investigate"
	"assessment for 'environment' carries an unrecognized band 'weird' — refusing to route on it" in r.reasons
}

test_empty_band_investigates if {
	routing.route == "investigate" with input as {"assessments": object.union(all_low, {"environment": object.union(dim("low"), {"band": ""})}), "urgency": fixable}
}

# ── precedence: invalid beats everything, critical beats high/urgency ─
test_invalid_beats_no_vendor_fix if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"blast_radius": {"band": "invalid", "valid": false}}), "urgency": object.union(fixable, {"has_vendor_fix": false})}
	r.route == "investigate"
	not "no vendor fix exists — investigate/replace, not patch" in r.reasons
}

test_critical_and_high_reports_critical_not_high if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"blast_radius": dim("critical"), "environment": dim("high")}), "urgency": fixable}
	r.route == "approve"
	r.critical_state == true
	not "dimension 'environment' banded high — human approval required" in r.reasons
}

# ── carried flags: list and AO-stringified forms ─────────────────────
test_flags_list_carried if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"tech_debt": object.union(dim("low"), {"low_confidence": true, "flags": ["low confidence: 0.3"]})}), "urgency": fixable}
	"tech_debt: low confidence: 0.3" in r.flags
}

test_flags_string_carried if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"tech_debt": object.union(dim("low"), {"flags": "low confidence: 0.3; clamped"})}), "urgency": fixable}
	"tech_debt: low confidence: 0.3" in r.flags
	"tech_debt: clamped" in r.flags
}

test_flags_absent_or_blank_ok if {
	r := routing.decision with input as {"assessments": object.union(all_low, {"tech_debt": object.remove(dim("low"), ["flags"]), "environment": object.union(dim("low"), {"flags": ""})}), "urgency": fixable}
	count(r.flags) == 0
}

test_decision_shape if {
	r := routing.decision with input as {"assessments": all_low, "urgency": fixable}
	object.keys(r) == {"route", "critical_state", "bands", "dimension_summary", "reasons", "flags", "authority"}
	r.authority == "policy"
	r.dimension_summary.environment.band == "moderate"
}
