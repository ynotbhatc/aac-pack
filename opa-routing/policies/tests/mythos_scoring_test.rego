# Tests for the Mythos per-agent score validation gate (package aac.mythos.scoring).
# Run: opa test ansible/opa-routing/policies/ -v
package aac.mythos.scoring_test

import rego.v1

import data.aac.mythos.scoring

ok(impact, importance) := {"agent": "blast_radius", "assessment": {"impact": impact, "importance": importance, "confidence": 0.9, "reasons": ["measured"]}}

# ── happy path and the matrix ─────────────────────────────────────────
test_valid_assessment_shape if {
	v := scoring.validate with input as ok(10, 10)
	v.valid == true
	v.agent == "blast_radius"
	v.band == "low"
	v.low_confidence == false
	count(v.flags) == 0
	v.reasons == ["measured"]
}

test_matrix_critical_both_axes if {
	scoring.band == "critical" with input as ok(90, 90)
}

test_matrix_critical_impact_low_importance_damped_to_high if {
	scoring.band == "high" with input as ok(90, 10)
}

test_matrix_high_impact_low_importance_damped_to_moderate if {
	scoring.band == "moderate" with input as ok(60, 10)
}

test_matrix_low_impact_critical_importance_is_moderate if {
	scoring.band == "moderate" with input as ok(10, 90)
}

test_matrix_moderate_moderate if {
	scoring.band == "moderate" with input as ok(30, 30)
}

# ── axis boundaries (0-24 low, 25-49 moderate, 50-74 high, 75-100 critical)
# Exercised through the public band: equal scores on both axes land on the
# matrix diagonal, so the band names the level directly.
test_boundary_24_is_low if {
	scoring.band == "low" with input as ok(24, 24)
}

test_boundary_25_is_moderate if {
	scoring.band == "moderate" with input as ok(25, 25)
}

test_boundary_49_is_moderate if {
	scoring.band == "moderate" with input as ok(49, 49)
}

test_boundary_50_is_high if {
	scoring.band == "high" with input as ok(50, 50)
}

test_boundary_74_is_high if {
	scoring.band == "high" with input as ok(74, 74)
}

test_boundary_75_is_critical if {
	scoring.band == "critical" with input as ok(75, 75)
}

test_boundary_0_and_100 if {
	scoring.band == "low" with input as ok(0, 0)
	scoring.band == "critical" with input as ok(100, 100)
}

# ── out-of-range and malformed scores are INVALID, never a band ──────
test_impact_over_100_invalid if {
	v := scoring.validate with input as ok(101, 50)
	v.valid == false
	v.band == "invalid"
	"assessment structurally invalid — do not compose" in v.flags
}

test_negative_importance_invalid if {
	scoring.valid == false with input as ok(50, -1)
}

test_non_numeric_string_impact_invalid if {
	v := scoring.validate with input as ok("high", 50)
	v.valid == false
	v.impact == -1
}

test_missing_scores_invalid if {
	scoring.valid == false with input as {"agent": "tech_debt", "assessment": {"confidence": 0.9, "reasons": ["x"]}}
}

test_empty_input_invalid if {
	v := scoring.validate with input as {}
	v.valid == false
	v.band == "invalid"
	v.agent == "unknown"
}

# ── string normalization (AO scalar templating) ──────────────────────
test_string_scores_normalized if {
	v := scoring.validate with input as {"agent": "environment", "assessment": {"impact": "80", "importance": "80", "confidence": "0.95", "reasons": "prod cluster; change freeze"}}
	v.valid == true
	v.band == "critical"
	v.impact == 80
	v.reasons == ["prod cluster", " change freeze"]
}

test_reasons_list_blanks_stripped if {
	v := scoring.validate with input as {"agent": "a", "assessment": {"impact": 1, "importance": 1, "confidence": 1, "reasons": ["", "  ", "real"]}}
	v.valid == true
	v.reasons == ["real"]
}

test_reasons_all_blank_invalid if {
	scoring.valid == false with input as {"agent": "a", "assessment": {"impact": 1, "importance": 1, "confidence": 1, "reasons": [" ", ""]}}
}

test_reasons_blank_string_invalid if {
	scoring.valid == false with input as {"agent": "a", "assessment": {"impact": 1, "importance": 1, "confidence": 1, "reasons": " ; "}}
}

test_missing_reasons_invalid if {
	scoring.valid == false with input as {"agent": "a", "assessment": {"impact": 1, "importance": 1, "confidence": 1}}
}

# ── agent name ────────────────────────────────────────────────────────
test_blank_agent_invalid if {
	scoring.valid == false with input as {"agent": "  ", "assessment": {"impact": 1, "importance": 1, "confidence": 1, "reasons": ["x"]}}
}

test_non_string_agent_invalid if {
	scoring.valid == false with input as {"agent": 7, "assessment": {"impact": 1, "importance": 1, "confidence": 1, "reasons": ["x"]}}
}

# ── confidence ────────────────────────────────────────────────────────
test_low_confidence_flagged_but_valid if {
	v := scoring.validate with input as {"agent": "a", "assessment": {"impact": 10, "importance": 10, "confidence": 0.2, "reasons": ["x"]}}
	v.valid == true
	v.low_confidence == true
	"low confidence: 0.2" in v.flags
}

test_confidence_at_threshold_not_low if {
	scoring.low_confidence == false with input as {"agent": "a", "assessment": {"impact": 10, "importance": 10, "confidence": 0.5, "reasons": ["x"]}}
}

test_missing_confidence_is_low if {
	v := scoring.validate with input as {"agent": "a", "assessment": {"impact": 10, "importance": 10, "reasons": ["x"]}}
	v.valid == true
	v.low_confidence == true
}

# THE case Copilot flagged: confidence outside 0-1 must not look auto-eligible.
test_confidence_above_one_invalid if {
	v := scoring.validate with input as {"agent": "a", "assessment": {"impact": 10, "importance": 10, "confidence": 5, "reasons": ["x"]}}
	v.valid == false
	v.band == "invalid"
	"confidence 5 outside 0.0-1.0" in v.flags
}

test_negative_confidence_invalid if {
	scoring.valid == false with input as {"agent": "a", "assessment": {"impact": 10, "importance": 10, "confidence": -0.1, "reasons": ["x"]}}
}

test_confidence_string_percent_invalid if {
	# "90%" is not a number: to_number fails, confidence defaults to 0 -> low confidence, still valid
	v := scoring.validate with input as {"agent": "a", "assessment": {"impact": 10, "importance": 10, "confidence": "90%", "reasons": ["x"]}}
	v.valid == true
	v.low_confidence == true
}
