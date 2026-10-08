# AAC — Mythos multi-agent triage: per-agent score validation gate
#
# Each triage dimension agent (blast_radius, patch_known_state, environment,
# tech_debt) POSTs its assessment here BEFORE the scores are composed. Agents
# report TWO raw scores and never classify themselves:
#
#   impact      0-100  how severe the consequences in this dimension are
#   importance  0-100  how much weight this dimension deserves in this decision
#
# The BAND is computed HERE, from an operator-owned risk matrix — the model
# measures, the policy classifies. A malformed assessment is refused (valid:
# false); the workflow must not compose garbage.
#
# Entrypoint: data.aac.mythos.scoring.validate
#   POST /v1/data/aac/mythos/scoring/validate
#   input: { "agent": "<dimension name>",
#            "assessment": { "impact": 0-100, "importance": 0-100,
#                            "reasons": "..;..", "confidence": 0.0-1.0 } }
#   A missing confidence is 0 (unmeasured → low confidence); a confidence
#   outside 0.0-1.0 is a malformed measurement and fails validation.
#
# Output (validate): { valid, agent, impact, importance, band, flags, reasons }
#
# Axis levels (operator-owned): 0-24 low, 25-49 moderate, 50-74 high,
# 75-100 critical — applied to each axis, then combined by the matrix.

package aac.mythos.scoring

import rego.v1

# ── Normalization (agents' JSON may arrive string-typed via AO templating) ──
impact := input.assessment.impact if is_number(input.assessment.impact)
impact := to_number(input.assessment.impact) if is_string(input.assessment.impact)

default impact := -1

importance := input.assessment.importance if is_number(input.assessment.importance)
importance := to_number(input.assessment.importance) if is_string(input.assessment.importance)

default importance := -1

confidence := input.assessment.confidence if is_number(input.assessment.confidence)
confidence := to_number(input.assessment.confidence) if is_string(input.assessment.confidence)

default confidence := 0

# reasons may arrive as a list or (via AO scalar templating) one "; "-joined
# string — both accepted, blanks stripped.
reasons_given := [r | some r in input.assessment.reasons; is_string(r); trim_space(r) != ""] if not is_string(input.assessment.reasons)

reasons_given := [r | some r in split(input.assessment.reasons, ";"); trim_space(r) != ""] if is_string(input.assessment.reasons)

default reasons_given := []

# ── Structural validity — fail closed, never compose garbage ─────────────────
valid if {
	is_string(input.agent)
	trim_space(input.agent) != ""
	impact >= 0
	impact <= 100
	importance >= 0
	importance <= 100
	confidence >= 0
	confidence <= 1
	count(reasons_given) > 0
}

default valid := false

# ── Axis levels ───────────────────────────────────────────────────────────────
level(s) := "low" if {
	s >= 0
	s <= 24
}

level(s) := "moderate" if {
	s >= 25
	s <= 49
}

level(s) := "high" if {
	s >= 50
	s <= 74
}

level(s) := "critical" if {
	s >= 75
	s <= 100
}

# ── The risk matrix (operator-owned): band = matrix[impact][importance] ──────
# High-impact findings that matter little are damped one step; anything
# critical on BOTH axes, or critical impact with real importance, is critical.
matrix := {
	"low": {"low": "low", "moderate": "low", "high": "moderate", "critical": "moderate"},
	"moderate": {"low": "low", "moderate": "moderate", "high": "moderate", "critical": "high"},
	"high": {"low": "moderate", "moderate": "high", "high": "high", "critical": "critical"},
	"critical": {"low": "high", "moderate": "critical", "high": "critical", "critical": "critical"},
}

band := matrix[level(impact)][level(importance)] if valid

default band := "invalid"

# ── Flags ─────────────────────────────────────────────────────────────────────
# Below this confidence the measurement is treated as unreliable: the routing
# policy refuses to count it toward an 'auto' route (unmeasured is not safe).
low_confidence_threshold := 0.5

low_confidence if {
	valid
	confidence < low_confidence_threshold
}

default low_confidence := false

flags contains sprintf("low confidence: %v", [confidence]) if low_confidence

flags contains "assessment structurally invalid — do not compose" if not valid

flags contains sprintf("confidence %v outside 0.0-1.0", [confidence]) if {
	not valid
	is_number(confidence)
	not confidence_in_range
}

confidence_in_range if {
	confidence >= 0
	confidence <= 1
}

validate := {
	"valid": valid,
	"agent": object.get(input, "agent", "unknown"),
	"impact": impact,
	"importance": importance,
	"band": band,
	"low_confidence": low_confidence,
	"flags": flags,
	"reasons": reasons_given,
}
