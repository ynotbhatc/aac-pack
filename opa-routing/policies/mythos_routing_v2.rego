# AAC — Mythos multi-agent triage: composed routing decision (v2)
#
# Four validated dimension assessments (from data.aac.mythos.scoring.validate)
# plus the measured urgency facts compose into ONE route. Design rules
# (operator-owned, decided 2026-09-27):
#
#   1. ANY dimension banding critical puts the whole pass into the CRITICAL
#      RISK STATE: the route can never be 'auto', regardless of other bands.
#   2. Urgency (the cost of NOT patching: KEV, severity) argues FOR acting —
#      it can raise auto→approve, and it stops a critical action-risk from
#      quietly becoming "wait forever": critical state + high urgency routes
#      to approve (a human weighs it NOW), not investigate.
#   3. No vendor fix → investigate (unchanged from v1: not a patching problem).
#   4. Structurally invalid assessments fail the composition — deny by
#      routing to investigate with the reason recorded.
#
# Entrypoint: data.aac.mythos.routing_v2.decision
#   input: {
#     "assessments": { "blast_radius":     <scoring.validate output>,
#                      "patch_known_state": <...>,
#                      "environment":       <...>,
#                      "tech_debt":         <...> },
#     "urgency": { "kev_present": bool, "max_severity": "CRITICAL|HIGH|...",
#                  "has_vendor_fix": bool, "affected_count": int }
#   }
#
# Output (decision): { route, critical_state, bands, reasons, flags,
#                      authority: "policy", dimension_summary }
#   route ∈ {auto, approve, investigate}

package aac.mythos.routing_v2

import rego.v1

dimensions := ["blast_radius", "patch_known_state", "environment", "tech_debt"]

# ── Normalization ─────────────────────────────────────────────────────────────
kev_present if input.urgency.kev_present == true
kev_present if input.urgency.kev_present == "true"

has_vendor_fix if input.urgency.has_vendor_fix == true
has_vendor_fix if input.urgency.has_vendor_fix == "true"

max_severity := upper(input.urgency.max_severity) if is_string(input.urgency.max_severity)

default max_severity := "UNKNOWN"

known_bands := {"low", "moderate", "high", "critical"}

band(dim) := b if b := input.assessments[dim].band
band(dim) := "missing" if not input.assessments[dim].band

# A band the matrix never produces ("", "invalid", "weird") cannot be composed.
band_known(dim) if band(dim) in known_bands

# `valid` may arrive as a native bool or a templated string ("true"/"True").
dim_valid(dim) if input.assessments[dim].valid == true
dim_valid(dim) if lower(sprintf("%v", [input.assessments[dim].valid])) == "true"

dim_low_conf(dim) if input.assessments[dim].low_confidence == true
dim_low_conf(dim) if lower(sprintf("%v", [input.assessments[dim].low_confidence])) == "true"

low_conf_dims contains dim if {
	some dim in dimensions
	dim_low_conf(dim)
}

# ── Composition state ─────────────────────────────────────────────────────────
invalid_dims contains dim if {
	some dim in dimensions
	not dim_valid(dim)
}

invalid_dims contains dim if {
	some dim in dimensions
	not band_known(dim)
}

critical_dims contains dim if {
	some dim in dimensions
	band(dim) == "critical"
}

high_dims contains dim if {
	some dim in dimensions
	band(dim) == "high"
}

critical_state if count(critical_dims) > 0

default critical_state := false

high_urgency if kev_present
high_urgency if max_severity == "CRITICAL"

# ── Route (first match wins by specificity; rego.v1 complete rules) ──────────
# Fail closed: anything the rules below don't positively classify lands here.
default route := "investigate"

# Broken composition: never route on garbage.
route := "investigate" if count(invalid_dims) > 0

# No fix exists: replacement problem, not a patch problem.
route := "investigate" if {
	count(invalid_dims) == 0
	not has_vendor_fix
}

# Critical risk state: a human weighs it — urgent criticals must not park.
route := "approve" if {
	count(invalid_dims) == 0
	has_vendor_fix
	critical_state
}

# High action-risk or high urgency: human approval.
route := "approve" if {
	count(invalid_dims) == 0
	has_vendor_fix
	not critical_state
	count(high_dims) > 0
}

route := "approve" if {
	count(invalid_dims) == 0
	has_vendor_fix
	not critical_state
	high_urgency
}

# A dimension measured with unreliable confidence cannot support auto:
# unmeasured is not safe. It routes to a human instead.
route := "approve" if {
	count(invalid_dims) == 0
	has_vendor_fix
	not critical_state
	count(high_dims) == 0
	not high_urgency
	count(low_conf_dims) > 0
}

# Routine: every dimension low/moderate, confidently measured, nothing urgent.
route := "auto" if {
	count(invalid_dims) == 0
	has_vendor_fix
	not critical_state
	count(high_dims) == 0
	not high_urgency
	count(low_conf_dims) == 0
}

# ── Reasons — every route explains itself (the log's contract) ───────────────
reasons contains sprintf("assessment for '%s' was structurally invalid — refusing to route on it", [dim]) if {
	some dim in invalid_dims
	not dim_valid(dim)
}

reasons contains sprintf("assessment for '%s' carries an unrecognized band '%v' — refusing to route on it", [dim, band(dim)]) if {
	some dim in invalid_dims
	dim_valid(dim)
	not band_known(dim)
}

reasons contains "no vendor fix exists — investigate/replace, not patch" if {
	count(invalid_dims) == 0
	not has_vendor_fix
}

reasons contains sprintf("CRITICAL RISK STATE: dimension '%s' banded critical — auto is off the table", [dim]) if some dim in critical_dims

reasons contains sprintf("dimension '%s' banded high — human approval required", [dim]) if {
	not critical_state
	some dim in high_dims
}

reasons contains "actively exploited (KEV) — urgency requires a human decision now" if {
	has_vendor_fix
	kev_present
}

reasons contains "max severity CRITICAL — urgency requires a human decision now" if {
	has_vendor_fix
	max_severity == "CRITICAL"
	not kev_present
}

reasons contains "all dimensions low/moderate, no urgency signals — auto-eligible per policy" if route == "auto"

reasons contains sprintf("dimension '%s' measured with low confidence — unmeasured is not safe, human review required", [dim]) if {
	not critical_state
	count(high_dims) == 0
	some dim in low_conf_dims
}

# ── Carried flags from the validation gates (clamps, low confidence) ─────────
# The gate returns flags as a list; the AO http_request body templates them in
# as a scalar, which may arrive as a native list or as one "; "-joined string.
dim_flags(dim) := f if {
	f := input.assessments[dim].flags
	is_array(f)
}

dim_flags(dim) := [t |
	some s in split(input.assessments[dim].flags, ";")
	t := trim(trim_space(s), "[]'\"")
	t != ""
] if {
	is_string(input.assessments[dim].flags)
}

dim_flags(dim) := [] if not input.assessments[dim].flags

dim_flags(dim) := [] if {
	f := input.assessments[dim].flags
	not is_array(f)
	not is_string(f)
}

flags contains sprintf("%s: %v", [dim, f]) if {
	some dim in dimensions
	some f in dim_flags(dim)
}

dimension_summary := {dim: {
	"band": band(dim),
	"impact": object.get(input.assessments[dim], "impact", -1),
	"importance": object.get(input.assessments[dim], "importance", -1),
} |
	some dim in dimensions
}

decision := {
	"route": route,
	"critical_state": critical_state,
	"bands": {dim: band(dim) | some dim in dimensions},
	"dimension_summary": dimension_summary,
	"reasons": reasons,
	"flags": flags,
	"authority": "policy",
}
