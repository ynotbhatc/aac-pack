# AAC — Mythos-on-AO remediation routing policy
#
# The governance boundary for the AO Mythos demo. The AI triage agent
# REASONS and produces a recommendation; this policy DECIDES the route the
# workflow switch acts on. The agent proposes, policy disposes — enforced by
# OPA, not by the model's own output.
#
# Entrypoint: data.aac.mythos.routing.decision
#   POST /v1/data/aac/mythos/routing/decision  with body {"input": {...}}
#
# Input contract (from the AO workflow: identify set_stats + triage_agent):
#   {
#     "agent":  { "recommended_route": "auto_patch|approve_patch|investigate",
#                 "rationale": "<free text, informational only>" },
#     "facts":  { "affected_count": <int blast radius>,
#                 "affected_cves":  <int>,
#                 "max_severity":   "CRITICAL|HIGH|MEDIUM|LOW",
#                 "kev_present":    <bool, actively exploited>,
#                 "has_vendor_fix": <bool>,
#                 "eol_exposed":    <bool> }
#   }
#
# Output (decision): { route, authority, agent_recommended, overrode_agent, reasons }
#   route ∈ {auto, approve, investigate}
#
# The thresholds below are OWNED BY THE OPERATOR, not the model. This policy is
# AAC-demo-specific and lives here, never in the vendor-neutral rego library.

package aac.mythos.routing

import rego.v1

# ── Operator-owned thresholds ─────────────────────────────────────────
# A change touching more than this many host/component pairs is high-
# consequence and needs a human, even if everything else looks routine.
blast_radius_threshold := 100

# ── Input normalization ───────────────────────────────────────────────
# The AO http_request node templates the identify facts in, and depending on
# how set_stats typed them they can arrive as native JSON or as strings
# ("1321", "true"). Normalize here so the decision is correct either way.

affected_count := input.facts.affected_count if is_number(input.facts.affected_count)
affected_count := to_number(input.facts.affected_count) if is_string(input.facts.affected_count)

default affected_count := 0

has_vendor_fix if input.facts.has_vendor_fix == true
has_vendor_fix if input.facts.has_vendor_fix == "true"

kev_present if input.facts.kev_present == true
kev_present if input.facts.kev_present == "true"

# ── Route decision ────────────────────────────────────────────────────
# Default is auto-remediation; the conditions below escalate away from it.
# investigate (no fix) and approve (fix + high-consequence) are mutually
# exclusive — investigate requires no vendor fix, approve requires one — so
# there is no rule conflict.

default route := "auto"

# No vendor fix exists → this is a replacement problem, not a patch. Routed to
# investigate (risk simulation / heat map) regardless of what the agent said.
route := "investigate" if not has_vendor_fix

# A fix exists but the change is high-consequence → hold for a human.
route := "approve" if {
	has_vendor_fix
	requires_human
}

requires_human if input.facts.max_severity == "CRITICAL"

requires_human if kev_present

requires_human if affected_count > blast_radius_threshold

# ── Compare against the agent's recommendation (for the override story) ──
# Normalize the agent's vocabulary (auto_patch/approve_patch/investigate) to the
# policy's (auto/approve/investigate) so we can tell when policy overrode it.
agent_route := "auto" if input.agent.recommended_route == "auto_patch"

agent_route := "approve" if input.agent.recommended_route == "approve_patch"

agent_route := "investigate" if input.agent.recommended_route == "investigate"

agent_route := input.agent.recommended_route if {
	not input.agent.recommended_route in {"auto_patch", "approve_patch", "investigate"}
}

overrode_agent := route != agent_route

# ── Human-readable reasons (evidence + presenter narration) ───────────
reasons contains "no vendor fix available — routing to investigate (replacement, not patch)" if {
	not has_vendor_fix
}

reasons contains sprintf("max_severity is %v — human approval required", [input.facts.max_severity]) if {
	has_vendor_fix
	input.facts.max_severity == "CRITICAL"
}

reasons contains "actively exploited (KEV) — human approval required" if {
	has_vendor_fix
	kev_present
}

reasons contains sprintf("blast radius %v exceeds threshold %v — human approval required", [affected_count, blast_radius_threshold]) if {
	has_vendor_fix
	affected_count > blast_radius_threshold
}

reasons contains "low-consequence change (vendor fix, not actively exploited, within blast-radius threshold) — auto-remediation permitted" if {
	route == "auto"
}

# ── The decision object the workflow switch reads ─────────────────────
decision := {
	"route": route,
	"authority": "policy",
	"agent_recommended": input.agent.recommended_route,
	"overrode_agent": overrode_agent,
	"reasons": reasons,
}
