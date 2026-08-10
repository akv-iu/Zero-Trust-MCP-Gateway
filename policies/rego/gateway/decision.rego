# The entrypoint: `data.gateway.decision`.
#
# PRECEDENCE (POLICY-008) is expressed by guarding each level with `not` on the ones
# above it, so it is a property the compiler can see. Rego has no rule ordering -
# writing these in sequence and hoping would be a bug that only shows up when two
# levels match at once, which is exactly the case that matters.
#
#   1  prohibition            explicit refusal, nothing overrides it
#   2  explicit_deny          a rule considered the request and said no
#   3  allow_with_obligations
#   0  default                nothing matched
#
# The default is last in importance and first in safety: absence of an allow is a
# deny (POLICY-005), so a typo in any rule name below degrades to POLICY_DEFAULT_DENY
# rather than to permission.
package gateway

import rego.v1

default decision := {
	"decision": "deny",
	"reason_code": "POLICY_DEFAULT_DENY",
	"risk_tier": "R4",
	"obligations": {},
}

# The default's `risk_tier` cannot reference input - Rego requires a default value to
# be constant - so it is R4, the most severe tier v1 implements. That is the honest
# reading: nothing matched, so policy could not classify the request, and the audit
# record should not claim it was low risk. Every rule below echoes the registry's
# tier instead, so R4-on-a-default is distinguishable from a real R4 decision.
#
# AS WRITTEN TODAY THIS DEFAULT NEVER FIRES, and it stays anyway. `deny_code` is total
# over every non-discovery input - the three rules that produce it cover every
# combination of root ceiling and granted operation - and `allow` is total over
# discovery, so one of the guarded rules always matches. It is the floor for the
# version of this file where that stops being true: a future guard that leaves a gap
# lands here, on a deny, rather than on an undefined `decision`. (Undefined would also
# be safe - the broker reads a missing result as POLICY_DEFAULT_DENY - but "safe by
# two accidents" is not what POLICY-005 asks for.) POLICY_DEFAULT_DENY is reachable in
# the broker, which is where it is tested.

decision := d if {
	d := prohibition
}

decision := d if {
	not prohibition
	d := explicit_deny
}

decision := d if {
	not prohibition
	not explicit_deny
	d := allow
}

# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------

# `policy_revision` is NOT set here. The broker stamps it, from a hash it computes
# over this bundle on disk, and compares that to `data.gateway.policy_revision` at
# startup. A bundle echoing its own revision would agree with itself no matter which
# copy OPA had actually loaded.
response(verdict, code) := {
	"decision": verdict,
	"reason_code": code,
	"risk_tier": input.target.registry_risk_tier,
	"obligations": obligations,
}

# `tools/list` names no tool and therefore no resource; unit 05 hands it empty
# strings for path, root and classification (its R0 tool-less target). Every rule that
# reads `input.resource` guards on this, because a discovery request has nothing for
# them to read and a rule that silently matched `root == ""` would be answering a
# question nobody asked.
is_discovery if input.target.tool_name == null

# ---------------------------------------------------------------------------
# Level 2 - explicit deny
# ---------------------------------------------------------------------------

explicit_deny := response("deny", deny_code) if {
	not is_discovery
	not granted
}

granted if {
	some role in input.principal.roles
	input.arguments.operation in grants[role][input.resource.root]
}

# THE ROOT CEILING, and it is checked before the role. `[[canonicalize.roots]]` says
# what may EVER be done in an area; the grant table says who may do it. Both must
# permit. Unit 05 reports the flags and enforces none of them - this is where they
# are enforced, which is why a write to `production/` is refused for every principal
# including one whose grants were widened by mistake.
root_permits_operation if data.config.roots[input.resource.root][input.arguments.operation]

# Operations this principal may perform ANYWHERE. The difference between "you may not
# do that" and "you may not do that HERE" is the difference between the two codes
# below, and it is the one an operator reading the audit log actually needs.
permitted_operations contains op if {
	some role in input.principal.roles
	some _, ops in grants[role]
	some op in ops
}

deny_code := "POLICY_OPERATION_NOT_PERMITTED" if not root_permits_operation

deny_code := "POLICY_OPERATION_NOT_PERMITTED" if not input.arguments.operation in permitted_operations

deny_code := "POLICY_PATH_NOT_PERMITTED" if {
	root_permits_operation
	input.arguments.operation in permitted_operations
}

# ---------------------------------------------------------------------------
# Level 3 - allow
# ---------------------------------------------------------------------------

allow := response("allow", allow_code) if {
	not is_discovery
	granted
	root_permits_operation
}

# Discovery is allowed to any principal the registry recognises; WHICH tools come back
# is `discoverable.rego`'s answer, evaluated per tool by unit 04. Filtering the list
# and refusing the call are different questions and conflating them would either
# disclose a tool nobody may use or hide one they may.
allow := response("allow", "POLICY_METADATA_READ") if is_discovery

# The allow code follows the registry's risk tier rather than the tool name: R0 tools
# return metadata about a resource, R1+ return its contents, and a write is a write.
# Deriving it from the tier keeps the vocabulary closed and means a new R0 tool needs
# no policy edit to be described correctly.
allow_code := "POLICY_METADATA_READ" if input.target.registry_risk_tier == "R0"

allow_code := "POLICY_SCOPED_READ" if {
	input.target.registry_risk_tier != "R0"
	input.arguments.operation == "read"
}

allow_code := "POLICY_SCOPED_WRITE" if {
	input.target.registry_risk_tier != "R0"
	input.arguments.operation != "read"
}

# ---------------------------------------------------------------------------
# Obligations
# ---------------------------------------------------------------------------
#
# Policy NARROWS; the gateway's ceiling is in `[router]` and the broker clamps to it
# (POLICY-007). Nothing here is above that ceiling, deliberately: a shipped policy that
# relies on being clamped is a policy whose author did not know the limit.

obligations := {
	"timeout_ms": timeout_ms,
	"max_response_bytes": 1048576,
}

default timeout_ms := 3000

timeout_ms := 5000 if input.target.registry_risk_tier == "R2"
