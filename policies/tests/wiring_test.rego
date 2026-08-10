# The consistency rules the gateway queries at startup, and `discoverable`.
#
# These are the checks that turn a silent misconfiguration into a refusal to serve.
# Each one has a positive case as well as a negative: a rule that always reports a
# problem would fail startup forever, which is fail-closed and useless.
package gateway_test

import data.gateway
import rego.v1

# `roots` and `config` come from `decision_test.rego` — same package, one table. This
# file carried its own copy until the classification-based prohibition needed a field
# the copy did not have, which is the ordinary way a duplicated fixture fails: not by
# disagreeing, but by being incomplete in a direction nobody looked.
# `test_policy.py` compares that one table against `config/gateway.toml`.
cfg := config

vocabulary := config.role_vocabulary

known_roots := roots

# ---------------------------------------------------------------------------
# grants <-> config agreement
# ---------------------------------------------------------------------------

extra_role := {"role_vocabulary": ["intern", "developer", "auditor", "reviewer"], "roots": known_roots}

one_role := {"role_vocabulary": ["intern"], "roots": known_roots}

one_root := {"role_vocabulary": ["intern", "developer", "auditor"], "roots": {"public": known_roots.public}}

test_shipped_grants_cover_every_role if {
	offenders := gateway.roles_without_grants with data.config as cfg
	count(offenders) == 0
}

test_a_role_with_no_grants_is_reported if {
	# The failure this exists for: adding a role to `identity.role_vocabulary` and
	# forgetting this bundle. Every request for that principal would be
	# POLICY_DEFAULT_DENY, which reads exactly like a policy decision.
	offenders := gateway.roles_without_grants with data.config as extra_role
	offenders == {"reviewer"}
}

test_no_shipped_grant_names_an_unknown_role if {
	offenders := gateway.grants_without_roles with data.config as cfg
	count(offenders) == 0
}

test_a_grant_for_a_removed_role_is_reported if {
	offenders := gateway.grants_without_roles with data.config as one_role
	offenders == {"developer", "auditor"}
}

test_no_shipped_grant_names_an_unknown_root if {
	offenders := gateway.grants_naming_unknown_roots with data.config as cfg
	count(offenders) == 0
}

test_a_grant_for_a_removed_root_is_reported if {
	offenders := gateway.grants_naming_unknown_roots with data.config as one_root
	count(offenders) > 0
}

test_no_shipped_grant_names_a_prohibited_root if {
	offenders := gateway.grants_on_prohibited_roots with data.config as cfg
	count(offenders) == 0
}

test_a_grant_on_a_prohibited_root_is_reported if {
	# A grant that can never fire, because a prohibition outranks it. It changes no
	# decision, which is exactly why nothing else notices — and why the one file a
	# reviewer reads as the authorization matrix must not contain one.
	offenders := gateway.grants_on_prohibited_roots with data.config as cfg
		with gateway.grants as {"intern": {"traps": {"read"}}}
	offenders == {["intern", "traps"]}
}

test_a_grant_on_a_root_prohibited_by_classification_is_reported if {
	# The other half. A prohibition can name a root OR a classification, and the first
	# version of this rule knew only about names — so a grant on `decoys`, prohibited
	# because it is classified `secret`, sailed through. Second run of the break pass.
	offenders := gateway.grants_on_prohibited_roots with data.config as cfg
		with gateway.grants as {"auditor": {"decoys": {"read"}}}
	offenders == {["auditor", "decoys"]}
}

# ---------------------------------------------------------------------------
# The allow rule in isolation (defence in depth behind the precedence guard)
# ---------------------------------------------------------------------------
#
# `decision` only reaches `allow` when `explicit_deny` is undefined, and
# `explicit_deny` fires on exactly `not granted` — so the `granted` condition inside
# `allow` is redundant through that path. The break pass proved it: deleting it
# changed no decision. It stays as the backstop for the day the precedence guard
# moves, and these two tests are what make it load-bearing rather than decorative.

allow_input(role, root, operation) := {
	"target": {"tool_name": "t", "registry_risk_tier": "R1"},
	"principal": {"roles": [role]},
	"resource": {"root": root, "classification": "public"},
	"arguments": {"operation": operation},
}

test_allow_fires_for_a_granted_request if {
	gateway.allow with input as allow_input("intern", "public", "read") with data.config as cfg
}

test_allow_is_undefined_without_a_grant if {
	not gateway.allow with input as allow_input("intern", "confidential", "read")
		with data.config as cfg
}

test_allow_is_undefined_when_the_root_ceiling_refuses if {
	not gateway.allow with input as allow_input("developer", "production", "overwrite")
		with data.config as cfg
}

# ---------------------------------------------------------------------------
# discoverable (REG-010)
# ---------------------------------------------------------------------------

ask(role, operation) := {
	"principal": {"roles": [role]},
	"arguments": {"operation": operation},
}

test_intern_can_discover_a_read_tool if {
	gateway.discoverable with input as ask("intern", "read") with data.config as cfg
}

test_intern_cannot_discover_a_write_tool if {
	not gateway.discoverable with input as ask("intern", "overwrite") with data.config as cfg
}

test_intern_cannot_discover_a_delete_tool if {
	not gateway.discoverable with input as ask("intern", "delete") with data.config as cfg
}

test_developer_can_discover_a_write_tool if {
	gateway.discoverable with input as ask("developer", "overwrite") with data.config as cfg
}

test_auditor_cannot_discover_a_write_tool if {
	not gateway.discoverable with input as ask("auditor", "overwrite") with data.config as cfg
}

test_discoverable_defaults_to_false_for_an_unknown_role if {
	not gateway.discoverable with input as ask("stranger", "read") with data.config as cfg
}

test_discoverable_ignores_a_prohibited_root if {
	# A grant on a prohibited root must not make a tool discoverable — otherwise
	# `tools/list` advertises a capability every call of which would be refused.
	not gateway.discoverable with input as ask("x", "read")
		with data.config as cfg
		with gateway.grants as {"x": {"traps": {"read"}}}
}

test_discoverable_respects_the_root_ceiling if {
	# The grant says delete, the root says no. Discovery must follow the ceiling, or
	# the list and the decision disagree — which is precisely what REG-011 forbids.
	not gateway.discoverable with input as ask("x", "delete")
		with data.config as cfg
		with gateway.grants as {"x": {"public": {"delete"}}}
}
