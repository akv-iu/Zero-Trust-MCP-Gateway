# POLICY-016. Run standalone: `opa test policies/ -v` needs no Python, no fixture,
# no OPA server, and no gateway. That independence is the point — the policy is a
# deliverable in its own right and a reviewer must be able to check it without
# building anything.
#
# Every assertion checks the REASON CODE, not just the decision (HARN-003). A rule
# that denies for the wrong reason is a defect, and a decision-only test hides it.
#
# `data.config` is supplied on every expression with `with`, because the gateway
# publishes it at startup from `config/gateway.toml` and these tests deliberately do
# not run the gateway. It cannot be hoisted into a helper — Rego forbids `with` in a
# rule head and inside a call argument — so it is repeated, which at least means each
# test states the data it assumed. `test_policy.py` asserts this shape matches the
# shipped file.
package gateway_test

import data.gateway
import rego.v1

roots := {
	"public": {"classification": "public", "read": true, "create": false, "overwrite": false, "append": false, "rename": false, "delete": false},
	"workspace": {"classification": "internal", "read": true, "create": true, "overwrite": true, "append": true, "rename": false, "delete": true},
	"confidential": {"classification": "confidential", "read": true, "create": false, "overwrite": false, "append": false, "rename": false, "delete": false},
	"production": {"classification": "production", "read": true, "create": false, "overwrite": false, "append": false, "rename": false, "delete": false},
	"decoys": {"classification": "secret", "read": false, "create": false, "overwrite": false, "append": false, "rename": false, "delete": false},
	"traps": {"classification": "internal", "read": true, "create": false, "overwrite": false, "append": false, "rename": false, "delete": false},
}

config := {"role_vocabulary": ["intern", "developer", "auditor"], "roots": roots}

# A request as unit 05 hands it over: canonical, derived, and carrying no raw input.
req(role, root, operation, tier) := {
	"request": {"request_id": "r", "protocol_version": "2026-07-28", "transport": "streamable_http", "method": "tools/call"},
	"principal": {"id": role, "auth_method": "local_config", "assurance": "unverified_local", "roles": [role], "environment": "development"},
	"client": {"id": "c"},
	"target": {"server_id": "s", "tool_name": "t", "schema_fingerprint": "v2:x", "registry_risk_tier": tier},
	"resource": {"canonical_path": sprintf("/fixture/%s/f", [root]), "root": root, "classification": roots[root].classification, "exists": true},
	"arguments": {"arg_hash": "h", "operation": operation},
	"context": {"policy_revision": "test"},
}

# `tools/list`: unit 04 returns a tool-less R0 target and unit 05 derives empty
# strings for path, root and classification.
discovery(role) := object.union(req(role, "public", "read", "R0"), {
	"request": {"request_id": "r", "protocol_version": "2026-07-28", "transport": "streamable_http", "method": "tools/list"},
	"target": {"server_id": "s", "tool_name": null, "schema_fingerprint": null, "registry_risk_tier": "R0"},
	"resource": {"canonical_path": "", "root": "", "classification": "", "exists": false},
})

rootless(role) := object.union(
	req(role, "public", "read", "R1"),
	{"resource": {"canonical_path": "/elsewhere", "root": "", "classification": "", "exists": true}},
)

unknown_root(role) := object.union(
	req(role, "public", "read", "R1"),
	{"resource": {"canonical_path": "/x", "root": "invented", "classification": "public", "exists": true}},
)

# ---------------------------------------------------------------------------
# The three-principal matrix (spec test 10), allow side first
# ---------------------------------------------------------------------------

test_intern_reads_public if {
	r := gateway.decision with input as req("intern", "public", "read", "R1") with data.config as config
	r.decision == "allow"
	r.reason_code == "POLICY_SCOPED_READ"
	r.risk_tier == "R1"
}

test_r0_read_is_metadata_not_content if {
	r := gateway.decision with input as req("intern", "public", "read", "R0") with data.config as config
	r.decision == "allow"
	r.reason_code == "POLICY_METADATA_READ"
}

test_developer_writes_workspace if {
	r := gateway.decision with input as req("developer", "workspace", "overwrite", "R2") with data.config as config
	r.decision == "allow"
	r.reason_code == "POLICY_SCOPED_WRITE"
}

test_developer_creates_in_workspace if {
	r := gateway.decision with input as req("developer", "workspace", "create", "R2") with data.config as config
	r.reason_code == "POLICY_SCOPED_WRITE"
}

test_developer_appends_in_workspace if {
	r := gateway.decision with input as req("developer", "workspace", "append", "R2") with data.config as config
	r.reason_code == "POLICY_SCOPED_WRITE"
}

test_developer_reads_own_workspace if {
	r := gateway.decision with input as req("developer", "workspace", "read", "R1") with data.config as config
	r.reason_code == "POLICY_SCOPED_READ"
}

test_auditor_reads_confidential if {
	r := gateway.decision with input as req("auditor", "confidential", "read", "R1") with data.config as config
	r.decision == "allow"
	r.reason_code == "POLICY_SCOPED_READ"
}

# ---------------------------------------------------------------------------
# Deny side, and the distinction between the two deny codes
# ---------------------------------------------------------------------------

test_intern_denied_confidential_by_path if {
	# Intern MAY read, and the root permits reading. What they may not do is read
	# HERE — so the code names the path, not the operation.
	r := gateway.decision with input as req("intern", "confidential", "read", "R1") with data.config as config
	r.decision == "deny"
	r.reason_code == "POLICY_PATH_NOT_PERMITTED"
	r.risk_tier == "R1"
}

test_developer_denied_production_by_path if {
	r := gateway.decision with input as req("developer", "production", "read", "R1") with data.config as config
	r.reason_code == "POLICY_PATH_NOT_PERMITTED"
}

test_write_to_production_denied_by_the_root_ceiling if {
	# The root forbids the operation outright, so no principal reaches the grant
	# table — including one whose grants were widened by mistake.
	r := gateway.decision with input as req("developer", "production", "overwrite", "R2") with data.config as config
	r.reason_code == "POLICY_OPERATION_NOT_PERMITTED"
}

test_delete_from_confidential_denied_by_the_root_ceiling if {
	r := gateway.decision with input as req("developer", "confidential", "delete", "R4") with data.config as config
	r.reason_code == "POLICY_OPERATION_NOT_PERMITTED"
}

test_auditor_never_writes_anywhere if {
	# The root permits overwriting the workspace; the ROLE performs no write
	# operation at all, so this is about the operation rather than the place.
	r := gateway.decision with input as req("auditor", "workspace", "overwrite", "R2") with data.config as config
	r.decision == "deny"
	r.reason_code == "POLICY_OPERATION_NOT_PERMITTED"
}

test_intern_never_deletes if {
	r := gateway.decision with input as req("intern", "workspace", "delete", "R4") with data.config as config
	r.reason_code == "POLICY_OPERATION_NOT_PERMITTED"
}

# ---------------------------------------------------------------------------
# Precedence (POLICY-008)
# ---------------------------------------------------------------------------

test_prohibition_beats_a_matching_grant if {
	# THE precedence test. `traps` is prohibited outright; this input additionally
	# gives the principal a grant for it, so an implementation that let an allow rule
	# win would allow. Guarding each level with `not` on the ones above is what makes
	# that impossible rather than unlikely.
	r := gateway.decision with input as req("developer", "traps", "read", "R1")
		with data.config as config
		with gateway.grants as {"developer": {"traps": {"read"}}}
	r.decision == "deny"
	r.reason_code == "POLICY_PROHIBITED"
}

test_secret_classification_is_prohibited if {
	# Defense in depth: unit 05 denies a decoy at stage 05 and this never fires in
	# the shipped configuration. Constructed directly here so it is tested anyway —
	# removing an entry from `canonicalize.sensitive_decoys` must downgrade the
	# denial, not remove it.
	r := gateway.decision with input as req("auditor", "decoys", "read", "R1") with data.config as config
	r.reason_code == "POLICY_PROHIBITED"
}

test_a_resource_in_no_root_is_prohibited if {
	r := gateway.decision with input as rootless("developer") with data.config as config
	r.reason_code == "POLICY_PROHIBITED"
}

# ---------------------------------------------------------------------------
# Default deny (POLICY-005)
# ---------------------------------------------------------------------------

test_unknown_role_is_denied if {
	# A role with no grants can perform no operation ANYWHERE, so the code names the
	# operation rather than the path — which is the more useful of the two here: the
	# principal's problem is not where they asked, it is that they hold nothing.
	# `IdentityConfig` already refuses a role outside the vocabulary at load, so this
	# is defense in depth rather than a reachable request.
	r := gateway.decision with input as req("stranger", "public", "read", "R1") with data.config as config
	r.decision == "deny"
	r.reason_code == "POLICY_OPERATION_NOT_PERMITTED"
}

test_unknown_root_denies if {
	# A root the gateway never approved cannot be looked up in `data.config.roots`,
	# so the ceiling check is undefined — which must read as "not permitted".
	r := gateway.decision with input as unknown_root("developer") with data.config as config
	r.decision == "deny"
	r.reason_code == "POLICY_OPERATION_NOT_PERMITTED"
}

test_no_published_config_denies_everything if {
	# The fail-closed shape of a missing `data.config`: if the gateway never published
	# the roots, no operation is permitted anywhere. An implementation reading a
	# missing ceiling as "unrestricted" would allow every write in the fixture.
	r := gateway.decision with input as req("developer", "workspace", "overwrite", "R2")
	r.decision == "deny"
}

# ---------------------------------------------------------------------------
# Discovery — the tool-less R0 target (unit 04's `tools/list`)
# ---------------------------------------------------------------------------

test_discovery_is_metadata_read if {
	r := gateway.decision with input as discovery("intern") with data.config as config
	r.decision == "allow"
	r.reason_code == "POLICY_METADATA_READ"
	r.risk_tier == "R0"
}

test_discovery_is_not_judged_as_an_empty_root if {
	# `root == ""` is prohibited for a real resource and must NOT be for discovery,
	# which names no resource at all. Both readings of the empty string are in this
	# bundle and this is the test that keeps them apart.
	r := gateway.decision with input as discovery("auditor") with data.config as config
	r.decision == "allow"
}

# ---------------------------------------------------------------------------
# Obligations (POLICY-007) — policy narrows, and nothing here is above the ceiling
# ---------------------------------------------------------------------------

test_obligations_are_present_on_every_allow if {
	r := gateway.decision with input as req("intern", "public", "read", "R1") with data.config as config
	r.obligations.timeout_ms == 3000
	r.obligations.max_response_bytes == 1048576
}

test_writes_get_a_longer_deadline if {
	r := gateway.decision with input as req("developer", "workspace", "overwrite", "R2") with data.config as config
	r.obligations.timeout_ms == 5000
}

test_shipped_obligations_stay_under_the_gateway_ceiling if {
	# A shipped policy that relies on being clamped is a policy whose author did not
	# know the limit. The ceilings are `[router]`'s, restated as literals because this
	# file cannot read the gateway's TOML; `test_policy.py` asserts they match.
	r := gateway.decision with input as req("developer", "workspace", "overwrite", "R2") with data.config as config
	r.obligations.timeout_ms <= 10000
	r.obligations.max_response_bytes <= 4194304
}

# ---------------------------------------------------------------------------
# Shape and tier fidelity
# ---------------------------------------------------------------------------

test_the_registry_tier_is_echoed_not_invented if {
	# The pipeline refuses an allow whose tier differs from the registry's, so a
	# policy inventing one would turn every allow into POLICY_RESULT_INVALID.
	r0 := gateway.decision with input as req("developer", "workspace", "read", "R0") with data.config as config
	r1 := gateway.decision with input as req("developer", "workspace", "read", "R1") with data.config as config
	r2 := gateway.decision with input as req("developer", "workspace", "append", "R2") with data.config as config
	r0.risk_tier == "R0"
	r1.risk_tier == "R1"
	r2.risk_tier == "R2"
}

test_a_denial_echoes_the_tier_too if {
	# Only the `default` rule may report R4-because-nothing-matched. A deny that a
	# rule actually produced must carry the registry's tier, or the audit record
	# overstates the severity of every refusal.
	r := gateway.decision with input as req("intern", "confidential", "read", "R1") with data.config as config
	r.risk_tier == "R1"
}
