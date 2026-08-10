# THE POLICY. Everything else in this bundle is plumbing around this table.
#
# role -> root -> the operations that role may perform there. `_specs/06` section 6
# reduced the source document's four-principal matrix to what the v1 fixture can
# actually exercise, and `admin` is deliberately absent: without R3 and an approval
# path there is no way to express a properly constrained administrator, and adding an
# unconstrained one would only demonstrate the anti-pattern.
#
# The ROOT NAMES and the ROLE NAMES are not defined here. Roots and their operation
# ceilings come from `[[canonicalize.roots]]` and the role vocabulary from
# `[identity]`, both published to `data.config` by the gateway at startup. Restating
# either here would create a second home for a value that already has one, and the
# failure mode is silent - a role present in config and absent from policy denies
# everything for that principal and looks exactly like a policy decision.
# `roles_without_grants` below is what turns that silence into a startup failure.
package gateway

grants := {
	"intern": {"public": {"read"}},
	"developer": {
		"public": {"read"},
		"workspace": {"read", "create", "overwrite", "append", "delete"},
	},
	"auditor": {
		"public": {"read"},
		"workspace": {"read"},
		"confidential": {"read"},
		"production": {"read"},
	},
}

# Every role the gateway will ever present must have an entry above. Queried at
# startup; a non-empty answer refuses to serve. Without it, adding a role to
# `identity.role_vocabulary` and forgetting this file produces a principal for whom
# every request is POLICY_DEFAULT_DENY - indistinguishable, from the outside, from a
# policy that considered the request and said no.
roles_without_grants contains role if {
	some role in data.config.role_vocabulary
	not grants[role]
}

# The reverse direction, and the reason it is separate: a grant for a role that no
# longer exists is dead policy, and dead policy in a file a reviewer reads as the
# authorization matrix is worse than dead code.
grants_without_roles contains role if {
	some role, _ in grants
	not role in data.config.role_vocabulary
}

# A grant naming a root the gateway does not approve can never fire. Same reasoning:
# a reviewer reads this table as the truth, so every line in it has to be live.
grants_naming_unknown_roots contains [role, root] if {
	some role, roots in grants
	some root, _ in roots
	not data.config.roots[root]
}

# A grant on a PROHIBITED root can never fire - prohibitions outrank everything - so
# it is a line that reads as permission and grants nothing. Found by the break pass:
# adding `"decoys": {"read"}` to the auditor changed no decision anywhere, because
# the prohibition caught every one of them, and no test noticed. In the one file a
# reviewer reads as the authorization matrix, a line that means nothing is worse than
# a line that means something wrong.
grants_on_prohibited_roots contains [role, root] if {
	some role, roots in grants
	some root, _ in roots
	prohibited_root(root)
}

# The same fact reached the other way. A prohibition can name a root OR a
# classification, and the first version of this rule only knew about names — so a
# grant on `decoys`, which is prohibited by its `secret` classification, still read as
# permission and still granted nothing. The break pass found it on the second run,
# after the first fix.
grants_on_prohibited_roots contains [role, root] if {
	some role, roots in grants
	some root, _ in roots
	prohibited_classification(data.config.roots[root].classification)
}
