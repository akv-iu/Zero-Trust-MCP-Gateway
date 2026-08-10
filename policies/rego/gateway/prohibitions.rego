# Explicit prohibitions. Highest precedence, and the file a reviewer should read
# first: nothing below can grant what this file refuses (POLICY-008).
#
# Deliberately tiny. A prohibition list that grows into a second authorization system
# stops being reviewable, which is the only property that makes it worth having.
package gateway

import rego.v1

# `traps/` holds the escape links the corpus uses to test containment. Nothing in it
# is data; no principal has business reading it. It is prohibited rather than merely
# ungranted so that the refusal survives someone adding a broad grant later.
#
# Note this does NOT block `traps/public_link/documentation.txt`: unit 05 resolves the
# link first, so that request arrives with `root == "public"` and is judged as the
# public read it really is. The prohibition is on where a path LANDS, never on how it
# was spelled - the same rule the canonicalizer follows.
prohibited_root(root) if root == "traps"

# Defense in depth. Unit 05 denies a sensitive decoy at stage 05 with
# CANON_SENSITIVE_PATH and this rule never fires in the shipped configuration - it is
# here so that removing an entry from `canonicalize.sensitive_decoys` downgrades the
# denial rather than removing it. Covered by the Rego tests, which construct the input
# directly and therefore do not depend on stage 05 having missed it.
prohibited_classification(classification) if classification == "secret"

prohibition := response("deny", "POLICY_PROHIBITED") if {
	not is_discovery
	prohibited_root(input.resource.root)
}

prohibition := response("deny", "POLICY_PROHIBITED") if {
	not is_discovery
	prohibited_classification(input.resource.classification)
}

# A resource in no approved root must never have reached stage 06 at all - unit 05
# denies it as CANON_OUTSIDE_ROOT. If one arrives, something upstream is broken, and
# the safe reading of "broken" is prohibited rather than evaluated.
prohibition := response("deny", "POLICY_PROHIBITED") if {
	not is_discovery
	input.resource.root == ""
}
