# `data.gateway.discoverable` - REG-010's `could_ever_allow`.
#
# The question is NOT "may this principal call this tool on this resource" but "is
# there ANY resource for which they could". Unit 04 asks it once per approved tool to
# build `tools/list`, and it is a required parameter there with no default: a default
# of yes would over-disclose the day someone forgot to pass it, and that failure is
# invisible - the list simply looks fuller than it should.
#
# `_tech/04` section 6 warns against approximating this by calling `decision` with a
# placeholder path, in both directions. A placeholder that happens to be denied hides
# a tool the principal can legitimately use; one that happens to be allowed reveals a
# tool they cannot. So this is its own entrypoint over its own input.
package gateway

import rego.v1

default discoverable := false

discoverable if {
	some role in input.principal.roles
	some root, ops in grants[role]
	not prohibited_root(root)
	input.arguments.operation in ops
	data.config.roots[root][input.arguments.operation]
}
