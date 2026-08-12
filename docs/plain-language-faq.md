# Zero-Trust MCP Gateway: Plain-Language FAQ

This page explains what the project is, why it exists, what has actually been built,
and what is still missing. It is written for people who understand the idea of MCP
but do not want to read the specifications or test reports first.

## What problem are we trying to solve?

AI applications can use MCP tools to read files, write data or perform other actions.
We do not want the AI application—or the request it produces—to be the final authority
on what is allowed.

The gateway is a security checkpoint placed before the tool. It checks the exact user,
tool, operation and resource before allowing the action.

## What is the main idea in one sentence?

> Never rely on the AI or MCP client to enforce permissions; make a deterministic
> security layer approve every tool action before it happens.

## Is the project only a collection of attack tests?

No. The gateway itself is implemented and can receive an MCP request, evaluate it,
forward an approved call to a local MCP server and return the result.

The attack harness is the test laboratory around the gateway. It tries harmful calls
and checks the protected files to confirm whether damage really happened. The harness
is evidence that the gateway works; it is not the gateway itself.

## Why is there no AI model or model API key?

The security decision should not depend on a particular model. The current tests use
a predictable test client in place of an AI so the same calls produce repeatable
results.

A model can be connected later. It would propose a tool call, but the gateway would
still make the final allow-or-deny decision.

## What is an MCP client?

An MCP client is the connector inside an AI application that speaks to an MCP server.
The model may decide that it wants to read a file; the MCP client converts that choice
into a structured MCP request and sends it.

The intended flow is:

```text
Person → AI application → MCP client → Gateway → MCP server → Tool
```

The gateway looks like an MCP server to the client and like an MCP client to the real
server.

## Is the AI expected to “go rogue”?

Not in the science-fiction sense. More realistic problems are misunderstanding an
instruction, selecting the wrong tool or path, following malicious instructions hidden
in untrusted content, or receiving an intentionally harmful request from a user.

The gateway limits the damage from these mistakes because the model cannot grant
itself more permission.

## If a user completed OAuth, are they not already authorized?

OAuth establishes identity and usually grants broad scopes. It does not always answer
whether this exact user may perform this exact operation on this exact resource.

For example, OAuth may allow Alice to connect to a file service. A separate policy may
still allow her to read `workspace/` while denying access to `payroll/`. If the AI asks
for `payroll/salaries.csv`, the gateway should deny the call even though Alice is
properly logged in.

## Does the current gateway support OAuth?

No. The current version uses one identity and role written in local configuration. It
demonstrates detailed authorization after identity is known, but it does not yet verify
a real OAuth user or token.

Connecting verified OAuth identity and scopes to gateway policy is required before a
multi-user or public version can be claimed.

## What harmful situations does the current gateway catch?

Within its local filesystem scope, it handles situations such as:

- malformed, oversized or contradictory MCP requests;
- unknown, disabled or unexpectedly changed tools;
- missing, incorrectly typed or extra tool arguments;
- directory traversal, encoded paths, null bytes and symlink escapes;
- attempts to read sensitive or unapproved locations;
- users trying operations their role does not permit;
- policy-engine failures, timeouts and invalid decisions;
- MCP server crashes, hangs and malformed or oversized responses;
- audit failures that would otherwise leave an action unrecorded.

It also tests legitimate reads, writes, directory listings and deletes so that simply
blocking everything cannot look successful.

## What does 113/113 mean?

It does not mean there are 113 test scenarios. The project has 118 hand-written
scenarios.

The 113/113 figure means that every request expected to produce an audit record in that
evidence run was matched to one. Some scenarios are handled by the transport before a
normal gateway decision exists, which is why the figures are different.

## Can this protect any MCP project?

Not yet. The current version is designed for one local filesystem-style MCP server,
with file paths and operations such as read, write, append and delete.

Supporting arbitrary services such as GitHub, Slack, databases or remote MCP servers
would require new resource types, policies and integrations.

## Can we host it publicly and let people use it?

Not safely in its current form. It listens only on the local machine, has no real
caller authentication, starts one local child server and has no simple production
launcher or onboarding flow.

The shortest usable product is a self-hosted local gateway that runs beside a
filesystem MCP server. A public service would additionally need HTTPS, OAuth, tenant
isolation, remote-server support, secure credential storage and operational controls.

## What external security is still missing?

The major missing pieces are:

- real OAuth/OIDC authentication and verified identity;
- HTTPS and safe public-network exposure;
- separation between different users and organizations;
- protection against clients bypassing the gateway and calling the server directly;
- stronger operating-system or container isolation;
- remote and non-filesystem MCP server support;
- a race-free guarantee when files change between checking and use.

These limits should remain visible rather than being hidden behind the test results.

## Is this a finished product?

No. It is a working security prototype with a strong evaluation harness. The security
pipeline is implemented, but installation, configuration, authentication and real
client integrations are not yet product-ready.

## Is the project still useful?

Yes. It demonstrates that MCP tool calls can be checked independently of the model and
that security claims can be tested by observing real effects rather than trusting the
gateway's own response.

Its current value is security engineering and evidence. Its next value should come
from making that engine easy for another developer to run.

## What should be built next?

The smallest useful next milestone is:

1. one command that starts the gateway correctly;
2. one integration with a real filesystem MCP server;
3. one configuration helper for approving tools and directories;
4. one real MCP client example;
5. one optional model-powered demonstration.

After that, another developer should be able to install it, point a client at it and
see an allowed and a denied tool call without understanding the evaluation harness.

## How should we describe the project honestly?

> A working prototype of a policy-enforcement gateway for local filesystem MCP tool
> calls, supported by an adversarial side-effect evaluation harness. Model integration,
> OAuth authentication and product packaging remain future work.
