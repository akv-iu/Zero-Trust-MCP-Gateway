# Zero-Trust MCP Gateway

**Document type:** Product idea, system requirements, reference architecture, evaluation harness, guardrails, and costed technology stack
**Draft:** v0.2 - cloud-first baseline finalized
**Research snapshot:** August 8, 2026
**Working project name:** Zero-Trust MCP Gateway
**Finalized baseline:** Hosted open-weight model inference; local deterministic MCP enforcement; no local LLM runtime required
**Finalized MVP direction:** Cloud-hosted open-weight inference with a lightweight local security control plane; no local LLM runtime required

---

## 1. Top-Level Idea

### 1.1 Problem statement

AI agents increasingly connect to Model Context Protocol (MCP) servers that expose files, databases, source-control systems, browsers, SaaS applications, and internal business actions. A direct client-to-server connection usually gives the agent whatever authority the MCP server and its underlying credentials possess. That creates several practical risks:

- A prompt-injected, compromised, or simply mistaken model can invoke a valid tool with unsafe arguments.
- Authentication alone does not answer whether a specific principal may call a specific tool on a specific resource.
- MCP servers may expose broader privileges than an individual user, agent, workflow, or environment should receive.
- Tool descriptions and annotations are supplied by the upstream server and cannot be treated as a complete security policy.
- Local `stdio` servers and remote Streamable HTTP servers have different identity and transport boundaries.
- Organizations often lack one consistent place to apply authorization, rate limits, approvals, audit logging, schema-drift detection, and security telemetry across MCP servers.
- A successful tool response does not prove that the action was authorized, safe, or fully auditable.
- Requiring every developer to own a high-end GPU or workstation would make the security project unnecessarily expensive and difficult to reproduce.

The project should solve this by placing a security enforcement point between an MCP client and one or more MCP servers while keeping model inference replaceable and outside the trusted security boundary.

### 1.2 Proposed solution

Build a transport-aware, default-deny **Zero-Trust MCP Gateway** that acts as:

- an MCP server toward the requesting client or agent; and
- an MCP client toward the selected upstream MCP server.

For every MCP request, the gateway will:

1. Validate the transport, protocol version, JSON-RPC envelope, and relevant MCP headers.
2. Establish or derive the requesting principal and client context.
3. Resolve the target server, MCP method, tool, resource, or prompt.
4. Canonicalize and inspect arguments before policy evaluation.
5. Evaluate deterministic authorization policy against identity, tool, resource, arguments, environment, and risk.
6. Apply obligations such as rate limits, timeouts, maximum response size, redaction, or human approval.
7. Forward only permitted requests with least-privilege downstream credentials.
8. Validate and constrain the upstream result.
9. Emit an audit event, metrics, logs, and a distributed trace for the full decision path.

The model may propose an action, explain an action, or recover from a denial. It does not authorize or execute the action. The core promise is:

> Every MCP action is explicitly identified, evaluated, constrained, and recorded before it is allowed to affect a protected system.

### 1.3 Finalized cloud-first deployment decision

The default project architecture will not run an LLM on the developer laptop. Model inference will use a cloud-hosted **open-weight** model, while all security-sensitive tool execution remains local or inside infrastructure controlled by the project.

The term *open-weight* is intentional. The model weights may be publicly available, but GroqCloud, Cloudflare Workers AI, and similar hosting platforms are commercial hosted services rather than open-source infrastructure.

| Decision | Finalized baseline |
|---|---|
| Model location | Hosted cloud inference; no local model weights or GPU requirement |
| Primary provider | **GroqCloud** |
| Primary model | **`openai/gpt-oss-20b`** |
| Independent cross-model comparison | **`qwen/qwen3.6-27b`** |
| Optional higher-capability comparison | **`openai/gpt-oss-120b`** |
| Optional advisory safety model | **`openai/gpt-oss-safeguard-20b`**, never the final authorizer |
| Provider fallback | **Cloudflare Workers AI** with **`@cf/openai/gpt-oss-20b`** |
| Agent orchestrator | **PydanticAI** running locally |
| Evaluation runtime | **Inspect AI**, plus `pytest` and Hypothesis |
| Local security services | Agent harness, gateway, OPA, one sandboxed MCP server, tests, and JSONL audit output |
| Disabled in the MVP | Ollama, local model inference, provider-native remote MCP, provider-built-in web search, and provider-built-in code execution |

A previously considered comparison model, `llama-3.3-70b-versatile`, is not part of the finalized baseline because Groq announced its free/developer-tier shutdown for August 16, 2026. The design must therefore treat provider model identifiers as replaceable configuration and check deprecation notices before release runs.

### 1.4 Finalized system boundary

The intended request path is:

```text
User or evaluation scenario
          |
          v
Local PydanticAI / Inspect harness
          |
          | HTTPS: prompt + selected tool schemas
          v
Cloud-hosted open-weight model
          |
          | structured proposed tool call
          v
Local harness
          |
          | MCP request; never direct execution
          v
Zero-Trust MCP Gateway
          |
          +--> OPA/Rego policy decision
          |
          +--> audit and bounded telemetry
          |
          v
Sandboxed local or controlled MCP server
```

The cloud provider performs inference only. It must not connect directly to the MCP server, receive downstream credentials, modify policy, mint approvals, or decide whether a tool call is allowed.

### 1.5 Intended users

The initial users are:

- Developers who run local MCP servers through Claude Desktop, Cursor, another MCP client, or a custom agent.
- Security and platform teams evaluating whether MCP-connected agents can be used safely.
- Teams that need one policy layer across several MCP servers.
- Organizations that require proof of who invoked a tool, why it was allowed or denied, and what side effect occurred.
- Students and individual developers who need a credible agent-security project without purchasing model hardware.

### 1.6 Initial product scope

The first useful release will focus on:

- `tools/list` and `tools/call` as the primary protected MCP capabilities.
- Both local `stdio` and remote Streamable HTTP transport paths.
- Deterministic tool-level and argument-level authorization.
- A sandboxed filesystem MCP server as the first protected system.
- Filesystem, SQL, outbound HTTP/fetch, and mock business-action guardrails over successive phases.
- Identity-aware access controls for remote HTTP traffic after the local security boundary works.
- Structured JSONL audit records and lightweight local metrics first; a complete observability backend later.
- A model-independent deterministic harness plus a separate cloud-model agent harness.
- Provider portability so Groq can be replaced by Cloudflare or another compatible endpoint without changing the gateway.
- Synthetic data only for all hosted-model experiments and public demonstrations.

Resources, prompts, elicitation, sampling, and other MCP capabilities may be added after the tool-call security model is stable.

### 1.7 Explicit non-goals for the first release

The project is not intended to be:

- An LLM-based firewall in which a model makes the final allow or deny decision.
- A local model-hosting or GPU-inference project.
- A provider-managed agent in which Groq, Cloudflare, or another vendor directly invokes the protected MCP server.
- A defense against an attacker who already controls the host, kernel, container runtime, gateway administrator account, or signing keys.
- A universal data-loss-prevention product in the first release.
- A replacement for least-privilege credentials on the upstream service.
- A promise that arbitrary shell execution can be made safe on the host machine.
- A Kubernetes platform in the MVP.
- A production identity provider, secrets manager, SIEM, or observability backend built from scratch.
- A guarantee that all prompt injection can be detected semantically.
- A requirement to run Keycloak, PostgreSQL, Prometheus, Grafana, Tempo, Loki, and several MCP servers simultaneously on a weak laptop.

The gateway should instead provide a narrow, testable security boundary with clear assumptions and measurable guarantees.

### 1.8 Success definition

The project is successful when it can demonstrate, with reproducible evidence, that:

- legitimate MCP actions still work through the gateway;
- prohibited actions are denied before the upstream side effect occurs;
- the result is independent of which model or deterministic client proposed the call;
- model-provider outages or quota exhaustion cannot create an authorization bypass;
- the laptop performs only lightweight orchestration, policy evaluation, test execution, and sandboxed tool work;
- gateway latency is measured separately from cloud-model latency;
- all published scenarios use synthetic data and bounded cloud usage; and
- the complete security-core test suite can run without any model API call.

---

## 2. Requirements

### 2.1 Requirement language and priorities

The words **MUST**, **SHOULD**, and **MAY** are normative:

- **MUST:** Required for the stated release or security property.
- **SHOULD:** Expected unless a documented reason exists not to implement it.
- **MAY:** Optional or deferred.

Priority levels:

- **P0:** Required for the first credible MVP.
- **P1:** Required for the first complete portfolio release.
- **P2:** Advanced or production-hardening work after the core design is validated.

A requirement is complete only when its acceptance test passes. A feature that exists without a test is not considered complete.

### 2.2 Design principles

#### REQ-PRINCIPLE-001 - Deterministic enforcement [P0]

The gateway MUST make final authorization decisions using deterministic code and policy. A language model MAY classify content, generate attack cases, or provide an advisory risk score, but its output MUST NOT be sufficient by itself to authorize an action.

**Acceptance criteria:**

- The gateway continues to enforce policy when all model services are unavailable.
- Replaying the same canonical request against the same policy revision and context produces the same authorization result.
- No code path maps an LLM response directly to `allow=true` without a deterministic policy check.

#### REQ-PRINCIPLE-002 - Default deny [P0]

A request with no matching allow policy MUST be denied. Unknown MCP methods, servers, tools, schemas, identities, scopes, protocol versions, and environments MUST be denied or quarantined unless explicitly placed in an approved compatibility mode.

#### REQ-PRINCIPLE-003 - Least privilege [P0]

The gateway MUST minimize privileges at every boundary:

- minimum client scopes;
- minimum tool access;
- minimum resource range;
- minimum downstream credential privileges;
- minimum response size and retention;
- minimum policy data disclosed to components.

#### REQ-PRINCIPLE-004 - Complete mediation [P0]

Every protected MCP action MUST pass through authentication or identity derivation, validation, policy evaluation, obligation enforcement, forwarding, and audit. There MUST NOT be an undocumented bypass route to an upstream MCP server in the protected deployment.

#### REQ-PRINCIPLE-005 - Fail safely [P0]

The gateway MUST fail closed for protected actions when policy, identity verification, registry data, argument parsing, approval verification, or critical audit persistence is unavailable or invalid. Health endpoints MAY remain available for diagnosis.

#### REQ-PRINCIPLE-006 - Transport-aware security [P0]

The design MUST treat `stdio` and Streamable HTTP as different trust boundaries. OAuth-style bearer-token validation applies to remote HTTP. For `stdio`, the launcher process and local configuration form the identity boundary; the gateway MUST NOT claim that a local pipe supplies a cryptographically verified end-user identity when it does not.

#### REQ-PRINCIPLE-007 - Evidence over demonstration [P0]

The project MUST produce repeatable evidence for security and performance claims. Screenshots of an agent being allowed or denied are insufficient without a test case, expected result, observed side effect, policy revision, and trace or audit identifier.

### 2.3 Trust boundaries and threat model

#### 2.3.1 Assets to protect

The system MUST model at least the following assets:

- Local files and directories.
- Database contents and schema.
- Source-control repositories and deployment environments.
- Business records and high-impact actions such as refunds or deletion.
- API credentials, OAuth tokens, session identifiers, and secrets.
- Cloud-model API keys, provider configuration, quota, and spend limits.
- Sanitized prompts, selected tool schemas, and tool results sent to a hosted model.
- MCP server definitions, tool schemas, policy bundles, and server registry entries.
- Audit evidence and security telemetry.
- Human approval decisions.

#### 2.3.2 Untrusted inputs

The following MUST be treated as untrusted unless independently verified:

- User prompts.
- Model-generated tool calls and arguments.
- Hosted-provider responses, tool-call payloads, refusal text, system fingerprints, and usage metadata.
- MCP client metadata.
- JSON-RPC bodies and transport headers.
- Tool descriptions, annotations, and schemas received from an upstream MCP server.
- Resource content and tool results returned by an MCP server.
- URLs, file paths, SQL text, command text, and business identifiers supplied as arguments.
- Network responses, redirects, and DNS results.
- Free-form text displayed in an approval interface.

#### 2.3.3 Conditionally trusted inputs

The following MAY be trusted only after validation:

- A principal derived from a locally controlled launcher configuration.
- An OIDC identity after issuer, signature, audience, expiry, not-before, and required claims are checked.
- A client registration after redirect URIs and metadata are validated.
- A policy bundle after provenance and integrity checks.
- A tool schema after it is registered, fingerprinted, and approved.
- A human approval after its token is verified and bound to the exact normalized action.

#### 2.3.4 Trusted computing base

The initial trusted computing base consists of:

- The gateway runtime and its configuration.
- The policy engine and active policy bundle.
- Trusted identity-provider keys and issuer configuration.
- The protected server registry.
- Secrets required to reach upstream services.
- Audit storage and its access controls.
- Deployment configuration that prevents provider-native or direct-to-upstream tool execution paths.
- Administrator identities and signing keys.

The design SHOULD keep this trusted base small. The agent orchestrator, cloud model provider, model weights, and upstream MCP server MUST NOT be considered part of the authorization trusted base.

#### 2.3.5 Required threat coverage

The threat model MUST include tests for:

1. Unauthorized tool invocation.
2. Authorized tool invoked against an unauthorized resource.
3. Header and JSON-RPC body mismatch.
4. Unsupported or downgraded MCP protocol version.
5. Malformed JSON-RPC, duplicate fields, excessive nesting, and oversized payloads.
6. Path traversal, encoded traversal, symlink escape, case normalization, and null-byte variants.
7. Destructive, multi-statement, obfuscated, or privilege-changing SQL.
8. Server-side request forgery, DNS rebinding, redirect escape, cloud metadata access, and credential forwarding.
9. Shell and command injection.
10. Prompt injection contained in a tool result or resource.
11. Tool-schema drift, misleading annotations, and tool-description poisoning.
12. Expired, forged, replayed, wrong-audience, or over-scoped tokens.
13. Token passthrough to a service for which the token was not issued.
14. Confused-deputy flows involving authorization or third-party credentials.
15. Cross-tenant access.
16. Rate-limit and resource-exhaustion attacks.
17. Approval replay, approval theft, and argument mutation after approval.
18. State-handle or session-handle hijacking.
19. Upstream timeout, partial response, crash, and malformed result.
20. Audit omission, log injection, sensitive-data leakage, and unauthorized log modification.
21. Dependency, container-image, and policy-supply-chain compromise.

#### 2.3.6 Security boundary limitations

The documentation MUST state that:

- A gateway running on a compromised host cannot reliably protect that host from an administrator or kernel-level attacker.
- A local `stdio` client can bypass the gateway if it is separately configured with direct access to the protected server.
- A policy cannot compensate for upstream credentials that are unnecessarily broad; downstream credentials should still be scoped.
- Semantic prompt-injection detection is probabilistic, so high-impact actions require deterministic controls independent of prompt content.
- Security guarantees apply only to traffic and servers registered behind the gateway.
- Hosted inference necessarily sends selected prompts, tool schemas, and sanitized tool results to an external provider; the project cannot claim that these values never leave the machine.
- Provider availability, rate limits, pricing, retention controls, and model identifiers may change; they are operational dependencies, not security authorities.

### 2.4 Reference architecture requirements

#### 2.4.1 Logical architecture

The finalized reference architecture separates cloud inference from local security enforcement:

```text
                         UNTRUSTED CLOUD INFERENCE

                 +-----------------------------------+
                 | GroqCloud                         |
                 | primary: openai/gpt-oss-20b       |
                 | comparison: qwen/qwen3.6-27b      |
                 | optional: openai/gpt-oss-120b     |
                 +-----------------^-----------------+
                                   |
                 HTTPS model calls | prompts, selected tool schemas,
                 and sanitized      | sanitized tool results only
                 tool results       |
                                   v
+------------------------------------------------------------------------+
|                         LOCAL / CONTROLLED BOUNDARY                     |
|                                                                        |
|  +------------------+       +---------------------+                     |
|  | User / scenarios |------>| PydanticAI or       |                     |
|  | Inspect AI       |       | deterministic runner|                     |
|  +------------------+       +----------+----------+                     |
|                                        | proposed MCP call              |
|                                        v                                |
|                           +-----------------------------+                |
|                           | ZERO-TRUST MCP GATEWAY      |                |
|                           |                             |                |
|                           | protocol validation         |                |
|                           | identity/context            |                |
|                           | schema resolution           |                |
|                           | canonicalization            |                |
|                           | deterministic authorization |                |
|                           | rate/approval obligations   |                |
|                           | response filtering          |                |
|                           | audit and telemetry         |                |
|                           +-----------+-----------------+                |
|                                       |                                  |
|                              policy   |                                  |
|                                       v                                  |
|                               +---------------+                          |
|                               | OPA / Rego    |                          |
|                               +-------+-------+                          |
|                                       | allow/deny                       |
|                                       v                                  |
|                 +---------------------+----------------------+           |
|                 |                     |                      |           |
|                 v                     v                      v           |
|          Filesystem MCP          SQL MCP later       Mock business MCP   |
|          synthetic fixture       seeded fixture      synthetic fixture  |
|                                                                        |
|  JSONL audit and lightweight metrics are local in the first profile.   |
+------------------------------------------------------------------------+

Cloudflare Workers AI is a provider fallback. It is not a second tool-execution path.
Provider-native remote MCP, provider-side browser tools, and provider-side code execution
remain disabled for the security evaluation.
```

#### REQ-ARCH-001 - Data plane and control plane separation [P0]

Request enforcement MUST be a data-plane operation. Policy authoring, registry management, audit search, provider configuration, and approval administration MUST be control-plane operations with separate permissions.

#### REQ-ARCH-002 - Agent and model isolation from policy [P0]

The agent orchestrator and hosted model MUST remain outside the trusted enforcement path. They MAY submit an MCP request but MUST NOT modify active policy, write registry entries, mint approvals, access downstream credentials, or decide that a request is allowed.

#### REQ-ARCH-003 - Lightweight local security profile [P0]

The first working profile MUST require only:

- the local Python agent or deterministic runner;
- the gateway;
- OPA;
- one sandboxed MCP server;
- the test runner; and
- structured JSONL audit output.

It MUST NOT require a local LLM runtime, GPU, vector database, Keycloak, PostgreSQL, Prometheus, Grafana, Tempo, Loki, or Kubernetes.

#### REQ-ARCH-004 - Cloud inference boundary [P0]

Hosted inference MUST be outbound-only HTTPS from the local harness. The provider MUST receive only the prompt, selected tool definitions, and sanitized tool results needed for that scenario. The provider MUST NOT receive gateway secrets, downstream credentials, bearer tokens, policy bundles, unrestricted audit data, or direct network access to the MCP server.

#### REQ-ARCH-005 - One tool-execution path [P0]

The protected configuration MUST provide exactly one execution path:

```text
Agent or test client -> gateway -> approved MCP server
```

The agent configuration MUST NOT include a second direct connection to the protected server. Provider-native remote MCP and provider-managed tool execution MUST be disabled.

#### REQ-ARCH-006 - Local `stdio` sidecar deployment [P0]

The gateway MUST support a local deployment in which it is launched by an MCP client and communicates with a local upstream MCP server over `stdio`.

```text
MCP client --stdio--> gateway --stdio--> local MCP server
```

The gateway SHOULD create and supervise the upstream process, control its environment variables, and terminate it when the client session ends.

#### REQ-ARCH-007 - Remote gateway deployment [P1]

The gateway MUST support an HTTPS deployment in which clients use Streamable HTTP and the gateway routes to one or more remote or local upstream services.

```text
MCP client --HTTPS--> gateway --HTTPS/stdio--> upstream MCP server
```

This mode does not change the rule that model inference and tool authorization are separate.

#### REQ-ARCH-008 - Safe public-demo deployment [P1]

A public demonstration MAY deploy the gateway and synthetic MCP fixtures to Render, Railway, a small VPS, or another platform. It MUST NOT expose the developer laptop, a real home directory, or real credentials. The public demo SHOULD use synthetic data inside the same controlled cloud environment.

#### REQ-ARCH-009 - Lightweight deployment orchestration [P0]

During early development, services MAY run as normal local processes or in a minimal Docker/Podman Compose profile. The portfolio release SHOULD include a Compose file for reproducibility. Kubernetes, k3s, Nomad, Temporal, and a service mesh MUST NOT be dependencies for the MVP.

#### REQ-ARCH-010 - Provider portability [P1]

The agent harness MUST isolate provider-specific code behind a model adapter. Provider selection, base URL, model identifier, request limits, and feature flags MUST be configuration. Switching from Groq to Cloudflare MUST NOT require changes to gateway authorization logic.

#### REQ-ARCH-011 - Provider features fail closed [P0]

Provider features that execute tools outside the application, including remote MCP, hosted code execution, hosted web search, or compound agent systems, MUST be disabled in security tests. If a provider cannot guarantee local tool calling for a chosen model, that model MUST NOT be used in the protected harness.

### 2.5 Canonical request lifecycle

Every protected request MUST follow this order. The implementation MAY combine internal stages for efficiency, but it MUST preserve the same security semantics.

1. **Connection acceptance:** Enforce TLS where applicable, host and origin rules, body-size limits, connection limits, and request deadlines.
2. **Protocol validation:** Validate the JSON-RPC envelope, MCP protocol version, method, request identifier, and required transport headers.
3. **Header/body consistency:** Where modern MCP headers mirror body fields, parse the body and reject any mismatch before routing or policy evaluation.
4. **Identity establishment:** Validate remote credentials or derive a local configured identity for `stdio`.
5. **Registry resolution:** Resolve the approved upstream server, method, tool, and expected schema revision.
6. **Canonicalization:** Normalize paths, URLs, SQL syntax, identifiers, numeric values, and other policy-relevant arguments using type-aware parsers.
7. **Derived attributes:** Compute policy-safe attributes such as canonical resource, tenant, environment, statement type, destination category, or risk tier.
8. **Pre-authorization:** Ask the policy engine for allow, deny, approval requirement, and other obligations.
9. **Obligation enforcement:** Apply rate limits, body/result caps, timeouts, approval checks, redaction rules, and downstream credential selection.
10. **Upstream invocation:** Forward the request with a unique correlation identifier and the minimum required authority.
11. **Response validation:** Validate the response envelope, content type, size, schema, and prohibited output patterns.
12. **Post-action evidence:** Verify observable side effects where the test or operation supports it.
13. **Audit and telemetry:** Record the decision, policy revision, outcome, latency, and trace linkage without leaking secrets.

If any required stage fails, the request MUST NOT advance to a later stage that can create a protected side effect.

### 2.6 MCP protocol and transport requirements

#### REQ-MCP-001 - Current protocol target [P0]

The primary implementation target MUST be the MCP specification dated July 28, 2026. The implementation MUST support the current stateless protocol model and required request metadata for the methods it protects.

#### REQ-MCP-002 - Compatibility policy [P1]

Compatibility with earlier Streamable HTTP versions SHOULD be implemented through an explicit adapter mode. Legacy HTTP+SSE support MAY be added only for a named client requirement and MUST be disabled by default.

#### REQ-MCP-003 - Streamable HTTP [P0]

The gateway MUST support Streamable HTTP for remote clients and upstream servers. It MUST implement the transport requirements relevant to:

- valid HTTP methods and content types;
- request and notification handling;
- event streaming when required;
- protocol-version validation;
- request correlation;
- transport-specific error handling;
- secure reconnection behavior where applicable.

#### REQ-MCP-004 - Origin and bind-address protection [P0]

For locally hosted HTTP endpoints, the gateway MUST validate the `Origin` header when present, MUST reject unapproved origins, and SHOULD bind to loopback by default. Public bind addresses MUST require explicit configuration and authentication.

#### REQ-MCP-005 - Required MCP headers [P0]

The gateway MUST validate the current `Mcp-Method`, `Mcp-Name`, and `MCP-Protocol-Version` requirements where applicable. It MUST reject a request when a mirrored header conflicts with the parsed JSON-RPC body or declared protocol version.

#### REQ-MCP-006 - `stdio` bridge [P0]

The gateway MUST function as an MCP server on its client-facing `stdin/stdout` and as an MCP client to the configured upstream process. It MUST:

- reserve `stdout` for protocol traffic;
- send diagnostics to `stderr` or structured logs;
- supervise the child process;
- impose startup, request, and shutdown deadlines;
- restrict inherited environment variables;
- expose an explicit allowlist of executable and arguments;
- prevent shell interpolation when launching the process;
- propagate cancellation safely;
- terminate orphaned children.

#### REQ-MCP-007 - JSON-RPC parser hardening [P0]

The gateway MUST reject:

- invalid JSON;
- invalid JSON-RPC versions;
- missing required fields;
- conflicting duplicate fields;
- unsupported batch behavior;
- excessive nesting;
- excessive string or array sizes;
- invalid request identifiers;
- method names outside the supported MCP registry.

Limits MUST be configurable and tested at, below, and above each boundary.

#### REQ-MCP-008 - Capability filtering [P1]

The gateway SHOULD return a client-specific filtered view of servers, tools, prompts, resources, and capabilities. A client MUST NOT discover an object it cannot ever be authorized to use unless a product requirement explicitly permits discoverable-but-denied resources.

#### REQ-MCP-009 - Tool schema fingerprinting [P1]

For each approved tool, the gateway MUST store a normalized schema fingerprint. A changed name, description, input schema, output schema, or security-relevant annotation MUST create a drift event. Depending on policy, the gateway MUST either:

- deny and quarantine the changed tool;
- allow only in shadow mode; or
- require administrator review.

Server-provided annotations MUST be treated as hints, not as authorization policy.

### 2.7 Identity and authentication requirements

#### REQ-AUTH-001 - Remote OIDC/OAuth validation [P1]

For protected remote HTTP access, the gateway MUST validate bearer tokens as an OAuth resource server. Validation MUST include:

- trusted issuer;
- signature and key status;
- exact intended audience or approved resource indicator;
- expiry and not-before time;
- required scopes or claims;
- token type;
- accepted signing algorithms;
- bounded clock skew;
- revocation or short token lifetime where supported.

#### REQ-AUTH-002 - No token passthrough [P0]

The gateway MUST NOT accept a client token and blindly forward it to an upstream service. A token issued for the gateway MUST be used only for gateway authorization. Upstream credentials MUST be separately obtained, exchanged, or selected for the intended upstream audience.

#### REQ-AUTH-003 - Local `stdio` identity [P0]

Each local client configuration MUST assign a principal and client identifier, for example:

```yaml
client_id: cursor-local
principal: akshay
roles: [developer]
transport: stdio
```

The audit record MUST label this as a locally configured identity, not a remotely authenticated identity.

#### REQ-AUTH-004 - Authorization context [P0]

The gateway MUST construct a normalized authorization context containing at least:

- principal identifier or pseudonym;
- authentication method and assurance level;
- client identifier;
- roles and scopes;
- tenant or project where applicable;
- transport;
- source environment;
- target server and environment;
- current policy revision.

#### REQ-AUTH-005 - Step-up authorization [P1]

High-risk actions SHOULD require additional authorization or approval rather than permanently broad scopes. A successful step-up MUST be limited to the exact action or narrow class of actions and MUST expire quickly.

#### REQ-AUTH-006 - Confused-deputy defense [P1]

Any flow in which the gateway obtains credentials for a third-party service MUST bind the authorization to the requesting client, redirect URI, resource, and user consent. The gateway MUST NOT reuse one client's authorization for another client without an explicit, independently authorized relationship.

#### REQ-AUTH-007 - Session and handle binding [P1]

Any stateful handle, continuation token, or session identifier MUST be unguessable and bound to the relevant principal, client, server, expiration time, and authorization context. A handle MUST NOT be transferable between principals by default.

### 2.8 Server registry and routing requirements

#### REQ-REG-001 - Explicit server registry [P0]

The gateway MUST route only to explicitly registered upstream MCP servers. Each registry entry MUST contain:

- stable server identifier;
- display name;
- transport and endpoint or executable;
- approved executable arguments or URL;
- allowed environments;
- expected protocol versions;
- credential strategy;
- connection and request limits;
- approved tools and schema fingerprints;
- owner and review date;
- enabled, shadow, quarantined, or disabled state.

#### REQ-REG-002 - No arbitrary upstream [P0]

A client MUST NOT be able to supply an arbitrary executable, command line, host, port, URL, or credential reference and cause the gateway to connect to it.

#### REQ-REG-003 - Least-privilege downstream credentials [P1]

Credentials MUST be selected by server, tenant, environment, and approved operation where practical. The gateway MUST NOT expose downstream tokens to the model, client, policy input, metrics labels, or normal audit records.

#### REQ-REG-004 - Router isolation [P1]

Connection pools, circuit breakers, rate budgets, and credentials SHOULD be isolated by upstream server and tenant so one failing or abusive server cannot exhaust the full gateway.

### 2.9 Policy engine requirements

#### REQ-POL-001 - Policy as code [P0]

Authorization policy MUST be externalized from request-routing code. The reference implementation SHOULD use Open Policy Agent (OPA) and Rego, running locally as a sidecar or embedded evaluation component with versioned bundles.

#### REQ-POL-002 - Policy input contract [P0]

The gateway MUST send a bounded, documented input object to the policy engine. A representative contract is:

```json
{
  "request": {
    "id": "req_01...",
    "protocol_version": "2026-07-28",
    "transport": "streamable_http",
    "method": "tools/call"
  },
  "principal": {
    "id": "user-123",
    "auth_method": "oidc",
    "assurance": "verified",
    "roles": ["developer"],
    "scopes": ["mcp:tools:call"],
    "tenant": "acme"
  },
  "client": {
    "id": "cursor-managed",
    "class": "interactive_agent"
  },
  "target": {
    "server": "filesystem-dev",
    "environment": "development",
    "tool": "read_file",
    "schema_hash": "sha256:..."
  },
  "resource": {
    "type": "file",
    "canonical_path": "/workspace/docs/readme.md",
    "root": "/workspace",
    "classification": "internal"
  },
  "arguments": {
    "hash": "sha256:...",
    "derived": {
      "operation": "read",
      "estimated_risk": "R1"
    }
  },
  "context": {
    "policy_revision": "git:abc123",
    "approval_id": null,
    "taint": ["model_generated"]
  }
}
```

Raw secrets, full tokens, and unnecessary prompt text MUST NOT be included when a derived attribute or hash is sufficient.

#### REQ-POL-003 - Policy result contract [P0]

The policy result MUST be structured and MUST support:

```json
{
  "decision": "allow",
  "reason_code": "FILESYSTEM_SCOPED_READ",
  "risk_tier": "R1",
  "policy_revision": "git:abc123",
  "obligations": {
    "timeout_ms": 3000,
    "max_response_bytes": 1048576,
    "max_rows": null,
    "redactions": [],
    "rate_limit_bucket": "fs-read-user",
    "approval_required": false
  }
}
```

The result MUST include a stable machine-readable reason code. User-facing explanations MAY be separately generated from the reason code.

#### REQ-POL-004 - Decision precedence [P0]

Policy precedence MUST be documented. The reference precedence is:

1. Explicit prohibited action.
2. Explicit deny.
3. Required approval or step-up.
4. Explicit allow with obligations.
5. Default deny.

An allow rule MUST NOT override an explicit prohibition unless a narrowly scoped break-glass mechanism is separately designed and audited.

#### REQ-POL-005 - Versioning and provenance [P0]

Every decision MUST identify the active policy revision. Policies MUST be stored in version control, reviewed, linted, tested, and deployed as immutable bundles or artifacts. Production policy changes SHOULD require signed commits or signed release artifacts.

#### REQ-POL-006 - Policy unit tests [P0]

Each allow, deny, and approval rule MUST include positive and negative tests. Tests MUST include boundary values and at least one bypass attempt.

#### REQ-POL-007 - Shadow and simulation mode [P1]

The gateway MUST support evaluating a candidate policy without enforcing it. Shadow results MUST be clearly distinguished from enforced decisions and MUST NOT alter the real request result. Administrators SHOULD be able to replay recorded sanitized requests against a candidate policy before promotion.

#### REQ-POL-008 - Policy outage behavior [P0]

If the active policy cannot be loaded or evaluated, protected operations MUST be denied. A small, hard-coded health or emergency-deny policy MAY remain available.

### 2.10 Generic input and resource guardrails

#### REQ-GUARD-001 - Strict schema validation [P0]

Tool arguments MUST be validated against the approved schema before policy evaluation and again before forwarding if any transformation occurs. Unknown fields SHOULD be rejected by default for high-risk tools.

#### REQ-GUARD-002 - Canonicalization before policy [P0]

Policy MUST evaluate canonical values, not raw ambiguous text. The system MUST retain a hash of the original and canonical representations for investigation without necessarily storing the full sensitive value.

#### REQ-GUARD-003 - Parser-based inspection [P0]

Security-critical structured inputs MUST be parsed with a grammar-aware or type-aware parser. Regular expressions alone MUST NOT be the primary defense for SQL, URLs, file paths, or shell commands.

#### REQ-GUARD-004 - Request limits [P0]

The gateway MUST enforce configurable limits for:

- request bytes;
- JSON depth;
- number of fields and array elements;
- string length;
- tool-call duration;
- concurrent requests;
- response bytes;
- streamed-event count and duration.

#### REQ-GUARD-005 - Risk classification [P0]

Each action MUST be assigned one of the following minimum tiers:

| Tier | Meaning | Default handling |
|---|---|---|
| R0 | Public or metadata-only, no protected side effect | Allow only by explicit policy |
| R1 | Scoped read of non-sensitive data | Allow by explicit policy with limits |
| R2 | Reversible write or low-impact external action | Allow by explicit policy; stronger logging and rate limits |
| R3 | Destructive, production, secret-bearing, high-value, or broad-export action | Human approval or step-up required |
| R4 | Prohibited action or unsupported safety boundary | Deny |

The tool's self-declared annotations MAY influence an initial review but MUST NOT be the sole source of risk classification.

### 2.11 Filesystem guardrail requirements

#### REQ-FS-001 - Approved roots [P0]

Filesystem access MUST be constrained to configured roots. Read, create, overwrite, rename, and delete permissions MUST be independently controllable per root and principal.

#### REQ-FS-002 - Canonical path resolution [P0]

Before authorization, the gateway MUST:

- decode supported encodings exactly once using a documented rule;
- reject malformed encodings and null bytes;
- resolve `.` and `..` segments;
- resolve symlinks or platform-equivalent reparse points;
- normalize case according to the actual filesystem semantics;
- verify that the final real path remains within an approved root.

Authorization MUST apply to the final resolved target, not only the supplied string.

#### REQ-FS-003 - Sensitive paths [P0]

The default policy MUST deny access to sensitive locations including SSH keys, cloud credentials, environment-secret files, browser profiles, package-manager tokens, operating-system configuration, and gateway configuration unless an explicit test fixture requires access.

#### REQ-FS-004 - Sandbox mounts [P0]

The reference filesystem server MUST run in a container or process sandbox with only the intended test directory mounted. It MUST NOT receive the user's home directory or host root as a broad mount.

#### REQ-FS-005 - Safe writes [P1]

Where possible, file writes SHOULD use atomic replacement, size limits, allowed extensions or content types, and optional backup or versioning. The policy MUST distinguish create, append, overwrite, rename, and delete.

#### REQ-FS-006 - Required attack tests [P0]

The harness MUST test plain traversal, encoded traversal, double encoding, symlink escape, absolute-path escape, case variants, path separators for supported operating systems, and race conditions where practical.

### 2.12 SQL guardrail requirements

#### REQ-SQL-001 - AST parsing [P0]

SQL MUST be parsed using a dialect-aware parser such as SQLGlot or a database-native parser. The gateway MUST classify statement type, referenced schemas, tables, columns, functions, and write behavior.

#### REQ-SQL-002 - One statement [P0]

The default policy MUST permit no more than one parsed statement per tool call. Stacked statements and parser ambiguities MUST be denied.

#### REQ-SQL-003 - Statement and object allowlists [P0]

Policies MUST independently control:

- `SELECT`, `INSERT`, `UPDATE`, `DELETE`, DDL, and administrative statements;
- schemas, tables, and columns;
- tenant predicates;
- functions and extensions;
- export or file-writing features.

DDL, privilege changes, extension loading, and host-file access MUST be R4 in the MVP.

#### REQ-SQL-004 - Database-side least privilege [P0]

Read-only demonstrations MUST use a read-only database role. The gateway's SQL parser MUST be a second layer, not a replacement for database permissions.

#### REQ-SQL-005 - Query limits [P0]

The gateway MUST enforce query deadlines and maximum returned rows or bytes. The database SHOULD enforce statement timeouts and resource quotas as an independent control.

#### REQ-SQL-006 - Tenant isolation [P1]

For multi-tenant examples, policy MUST verify the tenant context and either enforce a safe tenant predicate or use a database role/view that cannot access other tenants. String concatenation of tenant filters is not acceptable.

#### REQ-SQL-007 - Required attack tests [P0]

Tests MUST include comments, nested queries, common table expressions, mixed case, dialect-specific syntax, stacked statements, data-modifying CTEs, time-based functions, large result generation, and attempts to access restricted objects.

### 2.13 Outbound HTTP and fetch guardrail requirements

#### REQ-NET-001 - Destination allowlist [P1]

Outbound HTTP tools MUST be limited by scheme, hostname, port, path class, and environment. Plain HTTP SHOULD be denied except for isolated local tests.

#### REQ-NET-002 - SSRF protection [P1]

The gateway or a dedicated egress proxy MUST reject loopback, private, link-local, multicast, reserved, and cloud metadata destinations unless explicitly required by a test. It MUST validate both the supplied hostname and resolved addresses.

#### REQ-NET-003 - DNS and redirect validation [P1]

The system MUST guard against DNS rebinding and redirect escape. Each redirect target and effective destination MUST be revalidated. Redirect count MUST be bounded.

#### REQ-NET-004 - Credential isolation [P1]

Client or gateway credentials MUST NOT be forwarded to arbitrary destinations. Authorization headers, cookies, and client certificates MUST be attached only by an approved credential strategy for the intended origin.

#### REQ-NET-005 - Content limits [P1]

The gateway MUST bound response size, decompressed size, duration, content type, and streaming length. Unsupported content types SHOULD be rejected before they enter the model context.

### 2.14 Shell and code-execution guardrail requirements

#### REQ-EXEC-001 - No general host shell in MVP [P0]

The MVP MUST NOT expose a generic host shell or arbitrary command-execution tool.

#### REQ-EXEC-002 - Sandboxed execution only [P2]

If code execution is later added, it MUST run in an ephemeral sandbox with:

- no privileged mode;
- non-root user;
- read-only base filesystem;
- explicit temporary writable volume;
- no host socket or broad host mount;
- no network by default;
- CPU, memory, process, and time limits;
- seccomp/AppArmor/SELinux or an equivalent isolation profile;
- a fixed command or interpreter allowlist;
- argument arrays rather than shell interpolation.

#### REQ-EXEC-003 - Template-based commands [P2]

Operational commands SHOULD use predefined command templates with typed arguments. Free-form command text MUST remain prohibited unless the sandbox threat model is separately reviewed.

### 2.15 Business-action guardrail requirements

#### REQ-BIZ-001 - Domain attributes [P1]

The custom enterprise MCP server MUST expose actions that demonstrate authorization beyond file paths and SQL. Policy inputs SHOULD include operation, tenant, environment, object owner, amount, currency, reversibility, and data classification.

#### REQ-BIZ-002 - Example authorization rules [P1]

The reference policies MUST support examples such as:

- Support agent can read customers within the assigned tenant.
- Support agent can issue a refund up to a configured amount.
- Larger refunds require approval.
- Customer deletion and bulk export are denied for support agents.
- Production operations require stronger identity and approval than staging.

#### REQ-BIZ-003 - Idempotency [P1]

External write actions SHOULD require an idempotency key. Replayed requests MUST not create duplicate refunds, notifications, or records.

### 2.16 Human approval requirements

#### REQ-APPROVAL-001 - Exact action binding [P1]

An approval MUST be bound to:

- principal;
- client;
- target server and tool;
- normalized argument hash;
- target environment;
- policy revision;
- risk tier;
- expiration time;
- one-time nonce.

Any material argument change after approval MUST invalidate it and trigger a new policy evaluation.

#### REQ-APPROVAL-002 - Separation from the model [P1]

The requesting model MUST NOT approve its own action. Approval MUST come from an independently authenticated human or explicitly authorized service account.

#### REQ-APPROVAL-003 - Safe presentation [P1]

The approval interface MUST display a structured, canonical summary of the action. Untrusted tool descriptions or arguments MUST be visually distinguished and escaped so they cannot masquerade as trusted instructions.

#### REQ-APPROVAL-004 - Timeout and replay [P1]

Approvals MUST expire, MUST be single use by default, and MUST be recorded in the audit trail. Missing, expired, reused, mismatched, or revoked approvals MUST cause denial.

#### REQ-APPROVAL-005 - Initial interface [P1]

The first approval interface MAY be a CLI or small authenticated web page. Building a complex workflow UI is not required before the security token and binding semantics are tested.

### 2.17 Prompt-injection, hosted-model, and agent guardrail requirements

#### REQ-MODEL-GUARD-001 - Model output is a request, not authority [P0]

A model-generated tool call MUST be treated exactly like any other untrusted request. The model's explanation, confidence, chain-of-thought-like text, or claim of user consent MUST not change authorization unless represented by a separately verified external fact.

#### REQ-MODEL-GUARD-002 - Local tool calling only [P0]

The provider MUST return structured tool-call proposals to the local application. The local application MUST decide whether to send each proposal to the gateway. Provider-native remote MCP, provider-managed connectors, and provider-side tool execution MUST be disabled.

#### REQ-MODEL-GUARD-003 - Built-in provider tools disabled [P0]

Browser search, visit-website, code execution, compound systems, and similar provider-built-in tools MUST be disabled during gateway security evaluations. These features create execution paths that the gateway cannot fully mediate.

#### REQ-MODEL-GUARD-004 - Untrusted tool results [P0]

Text returned by a tool or resource MUST be labeled as untrusted content in the agent harness. The harness SHOULD prevent tool output from being concatenated into trusted system instructions.

#### REQ-MODEL-GUARD-005 - Output sanitization before cloud return [P0]

A tool result MUST pass size limits, schema filtering, secret-pattern checks, and configured redaction before it is returned to a hosted model. A result that cannot be safely sanitized MUST be replaced by a controlled error or minimal summary.

#### REQ-MODEL-GUARD-006 - Context and tool minimization [P0]

The harness SHOULD provide each model only the tool schemas and context required for the current scenario. It MUST NOT send gateway secrets, identity-provider secrets, raw downstream credentials, unrestricted audit records, unrelated files, or the complete server registry.

#### REQ-MODEL-GUARD-007 - Run budgets [P0]

Every agent run MUST have configurable hard limits. The initial defaults SHOULD be:

```text
maximum model calls per scenario:          5
maximum MCP tool calls per scenario:       8
maximum identical repeated tool calls:     2
maximum denied-action retries:             2
maximum wall-clock time:                   60 seconds
maximum input and output tokens:            provider/model specific
maximum estimated cost per scenario:        configured by test profile
```

Exceeding a budget MUST stop the run with a controlled, auditable outcome.

#### REQ-MODEL-GUARD-008 - Denial-loop protection [P0]

When a model repeatedly attempts the same denied action with cosmetic argument changes, the harness SHOULD stop the scenario or escalate to approval rather than permit unlimited probing or consume unbounded quota.

#### REQ-MODEL-GUARD-009 - Taint propagation [P1]

The harness SHOULD tag values originating from user text, tool output, external web content, secrets, and model generation. High-risk follow-on actions SHOULD be denied or require approval when their critical arguments originate only from untrusted content.

#### REQ-MODEL-GUARD-010 - Optional semantic classifier [P2]

A guard model, including `openai/gpt-oss-safeguard-20b`, MAY identify likely prompt injection, secret exposure, or function-call hallucination. Its output MUST be advisory, recorded with provider and model version, and combined with deterministic policy. A classifier failure MUST NOT cause a protected action to be allowed.

#### REQ-MODEL-GUARD-011 - Provider response validation [P0]

The harness MUST validate tool names, argument JSON, schema conformance, tool-call count, and output size even when the provider advertises function calling or JSON Schema support. Structured output improves reliability but does not replace local validation.

#### REQ-MODEL-GUARD-012 - Provider failure cannot create execution [P0]

A timeout, malformed response, rate limit, deprecation error, provider outage, or fallback failure MUST end the model turn without executing any unverified tool call. The gateway remains independently testable when all model providers are unavailable.

### 2.18 Response and output guardrail requirements

#### REQ-OUT-001 - Response envelope validation [P0]

The gateway MUST validate that the upstream response is valid for the request identifier and expected MCP/JSON-RPC shape. Unknown, malformed, or mismatched responses MUST become controlled errors.

#### REQ-OUT-002 - Maximum output [P0]

Each tool and risk tier MUST have a maximum response size. Streaming responses MUST have a maximum duration and event count.

#### REQ-OUT-003 - Secret redaction [P1]

The gateway SHOULD support deterministic redaction of known secret patterns and registered sensitive fields. Redaction MUST happen before output is sent to a model and before normal logs are written.

#### REQ-OUT-004 - Structured result filtering [P1]

For structured results, policy MAY remove fields or rows the principal cannot receive. The filter MUST be schema-aware and tested; ad hoc text substitution is insufficient for structured data.

#### REQ-OUT-005 - No false success [P0]

A denied, timed-out, partially failed, or invalid upstream operation MUST not be reported as successful. Error responses SHOULD include a stable reason code without revealing sensitive policy details.

### 2.19 Audit and evidence requirements

#### REQ-AUDIT-001 - One audit event per decision [P0]

Every allowed, denied, approval-required, failed, and shadow decision MUST create an audit event. The event MUST contain at least:

- timestamp;
- gateway request identifier;
- trace identifier;
- principal pseudonym or identifier;
- authentication method;
- client identifier;
- transport;
- target server;
- MCP method and tool name;
- schema fingerprint;
- normalized argument hash and safe derived attributes;
- decision and reason code;
- risk tier;
- obligations;
- policy revision and policy decision identifier;
- approval identifier where relevant;
- gateway, policy, and upstream latency;
- upstream status;
- response size;
- final outcome.

#### REQ-AUDIT-002 - Sensitive-data minimization [P0]

Audit records MUST NOT contain raw bearer tokens, private keys, passwords, full prompts, or arbitrary tool output by default. Sensitive request values SHOULD be represented by hashes, classifications, or approved redacted excerpts.

#### REQ-AUDIT-003 - Tamper evidence [P2]

A later release SHOULD support append-only storage, signed audit batches, write-once retention, or another mechanism that makes deletion and modification detectable.

#### REQ-AUDIT-004 - Correlation [P0]

A user or tester MUST be able to correlate one scenario with its policy decision, trace, gateway log, upstream operation, and observed side effect using a stable request identifier.

#### REQ-AUDIT-005 - Retention [P1]

Retention MUST be configurable by event class and environment. The lightweight laptop profile SHOULD default to 7 days of sanitized JSONL audit data or a documented size cap, whichever is reached first. A deployed demo MAY retain up to 30 days when storage, privacy, and deletion controls have been reviewed.

### 2.20 Observability requirements

#### REQ-OBS-001 - Vendor-neutral instrumentation [P0]

The gateway MUST instrument request stages through the OpenTelemetry API/SDK or an equivalent vendor-neutral abstraction. The lightweight laptop profile MAY use in-process, console, file, or test exporters and MUST NOT require a continuously running collector. An OpenTelemetry Collector and remote backend are P1 deployment features so observability can be added without rewriting gateway instrumentation.

#### REQ-OBS-002 - Required metrics [P0]

At minimum, expose:

```text
mcp_gateway_requests_total{decision,transport,server,method,risk_tier}
mcp_gateway_request_duration_seconds
mcp_gateway_added_overhead_seconds
mcp_gateway_policy_duration_seconds
mcp_gateway_upstream_duration_seconds
mcp_gateway_auth_failures_total{reason}
mcp_gateway_rate_limit_hits_total{bucket}
mcp_gateway_approval_total{result,risk_tier}
mcp_gateway_schema_drift_total{server}
mcp_gateway_upstream_errors_total{server,error_class}
mcp_gateway_audit_failures_total{reason}
```

Histogram buckets or native histograms MUST support p50, p95, and p99 analysis for request, policy, upstream, and added-overhead latency.

#### REQ-OBS-003 - Bounded cardinality [P0]

Metric labels MUST be bounded. User identifiers, request identifiers, prompts, full paths, arbitrary URLs, SQL strings, and tool arguments MUST NOT be metric labels. Detailed request context belongs in protected traces or audit logs.

#### REQ-OBS-004 - Trace stages [P0]

A request trace SHOULD include spans for:

- transport acceptance;
- protocol validation;
- identity validation;
- registry lookup;
- argument canonicalization;
- policy evaluation;
- approval verification;
- upstream connection and invocation;
- response validation;
- audit persistence.

#### REQ-OBS-005 - Dashboards [P1]

When a dashboard profile is enabled, the reference dashboard MUST show:

- request volume;
- allow, deny, and approval rates;
- block reasons;
- p50/p95/p99 gateway overhead;
- policy latency;
- upstream latency and errors;
- schema-drift events;
- authentication failures;
- top bounded server/tool categories;
- current test-run security and false-positive results.

#### REQ-OBS-006 - Health and readiness [P0]

Liveness MUST indicate that the process is running. Readiness MUST remain false until required policy, registry, credentials, audit sink, and upstream dependencies required by the configured mode are usable.

### 2.21 Reliability and performance requirements

#### REQ-REL-001 - Timeouts [P0]

Connection, policy, approval, upstream, streaming, and total-request deadlines MUST be explicit. No protected call may wait indefinitely.

#### REQ-REL-002 - Cancellation [P0]

Client cancellation SHOULD propagate to the upstream request where safe. The audit event MUST distinguish canceled, timed out, failed, and denied requests.

#### REQ-REL-003 - Circuit breakers [P1]

Repeated upstream failures SHOULD open a per-server circuit breaker. A failed server MUST not exhaust gateway worker capacity.

#### REQ-REL-004 - Backpressure [P1]

The gateway MUST bound queues and concurrent requests. When overloaded, it SHOULD reject early with a controlled response rather than consume unbounded memory.

#### REQ-REL-005 - Reference performance gates [P1]

On the documented reference machine and a local network, without a human approval or model classifier in the critical path, the portfolio release SHOULD meet:

- p95 added gateway overhead at or below 15 ms at 100 requests per second;
- p99 added gateway overhead at or below 30 ms at 100 requests per second;
- zero authorization bypasses under the deterministic P0 security corpus;
- 100 percent audit-event completeness for completed decisions;
- at least 98 percent legitimate-request pass rate after the legitimate corpus is stabilized;
- no unbounded growth during a 60-minute soak test.

These are design targets, not claimed results. The final report MUST publish the actual environment and observed numbers even if a target is missed.

### 2.22 Administrative and control-plane requirements

#### REQ-ADMIN-001 - Separate permissions [P1]

Permissions to call tools, approve high-risk actions, edit policy, register servers, read audit data, and manage secrets MUST be separate roles.

#### REQ-ADMIN-002 - Minimal management API [P1]

The management surface SHOULD provide authenticated endpoints or commands for:

- health and readiness;
- active policy revision;
- server registry listing;
- schema-drift review;
- approval creation and revocation;
- sanitized audit search;
- policy simulation;
- configuration diagnostics.

It MUST NOT expose raw secrets or unrestricted arbitrary policy execution.

#### REQ-ADMIN-003 - Safe configuration [P0]

Configuration MUST have a validated schema, safe defaults, environment separation, and startup checks. Unknown fields SHOULD fail startup rather than being silently ignored.

#### REQ-ADMIN-004 - Break-glass [P2]

If break-glass access is implemented, it MUST require strong authentication, a narrow expiration, explicit reason, independent alerting, and complete audit. It MUST not be part of the MVP.

### 2.23 Privacy, secrets, cloud-provider, and supply-chain requirements

#### REQ-SEC-001 - Secrets management [P0]

Secrets MUST be supplied through environment injection, mounted secret files, or a secrets manager. They MUST not be committed to the repository, embedded in images, returned to clients, placed in prompts, or printed in logs.

The first provider keys are expected as environment variables such as:

```text
GROQ_API_KEY
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

The repository MUST include `.env.example` with placeholders and MUST ignore `.env` and local secret files.

#### REQ-SEC-002 - Synthetic cloud-test data [P0]

All hosted-model tests MUST use synthetic fixtures. Real SSH keys, cloud credentials, browser profiles, password databases, personal documents, production database rows, customer records, and real environment files MUST NOT be mounted into the test MCP server or sent to a hosted model.

#### REQ-SEC-003 - Provider data controls [P0]

The project MUST document the provider's current retention behavior and the account setting used for the test. When the provider offers zero-data-retention or equivalent controls, the project SHOULD enable them. A retention setting does not remove the requirement for synthetic data and output redaction.

#### REQ-SEC-004 - Model-provider API-key isolation [P0]

The model-provider key MUST be available only to the local agent adapter. The MCP server, OPA, untrusted test fixtures, model prompts, and normal audit events MUST not receive the key. Provider keys SHOULD be scoped to a dedicated project or account with usage limits where supported.

#### REQ-SEC-005 - Provider egress allowlist [P1]

The local harness SHOULD restrict outbound model traffic to configured provider endpoints. Redirects and proxy settings MUST not silently send model requests or authorization headers to another origin.

#### REQ-SEC-006 - Data minimization [P0]

Prompts, arguments, tool output, and identity attributes MUST be collected only when necessary for an explicit function. The documentation MUST state what is sent to each provider, what is stored locally, where it is stored, how long it is retained, and who can read it.

#### REQ-SEC-007 - Audit minimization for model traffic [P0]

Normal audit events SHOULD record provider, model identifier, token usage, cost estimate, request identifier, and hashes or classifications of transmitted content. They MUST NOT store complete prompts or tool results by default.

#### REQ-SEC-008 - Dependency scanning [P0]

CI MUST run dependency and container-image vulnerability scans. The project SHOULD generate a software bill of materials for releases.

#### REQ-SEC-009 - Secret scanning [P0]

The repository MUST run automated secret scanning in CI and SHOULD enable pre-commit scanning.

#### REQ-SEC-010 - Reproducible builds [P1]

Python dependencies and container base images MUST be pinned. Release builds SHOULD produce provenance and signed artifacts or images.

#### REQ-SEC-011 - Non-root containers [P0]

Gateway, policy engine, database, and test servers SHOULD run as non-root users with read-only filesystems where practical and with only required ports and volumes.

#### REQ-SEC-012 - Localhost-first networking [P0]

Development services SHOULD bind to `127.0.0.1` by default. OPA, the administration API, local MCP HTTP endpoints, and future database or identity services MUST NOT be exposed to the LAN or public Internet without an explicit deployment profile.

### 2.24 Evaluation harness requirements

#### 2.24.1 Purpose

The harness exists to answer three independent questions:

1. Does the gateway enforce the stated security requirements?
2. What latency, throughput, reliability, and usability cost does that enforcement add?
3. How do different hosted models behave when placed in front of the same deterministic enforcement boundary?

A capable model MUST NOT be allowed to hide a weak gateway, and a weak model MUST NOT make a strong gateway appear better than it is.

#### 2.24.2 Finalized harness architecture

```text
                         SCENARIO CORPUS
              deterministic + fuzzed + agent-oriented
                              |
             +----------------+----------------+
             |                                 |
             v                                 v
   DETERMINISTIC SECURITY MODE          AGENT BEHAVIOR MODE
   no model API required                local orchestrator
             |                                 |
             |                                 v
             |                      Groq or Cloudflare model
             |                                 |
             |                         proposed tool call
             +----------------+----------------+
                              |
                              v
                        MCP client adapter
                              |
              +---------------+----------------+
              |                                |
              v                                v
        DIRECT BASELINE                  PROTECTED MODE
        isolated lab only                gateway -> OPA -> MCP
              |                                |
              +---------------+----------------+
                              |
                              v
                side-effect + audit + trace oracle
                              |
                              v
              security, behavior, cost, and latency report
```

#### REQ-HARNESS-001 - Separate test layers [P0]

The harness MUST separate:

1. **Protocol conformance tests:** Raw MCP and JSON-RPC requests independent of a model.
2. **Deterministic security tests:** Known allowed and malicious cases with exact expected decisions and side effects.
3. **Agent-driven adversarial tests:** Hosted models receive goals, malicious content, or prompt injections and may choose tool calls.
4. **Performance tests:** Gateway overhead measured without model inference.
5. **Provider resilience tests:** Rate limits, timeouts, invalid responses, fallback behavior, and model deprecation handling.
6. **Chaos tests:** Slow upstream, policy outage, malformed stream, connection disruption, and audit failure.

#### REQ-HARNESS-002 - Model-free security core [P0]

All P0 gateway authorization and canonicalization tests MUST run without a model API key. Pull-request CI MUST not depend on Groq, Cloudflare, or another hosted model.

#### REQ-HARNESS-003 - Direct and protected modes [P0]

Each deterministic scenario SHOULD be executable in:

- `direct`: the scripted client calls the isolated upstream server;
- `protected`: the same request passes through the gateway; and
- `shadow`: policy is evaluated without changing an otherwise allowed isolated test flow.

Direct mode exists only to demonstrate risk in synthetic fixtures. It MUST NOT be enabled in the protected client configuration.

#### REQ-HARNESS-004 - No LLM in gateway-overhead benchmark [P0]

Gateway overhead MUST be calculated using the same scripted request in direct and protected modes:

```text
gateway added overhead = protected round-trip latency - direct round-trip latency
```

Cloud-model generation time, Internet latency, and agent deliberation MUST be reported separately.

#### REQ-HARNESS-005 - Deterministic side-effect oracle [P0]

A scenario MUST check both the gateway decision and the protected system's actual state. Examples include:

- whether a prohibited file was read, changed, created, or deleted;
- whether a SQL row or schema object changed;
- whether an outbound request reached a controlled sink;
- whether a mock refund or export record was created;
- whether the upstream MCP server observed the denied call.

A denial message without side-effect verification is insufficient evidence.

#### REQ-HARNESS-006 - Scenario schema [P0]

Every scenario MUST define or derive:

```yaml
id: fs-traversal-001
test_layer: deterministic
principal: intern
transport: stdio
server: filesystem
tool: read_file
input: /workspace/public/../../confidential/fake_api_keys.txt
expected_decision: deny
expected_reason: path_outside_allowed_root
expected_side_effect: none
risk_tier: high
cloud_data_class: synthetic
max_model_calls: 0
max_tool_calls: 1
```

Agent scenarios MUST additionally record provider, model identifier, system prompt revision, expected task behavior, token limits, cost limit, and whether fallback is allowed.

#### REQ-HARNESS-007 - Sandboxed fixtures [P0]

The initial fixture MUST be an isolated synthetic directory such as:

```text
sandbox/
  public/
    documentation.txt
  confidential/
    fake_salaries.csv
    fake_api_keys.txt
  production/
    fake_config.env
```

The filesystem MCP server MUST see only this fixture, never the developer's home directory.

#### REQ-HARNESS-008 - Attack corpus [P0]

The repository MUST maintain versioned malicious and legitimate corpora. The P0 corpus MUST include path traversal, encoded traversal, symlink escape, unknown tools, changed schemas, malformed JSON-RPC, oversized requests, repeated denied calls, invalid identities, and audit failure behavior.

#### REQ-HARNESS-009 - Property-based testing [P0]

Hypothesis or an equivalent open-source framework MUST generate path, encoding, identifier, numeric-boundary, and JSON-structure variants. Generated cases MUST be reproducible from a recorded seed.

#### REQ-HARNESS-010 - Protocol conformance tooling [P0]

The project SHOULD use the official MCP Inspector or SDK-based clients for interactive protocol validation, while raw protocol tests remain automated in the repository.

#### REQ-HARNESS-011 - Agent runtime [P0]

Use **PydanticAI** for the local agent under test and **Inspect AI** for reproducible evaluation sets, scoring, limits, and run records. The PydanticAI agent MUST connect to the gateway rather than the protected upstream server.

#### REQ-HARNESS-012 - Cloud-model matrix [P1]

The release evaluation SHOULD run a stable scenario subset with:

- `openai/gpt-oss-20b` as the primary model;
- `qwen/qwen3.6-27b` as an independent model family;
- `openai/gpt-oss-120b` for an optional higher-capability comparison; and
- `@cf/openai/gpt-oss-20b` as a provider-fallback validation.

Security pass/fail MUST come from gateway and side-effect oracles, not from an LLM judge.

#### REQ-HARNESS-013 - Quota and cost controls [P0]

The harness MUST read provider rate-limit responses where available, maintain per-run token and request totals, estimate cost, and stop before a configured hard budget. Free-tier limits MUST be treated as variable configuration rather than permanent guarantees.

#### REQ-HARNESS-014 - Caching and replay [P1]

For development, model responses MAY be cached by a hash of provider, model, messages, tool definitions, and sampling configuration. Cached output MUST be clearly identified and MUST NOT replace live calls in the final cross-model report. Deterministic gateway replay SHOULD reuse recorded tool calls without paying for inference.

#### REQ-HARNESS-015 - Provider fallback semantics [P1]

A provider fallback MAY occur only before a tool call is accepted for execution. The run log MUST record each attempted provider and model. A fallback MUST NOT silently change the expected model in a reproducibility report.

#### REQ-HARNESS-016 - Load and chaos [P1]

Load tests SHOULD use k6, Locust, or another open-source tool against the gateway without model inference. Chaos tests MUST cover OPA outage, upstream timeout, model-provider timeout, malformed model tool call, audit-sink failure, and client cancellation.

#### REQ-HARNESS-017 - Required security metrics [P0]

Report at least:

```text
malicious scenarios attempted
malicious scenarios blocked
prohibited side effects observed
security enforcement rate
policy bypass rate
legitimate scenarios attempted
legitimate scenarios allowed
false-positive rate
unknown or indeterminate outcomes
audit completeness
```

#### REQ-HARNESS-018 - Required model-behavior metrics [P1]

Report separately:

```text
task completion rate
correct tool-selection rate
unsafe tool-attempt rate
denied-action recovery rate
repeated-denial rate
malformed tool-call rate
average model calls per scenario
average tool calls per scenario
input and output tokens
estimated inference cost
provider errors and fallbacks
```

#### REQ-HARNESS-019 - Required performance metrics [P0]

Report p50, p95, and p99 for direct latency, protected latency, gateway overhead, policy time, upstream time, and audit time. Model latency MUST appear in a separate agent-performance table.

#### REQ-HARNESS-020 - CI cadence [P0]

- **Every pull request:** unit, policy, protocol, deterministic integration, property, secret-scan, and dependency-scan tests with no cloud model.
- **Manual or scheduled low-volume run:** five to twenty hosted-model scenarios within free quota.
- **Release:** complete deterministic corpus, selected live cross-model scenarios, load test, soak test, container scan, SBOM, and benchmark report.

#### REQ-HARNESS-021 - Reproducibility [P0]

Each report MUST include commit SHA, policy revision, gateway version, OS, CPU, memory, Python version, container versions, scenario-corpus version, provider, model identifier, provider system fingerprint when available, sampling configuration, tool-schema fingerprint, token usage, request count, account tier, data-control setting, and test timestamp.

### 2.25 Open-source orchestrator requirements and selection

#### 2.25.1 Role of the orchestrator

The orchestrator is used to build the agent under test, coordinate multi-step scenarios, pause for approval, communicate with the hosted model, and collect evaluation traces. It is not the gateway's authorization mechanism.

The orchestrator MUST support or permit:

- Python integration;
- an MCP client or custom tool adapter;
- explicit control flow;
- typed tool inputs and outputs where possible;
- deterministic test hooks;
- human-in-the-loop interruption;
- model-provider portability;
- per-run token, request, time, and cost limits;
- open-source licensing suitable for a public portfolio project; and
- exportable run records.

#### 2.25.2 Candidate matrix

| Framework | Best fit | Strengths for this project | Main caution | License |
|---|---|---|---|---|
| **PydanticAI** | Finalized default local agent harness | Python-native typed tools, Groq integration, MCP client support, provider portability, approvals, usage limits, and testability | Its provider-native MCP option must remain disabled; use the locally controlled gateway path | MIT |
| **Inspect AI** | Finalized evaluation and red-team runtime | Reproducible tasks, scorers, MCP tools, sandboxes, limits, caching, concurrency control, and rich run logs | It evaluates agents; it is not the gateway or production control plane | MIT |
| **LangGraph** | Durable branching workflows | Explicit graphs, persistence, replay, interrupts, and human-in-the-loop | More state and orchestration complexity than the initial harness requires | MIT |
| **LlamaIndex Workflows** | Event-driven data and RAG workflows | Typed events, workflow steps, retries, streaming, and broad data integration | RAG-oriented abstractions are not needed for the first security lab | MIT |
| **Haystack** | Pipeline-heavy retrieval and agent experiments | Mature components, tools, pipelines, and evaluation ecosystem | Less directly focused on MCP security mediation | Apache-2.0 |
| **mcp-agent** | MCP-native workflow experiments | MCP-first abstractions and optional durable workflows | Compatibility with the exact protocol revision must be verified before adoption | Apache-2.0 |

#### REQ-ORCH-001 - Finalized initial choice [P0]

Use **PydanticAI** for the custom agent and **Inspect AI** for evaluation. Do not maintain two full agent implementations in the MVP.

#### REQ-ORCH-002 - Local orchestration, cloud inference [P0]

The orchestrator MUST run locally or in project-controlled infrastructure. Only inference is delegated to the hosted provider. Tool-call parsing, gateway invocation, denial handling, result sanitization, and run limits remain in the local harness.

#### REQ-ORCH-003 - LangGraph decision point [P1]

Adopt LangGraph only when scenarios require durable long-running state, complex branching approvals, resumability, or replay that becomes awkward in the initial PydanticAI runner.

#### REQ-ORCH-004 - Infrastructure orchestration [P0]

Use normal local processes or a minimal Docker/Podman Compose file for the gateway, OPA, and test MCP server. Add PostgreSQL, Keycloak, and telemetry services only in named profiles. Do not introduce Kubernetes or a service mesh before measuring a real need.

#### REQ-ORCH-005 - No provider-native MCP [P0]

When the selected orchestrator supports provider-native MCP, that capability MUST remain off for protected tests. The orchestrator must receive proposed function calls and route them through the local gateway itself.

### 2.26 Hosted open-weight model requirements and selection

#### 2.26.1 Terminology and model roles

The finalized baseline uses **cloud-hosted open-weight models**. The model weights are openly available under their respective terms, while the inference platform is a hosted commercial service.

Models may serve four separate roles. Results MUST not conflate them:

1. **Agent under test:** Chooses whether and how to call MCP tools.
2. **Adversarial case generator:** Mutates prompts, arguments, and attack narratives.
3. **Advisory guard model:** Flags possible prompt injection, secret exposure, or hallucinated function calls.
4. **Optional evaluator:** Scores open-ended agent behavior, never replacing deterministic side-effect or policy oracles.

#### 2.26.2 Finalized provider and model matrix

The values below are the August 8, 2026 research snapshot and MUST be rechecked before deployment or a release benchmark.

| Provider/model | Finalized role | Current useful properties | Current free/paid snapshot | Caution |
|---|---|---|---|---|
| **Groq `openai/gpt-oss-20b`** | Primary agent model | Tool use, JSON object/schema modes, reasoning, 131,072-token context | Free limits listed as 30 RPM, 1,000 RPD, 8,000 TPM, 200,000 TPD; paid list price $0.075/M input and $0.30/M output | Provider and model limits may change |
| **Groq `qwen/qwen3.6-27b`** | Independent cross-family comparison | Tool use, reasoning, text/vision, 131,072-token context | Same listed free limits; paid list price $0.60/M input and $3.00/M output | Preview status and higher paid price; use on a selected subset |
| **Groq `openai/gpt-oss-120b`** | Optional stronger comparison | Tool use, JSON object/schema modes, reasoning, 131,072-token context | Same listed free limits; paid list price $0.15/M input and $0.60/M output | Same model family as primary, so it is not the independent-family result |
| **Groq `openai/gpt-oss-safeguard-20b`** | Optional advisory safety classifier | Customizable policy-oriented content/safety classification | Same listed free request/token limits at snapshot | Advisory only; never authorizes tools |
| **Cloudflare `@cf/openai/gpt-oss-20b`** | Provider fallback | Function calling, reasoning, OpenAI-compatible endpoints | 10,000 Neurons/day free allocation; paid Workers AI overage $0.011/1,000 Neurons; model page lists $0.20/M input and $0.30/M output | Function calling is documented as beta; validate behavior before use |
| **OpenRouter free model variants** | Manual emergency exploration only | Many open-model endpoints through one API | 20 RPM and 50 RPD before $10 lifetime credit purchase; 1,000 RPD after that threshold | Free availability changes and routing may reduce reproducibility |

#### REQ-MODEL-001 - Finalized primary model [P0]

Use Groq-hosted `openai/gpt-oss-20b` as the default agent-under-test model. The provider and model identifier MUST be configuration rather than hard-coded authorization logic.

#### REQ-MODEL-002 - Independent model comparison [P1]

Use `qwen/qwen3.6-27b` on a smaller stable scenario subset to reduce single-family bias. Because it is currently preview and more expensive on paid usage, it SHOULD not run on every development test.

#### REQ-MODEL-003 - Optional capability escalation [P1]

Use `openai/gpt-oss-120b` only for selected higher-difficulty scenarios or a capability comparison. Results MUST clearly state that it shares the GPT-OSS family with the primary model.

#### REQ-MODEL-004 - Cloudflare fallback [P1]

Implement a Cloudflare Workers AI adapter for `@cf/openai/gpt-oss-20b`. Fallback MUST be explicit in the run profile and recorded in the report. It MUST not create a second MCP execution path.

#### REQ-MODEL-005 - No local model runtime in the MVP [P0]

Ollama, vLLM, llama.cpp, local model weights, and GPU inference are not required or installed by the default MVP profile. A future optional self-hosted profile MAY be added without changing gateway policy semantics.

#### REQ-MODEL-006 - Local tool calling [P0]

The model request MUST use normal structured tool/function calling in which the provider returns a proposal to the local harness. Remote MCP orchestration and provider-built-in tools MUST be disabled.

#### REQ-MODEL-007 - Revision and provider metadata [P0]

Every agentic test run MUST record:

- provider and account tier;
- exact model identifier;
- provider system fingerprint or revision when available;
- context and output limits;
- system prompt revision;
- tool-schema fingerprint;
- sampling and reasoning settings;
- seed where supported;
- provider data-control setting;
- input/output token usage;
- request count and cost estimate; and
- any fallback or retry.

#### REQ-MODEL-008 - Deprecation checks [P0]

Before each release run, CI or a documented manual step MUST check the provider's supported-model and deprecation pages. A model announced for shutdown MUST be replaced before it becomes the reference baseline.

#### REQ-MODEL-009 - Synthetic data and redacted results [P0]

Hosted-model prompts and returned tool results MUST contain only synthetic or intentionally public data. The output-redaction stage MUST run before any permitted tool result is sent back to the provider.

#### REQ-MODEL-010 - Cross-provider evaluation [P1]

At least one release scenario subset SHOULD be executed through both Groq and Cloudflare using the same model family to distinguish provider integration behavior from model-family behavior.

#### REQ-MODEL-011 - Model-independent security claim [P0]

No security claim may depend on a model refusing an unsafe request. The same prohibited action MUST be denied when proposed by a deterministic client, GPT-OSS 20B, Qwen 3.6 27B, or any future model.

### 2.27 Reference policy scenarios

The repository MUST include readable policy examples for these principals:

| Principal | Filesystem | Database | Business tools |
|---|---|---|---|
| `intern` | Read `/workspace/public/**`; deny confidential and production | Read approved reporting views only | Read assigned customers; no refunds, deletes, or exports |
| `developer` | Read/write project workspace; deny secrets and production | Read and limited writes in development | Read customers; small staging actions; no production delete/export |
| `support` | No general filesystem access | No direct SQL | Read assigned customers; refunds below threshold; larger refunds require approval |
| `admin` | Broad access only by explicit rule; high-risk actions still audited | Administrative actions limited by environment and break-glass design | High-impact operations require strong identity and approval |

Being an administrator MUST NOT automatically bypass all risk controls. Production deletion, secret export, and gateway-policy changes SHOULD remain separately protected.

### 2.28 Delivery phases and acceptance gates

#### Phase 0 - Threat model and deterministic harness skeleton [P0]

Deliver:

- documented trust boundaries;
- architecture decision records;
- scenario schema;
- isolated filesystem fixture;
- raw MCP client and MCP Inspector connectivity;
- direct baseline demonstration;
- initial 25 deterministic cases; and
- no model dependency.

**Exit gate:** Direct mode can demonstrate at least three real unsafe side effects in isolated fixtures, and the expected protected behavior is specified before gateway code is considered complete.

#### Phase 1 - Minimal local MCP firewall [P0]

Deliver:

- `stdio` gateway bridge;
- Streamable HTTP path for local testing;
- `tools/list` and `tools/call`;
- explicit server registry;
- default-deny policy;
- filesystem canonicalization and guards;
- OPA/Rego integration;
- structured JSONL audit events;
- lightweight metrics;
- at least 100 deterministic cases; and
- direct-versus-protected latency and side-effect report.

The laptop runs no LLM in this phase.

**Exit gate:** All P0 filesystem and protocol malicious cases are denied with zero prohibited side effects, all legitimate P0 cases produce the expected result, and every completed decision has an audit event.

#### Phase 2 - Cloud model and agent integration [P0/P1]

Deliver:

- PydanticAI local agent;
- Groq adapter using `openai/gpt-oss-20b`;
- local function/tool calling only;
- provider-native MCP and built-in tools disabled;
- strict tool-call validation;
- result sanitization before cloud return;
- per-run request, token, time, retry, and cost budgets;
- five initial model-driven attack scenarios;
- Inspect AI evaluation task; and
- Cloudflare provider adapter skeleton.

**Exit gate:** A hosted model can propose permitted and prohibited calls, every call still passes through the gateway, unsafe proposals are blocked, model-provider failure creates no tool side effect, and the run remains within a configured free-tier budget.

#### Phase 3 - Identity, policy breadth, and observability [P1]

Deliver:

- OIDC/OAuth resource-server validation;
- Keycloak local identity profile only when the laptop can support it, otherwise a CI or cloud lab;
- SQL and outbound HTTP guards;
- rate limiting;
- optional PostgreSQL audit storage;
- OpenTelemetry collector and one dashboard backend;
- cross-model subset using `qwen/qwen3.6-27b`; and
- provider-fallback test using Cloudflare.

**Exit gate:** Wrong-audience and token-passthrough tests pass, policy replay works, provider/model metadata is reproducible, and the report separates gateway latency from model latency.

#### Phase 4 - Approval and sanitized public demo [P1]

Deliver:

- one-time, action-bound approval token;
- small approval CLI or web interface;
- schema-drift quarantine;
- remote HTTPS deployment;
- synthetic public demonstration;
- load, soak, and selected chaos reports; and
- a documented monthly cost ceiling.

**Exit gate:** Approval replay and argument mutation are rejected; the remote demo has no real secrets or host mounts; provider-side MCP is disabled; p95/p99 overhead and infrastructure/inference cost are documented.

#### Phase 5 - Advanced hardening [P2]

Possible work:

- taint tracking and richer DLP rules;
- signed policy bundles and audit batches;
- multi-tenant isolation;
- durable workflow integration;
- restricted code-execution sandbox;
- state-handle protection;
- hardware-backed keys;
- formal policy analysis;
- optional self-hosted model profile; and
- k3s or Nomad only if scaling requirements justify them.

### 2.29 Finalized MVP definition

The MVP is complete when all of the following are true:

- One MCP client can connect through the gateway over `stdio`.
- A raw or SDK client can connect through Streamable HTTP.
- The gateway protects one sandboxed filesystem MCP server containing only synthetic data.
- `tools/list` is filtered and `tools/call` is enforced.
- Policies can allow by principal, tool, operation, and canonical path.
- Path traversal and symlink escape are blocked.
- Unknown tools and changed schemas are denied.
- Denied requests do not reach the upstream server.
- Allowed and denied calls emit correlated JSONL audit records.
- At least 100 deterministic tests include both malicious and legitimate calls and require no model API.
- PydanticAI can call Groq-hosted `openai/gpt-oss-20b` and receive a structured tool proposal.
- The local harness sends every proposal through the gateway and never directly to the MCP server.
- Provider-native MCP, provider-built-in web search, and provider-built-in code execution are disabled.
- At least five model-driven attack scenarios are recorded with token and request budgets.
- The benchmark reports security rate, false-positive rate, gateway overhead, model latency, token usage, and estimated cost as separate measurements.
- No local LLM runtime or GPU is required.
- The local security core works when the model provider is unavailable.

OIDC, SQL, network fetch, human approval, PostgreSQL, a full observability stack, and public deployment are important portfolio features but are not required before the finalized MVP boundary is proven.

### 2.30 Finalized decisions and recommended defaults

| Decision | Finalized default | When to change it |
|---|---|---|
| Primary operating system | Linux for CI/deployment; support macOS and Windows developer use as practical | Add platform-specific path suites when that OS is a required client target |
| Developer hardware assumption | Modest laptop; no GPU requirement; low local concurrency | Increase local services only after measuring RAM and CPU headroom |
| First MCP client | Custom test driver plus MCP Inspector | Add Claude Desktop and Cursor after protocol and policy behavior are stable |
| Protocol baseline | Current July 28, 2026 MCP specification snapshot | Add older adapters only for a named compatibility need |
| First protected server | Sandboxed filesystem MCP | Add SQL and business servers after canonical path policy is proven |
| Agent orchestrator | PydanticAI | Move to LangGraph only for durable branching workflows |
| Evaluation runtime | Inspect AI plus pytest/Hypothesis | Add another framework only for unique coverage |
| Primary model | Groq `openai/gpt-oss-20b` | Replace on deprecation, unacceptable quality, or provider availability issues |
| Independent comparison | Groq `qwen/qwen3.6-27b` | Replace if preview status, cost, or tool-call quality is unsuitable |
| Optional stronger model | Groq `openai/gpt-oss-120b` | Use only for selected higher-difficulty scenarios |
| Provider fallback | Cloudflare `@cf/openai/gpt-oss-20b` | Add another provider only after the adapter contract is stable |
| Local model runtime | None | Add only as an optional future profile |
| Provider tool mode | Local function calling only | Never change for protected security tests |
| Policy engine | OPA/Rego | Consider embedded policy only after measuring a concrete packaging or latency problem |
| Identity in MVP | Static synthetic development principal | Add Keycloak/OIDC in Phase 3 |
| Audit in MVP | Sanitized JSONL | Move to PostgreSQL when searchable persistence is required |
| Local deployment | Normal processes or minimal Compose | Add full profiles as the laptop and project mature |
| Public hosting | Only gateway plus synthetic demo services | Never expose the laptop filesystem or real data |
| Free-tier policy | Use free quota for small agent runs; deterministic tests for scale | Temporarily pay for release-scale inference with a hard budget |

---

## 3. Tech Stack

### 3.1 Finalized reference stack

| Layer | Finalized technology | Why it fits | MVP status |
|---|---|---|---|
| Language | **Python 3.12+** | Strong async, typing, security-test, MCP, and agent ecosystem | Required |
| Package/environment management | **uv** with a committed lockfile | Fast reproducible Python environments | Required |
| MCP implementation | **Official MCP Python SDK / FastMCP components** | Current protocol and transport support | Required |
| HTTP and control surface | **FastAPI / Starlette / Uvicorn** | ASGI, validation integration, health/admin endpoints | Required |
| Validation and configuration | **Pydantic v2** | Strict typed request, policy-input, configuration, and audit schemas | Required |
| Policy engine | **OPA with Rego** | Deterministic policy as code, tests, versioned bundles | Required |
| Agent orchestrator | **PydanticAI** | Local typed agent, Groq provider, MCP client support, provider portability | Required for agent mode |
| Evaluation runtime | **Inspect AI** | Reproducible agent evaluations, MCP tools, limits, caching, logs | Required for portfolio evaluation |
| Deterministic testing | **pytest + Hypothesis** | Model-free correctness, integration, and property-based security tests | Required |
| Primary model provider | **GroqCloud** | Free developer quota, fast OpenAI-compatible API, local tool calling | Required for agent mode |
| Primary model | **`openai/gpt-oss-20b`** | Open-weight, tool use, structured modes, low paid price | Required for agent mode |
| Cross-model | **`qwen/qwen3.6-27b`** | Independent family and strong agent/tool capabilities | Release subset |
| Optional stronger model | **`openai/gpt-oss-120b`** | Higher-capability GPT-OSS comparison | Optional |
| Optional guard model | **`openai/gpt-oss-safeguard-20b`** | Advisory policy-oriented safety classification | Deferred |
| Provider fallback | **Cloudflare Workers AI `@cf/openai/gpt-oss-20b`** | Free daily allocation, function calling, OpenAI-compatible endpoint | P1 |
| Initial protected system | **Sandboxed filesystem MCP server** | Easy-to-understand, real resource-level security demonstrations | Required |
| Audit storage | **JSONL with strict schema and redaction** | Minimal local hardware and easy replay | Required |
| Durable audit storage | **PostgreSQL** | Queryable records and retention | Deferred P1 |
| Initial rate limiting | **In-process bounded limiter** | Avoids another service in the MVP | Required |
| Distributed rate limiting | **Valkey** | Open-source Redis-compatible shared state | Deferred P1 |
| Instrumentation | **OpenTelemetry SDK** | Backend-neutral traces and metrics | Required at code level |
| Initial metrics | **Prometheus-compatible `/metrics` endpoint** or local summary report | Minimal local overhead | Required |
| Telemetry collector/backend | **OpenTelemetry Collector + Grafana Cloud** | Offloads storage and dashboards from weak laptop | Deferred P1 |
| Commercial observability | **Datadog through OTel** | Useful only when student credits are available | Optional |
| Local process orchestration | **Normal processes or minimal Docker/Podman Compose** | Keeps RAM use low while remaining reproducible | Required |
| Public TLS | **Caddy** on VPS or platform-managed TLS | Simple secure HTTPS | Public demo only |
| CI/CD | **GitHub Actions** | Model-free test suite, scans, builds, and reports | Required |
| Code quality | **Ruff + mypy/pyright** | Fast linting and static checking | Required |
| Vulnerability scanning | **Trivy** | Dependency, filesystem, and container scanning | Required |
| Secret scanning | **Gitleaks** | Prevents provider and downstream keys entering Git | Required |
| Load testing | **k6 or Locust** | Model-independent gateway performance testing | P1 |

### 3.2 Fully free cloud-first development stack

This is the finalized default for a developer with a modest laptop.

#### 3.2.1 Local components

```text
Developer laptop
  |
  +-- Python process: PydanticAI agent or deterministic runner
  +-- Python process: Zero-Trust MCP Gateway
  +-- OPA process
  +-- One sandboxed filesystem MCP process
  +-- pytest / Hypothesis / Inspect AI when tests run
  +-- JSONL audit files
```

The laptop does not load model weights, run Ollama, require a GPU, or host a large observability stack.

#### 3.2.2 Cloud components

```text
Primary inference:
  GroqCloud -> openai/gpt-oss-20b

Selected comparison:
  GroqCloud -> qwen/qwen3.6-27b

Fallback validation:
  Cloudflare Workers AI -> @cf/openai/gpt-oss-20b
```

As of the research snapshot, Groq lists 30 requests/minute, 1,000 requests/day, 8,000 tokens/minute, and 200,000 tokens/day for each selected free-plan model. Cloudflare Workers AI includes 10,000 Neurons/day at no charge. Account-specific limits and model availability must be checked before use.

#### 3.2.3 Cost

- **Local software:** $0; all selected core components are open source.
- **Primary cloud inference:** $0 while usage remains inside the provider's free quota.
- **Fallback inference:** $0 while usage remains inside Cloudflare's daily free allocation.
- **Public hosting:** none required for development.
- **Required existing resources:** a normal laptop, Internet connection, and provider accounts.

#### 3.2.4 Free-stack limitations

- Hosted inference requires Internet access.
- Free quotas can change or disappear.
- Model identifiers can be deprecated.
- Rate limits make large live-model sweeps impractical.
- Prompts, selected schemas, and sanitized tool results leave the laptop.
- Release-scale security testing must remain mostly deterministic and model-free.

### 3.3 Recommended low-hardware development profiles

#### Profile A - Security core, no cloud call

```text
gateway + OPA + filesystem MCP + pytest/Hypothesis + JSONL
```

Use for daily development, CI, fuzzing, policy tests, and performance benchmarks.

#### Profile B - Small hosted-agent run

```text
Profile A + PydanticAI + Groq GPT-OSS 20B
```

Use for five to twenty scenarios at a time. Keep one agent request active at a time on a weak laptop.

#### Profile C - Release evaluation

```text
Profile A + Inspect AI
+ GPT-OSS 20B full selected set
+ Qwen 3.6 27B smaller subset
+ Cloudflare fallback subset
```

Run model families sequentially, not concurrently. The expensive work occurs in the provider cloud; local concurrency is still bounded to avoid network, audit, and test contention.

#### 3.3.1 What the laptop still does

Moving inference to the cloud removes the largest compute and memory workload, but the laptop still owns the security-critical work:

| Local job | Why it remains local | Expected pressure in the MVP |
|---|---|---|
| Agent tool loop | Receives the provider's proposed function call and sends it only to the gateway | Low CPU and memory; network-bound |
| Gateway parsing and validation | Validates JSON-RPC/MCP messages, schemas, sizes, and protocol state | Low under normal development traffic |
| Canonicalization and policy input construction | Resolves paths and derives trusted attributes before authorization | Low, but security-sensitive |
| OPA/Rego evaluation | Produces deterministic allow, deny, reason, and obligation decisions | Low for a small policy bundle |
| Sandboxed MCP execution | Reads or modifies only synthetic fixture data after authorization | Low for filesystem tests |
| Deterministic and property tests | Generates malformed, boundary, traversal, and policy cases | Usually moderate; fuzzing can become CPU-intensive |
| Load and soak tests | Measures throughput, latency, leaks, and backpressure | Potentially the hardest local task; run separately from agent tests |
| Audit and lightweight telemetry | Writes redacted JSONL records and bounded metrics | Low, but disk growth must be capped |
| Containers, when enabled | Package and isolate services | Adds RAM and filesystem overhead; native processes come first |

The benchmark report MUST distinguish ordinary development results from single-machine load results. When the laptop acts as client, gateway, policy engine, MCP server, and load generator simultaneously, throughput is a development measurement rather than a production capacity claim.

#### 3.3.2 Pre-flight checklist for a modest laptop

Before implementation or any live-model run:

- Keep the protected fixture in a dedicated synthetic directory; never mount the user's home directory, SSH directory, browser profile, cloud configuration, or real project secrets.
- Bind gateway administration, OPA, the test MCP server, and any local database to loopback or private process pipes by default.
- Remove every direct client-to-upstream MCP configuration so the gateway is the only execution route.
- Store provider keys in an ignored `.env` file or operating-system secret store; use a project-specific key, a hard spend limit, and a revocation plan.
- Start with Profile A and make all deterministic allow/deny tests pass before adding a cloud model.
- Run one model-driven scenario at a time initially and enforce model-call, tool-call, token, retry, time, and cost limits.
- Keep provider-native MCP, web search, connectors, and code execution disabled for protected tests.
- Inspect outbound provider payloads for canary secrets and prohibited fields before the HTTPS request is sent.
- Redact and truncate every allowed tool result before returning it to the model.
- Keep audit retention size-bounded and monitor free disk space during fuzz, load, and soak tests.
- Record the provider, exact model ID, account tier, quota snapshot, prompt revision, tool-schema fingerprint, policy revision, and gateway commit for every reported run.
- Run load tests without model inference so the laptop measures gateway overhead rather than cloud generation latency.
- Add Docker, PostgreSQL, Keycloak, and remote telemetry one named profile at a time; measure idle and peak RAM before keeping any of them enabled.
- Recheck model availability, deprecations, free quotas, and prices before a release because provider conditions are not permanent requirements.

#### 3.3.3 Local resource acceptance gate

The minimal Profile A deployment SHOULD remain responsive during normal development on the documented laptop. Before adding another continuously running service, record:

```text
idle and peak resident memory
idle and peak CPU
open process and file counts
local audit growth per 1,000 requests
p50, p95, and p99 gateway overhead
maximum safe deterministic-test concurrency
```

A new service SHOULD be deferred, moved to a remote free tier, or enabled only in a named test profile when it causes swapping, frequent process termination, sustained thermal throttling, or materially distorts gateway latency measurements.

### 3.4 Free public-demo option

A limited public demo MAY use:

- a Render free web service or Railway Free plan for one thin gateway/demo service;
- the Groq free plan for primary inference;
- Cloudflare Workers AI as a fallback;
- OPA in the same container or as a very small sidecar;
- an in-memory or bundled synthetic fixture;
- JSONL or temporary audit records; and
- no Keycloak, PostgreSQL, local filesystem bridge, real secret, or always-on SLA.

Current platform limitations matter:

- Render free web services spin down after 15 minutes of inactivity, and free Render Postgres databases expire after 30 days.
- Railway Free currently provides $1 of monthly credit and a small maximum service profile.
- A public cloud demo must contain synthetic data in the deployed environment; it must not tunnel to the developer laptop.

Free tiers are suitable for a portfolio demonstration, not a production claim.

### 3.5 Reasonably priced option A - Keep execution local and pay only for inference

This is the best paid option when the laptop is weak but the gateway does not need a public URL.

Groq currently lists `openai/gpt-oss-20b` at:

```text
$0.075 per million input tokens
$0.30  per million output tokens
```

Illustrative evaluation budget:

```text
1,000 scenarios
average total input per scenario:   4,000 tokens
average total output per scenario:    800 tokens

input:  4.0M * $0.075/M = $0.30
output: 0.8M * $0.30/M  = $0.24
estimated total:          $0.54
```

Ten thousand scenarios at the same average would be approximately $5.40. Retries, longer histories, reasoning output, and multi-model comparisons increase the total.

A 100-scenario Qwen 3.6 comparison at the same token averages would be approximately $0.48 at the current $0.60/M input and $3.00/M output list price. This supports using Qwen on a selected subset instead of every test.

Cloudflare's `@cf/openai/gpt-oss-20b` page currently lists $0.20/M input and $0.30/M output, while Workers AI charges through its Neuron accounting and includes a daily free allocation. Actual bills must be verified in the provider dashboard.

**Expected paid-development range:** approximately **$1-$10 per month** for disciplined student-scale experiments, with a hard provider budget and model-free bulk tests.

### 3.6 Reasonably priced option B - Small public VPS

A small VPS can host the public gateway, OPA, synthetic MCP fixture, Caddy, and optionally PostgreSQL while model inference remains on Groq or Cloudflare.

| VPS profile | Current reference price | Suitable deployment |
|---|---:|---|
| Hetzner CX23, 4 GB RAM | approximately EUR 5.99/month before tax | Gateway + OPA + synthetic MCP + JSONL, or light PostgreSQL |
| Hetzner CX33, 8 GB RAM | approximately EUR 8.99/month before tax | Adds PostgreSQL, light Keycloak, or more telemetry headroom |

Additional public IP, backups, storage, domain, and taxes may apply. The provider's regional availability and current price must be checked before purchase.

**Expected small public-demo total:** approximately **$6-$20 equivalent per month plus inference**, depending on database, backup, and observability choices.

### 3.7 Reasonably priced option C - Managed PaaS

#### Railway

Railway currently offers:

- Free: $0/month with $1 of monthly credit;
- Hobby: $5/month with $5 of included resource usage; and
- usage-based CPU, memory, storage, and network charges above the included amount.

A thin gateway, OPA, and synthetic MCP service may fit close to the Hobby minimum. Configure usage alerts and a hard limit before load testing.

#### Render

Render remains convenient for a thin FastAPI demonstration and managed TLS. The free service is acceptable for previews but sleeps when idle. A durable paid deployment should use the current paid compute and datastore prices shown in the Render console at deployment time rather than relying on a hard-coded estimate in this document.

#### Recommendation

- Use **local processes plus Groq free quota** for daily work.
- Use **paid Groq inference only** when a release run exceeds free quota.
- Use **Railway Hobby** when deployment convenience and a small spend ceiling matter.
- Use a **small VPS** when predictable fixed cost and full network control matter most.
- Use **Render free** only for a sleeping synthetic preview.

### 3.8 Provider and model safety configuration

The default environment configuration should include controls equivalent to:

```yaml
model_provider: groq
model_name: openai/gpt-oss-20b
provider_native_mcp: false
provider_builtin_web_search: false
provider_builtin_code_execution: false
provider_compound_agent: false
local_model_runtime: disabled
max_model_calls: 5
max_tool_calls: 8
max_identical_tool_retries: 2
max_denied_action_retries: 2
max_run_seconds: 60
cloud_data_class: synthetic-only
```

A fallback profile changes only the provider adapter and model identifier. It does not change the gateway or the MCP server route.

### 3.9 What the laptop is responsible for

The laptop performs:

- Python orchestration and HTTP requests to the model provider;
- JSON and JSON-RPC parsing;
- schema validation and canonicalization;
- OPA policy evaluation;
- filesystem operations inside a tiny synthetic sandbox;
- audit writing;
- deterministic and property-based tests; and
- limited local metrics.

The laptop does not perform:

- transformer inference;
- model-weight loading;
- GPU computation;
- high-volume telemetry storage;
- large-scale model serving; or
- provider-side search or code execution.

### 3.10 Recommended repository layout

```text
zero-trust-mcp-gateway/
  README.md
  pyproject.toml
  uv.lock
  compose.yaml
  .env.example
  .gitignore
  docs/
    requirements.md
    threat-model.md
    architecture.md
    cloud-model-data-flow.md
    benchmark-methodology.md
    cost-model.md
    adr/
  gateway/
    transports/
    protocol/
    identity/
    registry/
    canonicalizers/
    policy/
    approvals/
    routing/
    responses/
    audit/
    telemetry/
    admin_api/
  agent/
    orchestrator/
    providers/
      groq.py
      cloudflare.py
    tool_adapter/
    sanitization/
    budgets/
  policies/
    rego/
    tests/
    bundles/
  servers/
    filesystem_fixture/
    sql_fixture/
    enterprise_fixture/
    malicious_fixture/
  harness/
    scenarios/
      deterministic/
      agentic/
      performance/
      chaos/
    inspect_tasks/
    oracles/
    reporters/
    cached_model_outputs/
  tests/
    unit/
    integration/
    protocol/
    security/
    property/
  dashboards/
  deploy/
    local/
    vps/
    render/
    railway/
  scripts/
  .github/workflows/
```

### 3.11 Technologies deliberately deferred

The following SHOULD NOT be introduced in the MVP without a measured need:

- Ollama, vLLM, llama.cpp, or local model weights.
- Kubernetes, a service mesh, or a multi-cluster control plane.
- Kafka or another event-streaming platform.
- A custom identity provider.
- A custom policy language.
- A vector database for authorization.
- An LLM call in the synchronous allow/deny path.
- Provider-native remote MCP or provider-built-in execution tools.
- A generic shell tool on the host.
- Keycloak, PostgreSQL, Grafana, Tempo, and Loki in the default low-hardware profile.
- More than one primary agent orchestrator implementation.

### 3.12 Research references

The references below are intentionally weighted toward official specifications, project documentation, provider documentation, and official pricing pages. Pricing, free quotas, model status, and hosted-service limits are time-sensitive and must be rechecked before deployment.

1. Model Context Protocol, July 28, 2026 release overview: <https://blog.modelcontextprotocol.io/posts/2026-07-28/>
2. MCP Streamable HTTP transport specification: <https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http>
3. MCP security best practices: <https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices>
4. MCP authorization tutorial: <https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization>
5. Official MCP Python SDK: <https://github.com/modelcontextprotocol/python-sdk>
6. MCP Python SDK authorization documentation: <https://py.sdk.modelcontextprotocol.io/run/authorization/>
7. OPA documentation: <https://www.openpolicyagent.org/docs/latest/>
8. OPA REST API: <https://www.openpolicyagent.org/docs/rest-api>
9. FastAPI documentation: <https://fastapi.tiangolo.com/>
10. PydanticAI repository: <https://github.com/pydantic/pydantic-ai>
11. PydanticAI Groq model integration: <https://github.com/pydantic/pydantic-ai/blob/main/docs/models/groq.md>
12. PydanticAI MCP client documentation: <https://github.com/pydantic/pydantic-ai/blob/main/docs/mcp/client.md>
13. Inspect AI documentation: <https://inspect.aisi.org.uk/>
14. Inspect AI MCP tools: <https://inspect.aisi.org.uk/tools-mcp.html>
15. Inspect AI limits and evaluation tooling index: <https://inspect.aisi.org.uk/llms.txt>
16. LangGraph overview: <https://docs.langchain.com/oss/python/langgraph/overview>
17. Haystack repository: <https://github.com/deepset-ai/haystack>
18. LlamaIndex Workflows documentation: <https://docs.llamaindex.ai/en/stable/module_guides/workflow/>
19. Groq GPT-OSS 20B model page: <https://console.groq.com/docs/model/openai/gpt-oss-20b>
20. Groq GPT-OSS 120B model page: <https://console.groq.com/docs/model/openai/gpt-oss-120b>
21. Groq Qwen 3.6 27B model page: <https://console.groq.com/docs/model/qwen/qwen3.6-27b>
22. Groq GPT-OSS Safeguard 20B model page: <https://console.groq.com/docs/model/openai/gpt-oss-safeguard-20b>
23. Groq rate limits: <https://console.groq.com/docs/rate-limits>
24. Groq local tool calling: <https://console.groq.com/docs/tool-use/local-tool-calling>
25. Groq model deprecations: <https://console.groq.com/docs/deprecations>
26. Groq data retention and zero-data-retention controls: <https://console.groq.com/docs/your-data>
27. Groq OpenAI compatibility: <https://console.groq.com/docs/openai>
28. Cloudflare Workers AI pricing: <https://developers.cloudflare.com/workers-ai/platform/pricing/>
29. Cloudflare Workers AI limits: <https://developers.cloudflare.com/workers-ai/platform/limits/>
30. Cloudflare GPT-OSS 20B model page: <https://developers.cloudflare.com/workers-ai/models/gpt-oss-20b/>
31. Cloudflare OpenAI-compatible endpoints: <https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/>
32. OpenRouter free model variants: <https://openrouter.ai/docs/guides/routing/model-variants/free>
33. OpenRouter rate limits: <https://openrouter.ai/docs/api_reference/limits>
34. OpenTelemetry Python documentation: <https://opentelemetry.io/docs/languages/python/>
35. Prometheus histogram guidance: <https://prometheus.io/docs/practices/histograms/>
36. Grafana Cloud pricing: <https://grafana.com/pricing/>
37. Keycloak authorization services: <https://www.keycloak.org/docs/latest/authorization_services/index.html>
38. PostgreSQL documentation: <https://www.postgresql.org/docs/>
39. Valkey documentation: <https://valkey.io/topics/documentation/>
40. Hypothesis documentation: <https://hypothesis.readthedocs.io/>
41. Grafana k6 documentation: <https://grafana.com/docs/k6/latest/>
42. Trivy documentation: <https://trivy.dev/latest/>
43. Gitleaks repository: <https://github.com/gitleaks/gitleaks>
44. GitHub Actions billing and usage documentation: <https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions>
45. Render free-service documentation: <https://render.com/docs/free>
46. Render web-service documentation: <https://render.com/docs/web-services>
47. Railway plans and pricing: <https://docs.railway.com/pricing/plans>
48. Railway cost controls: <https://docs.railway.com/pricing/cost-control>
49. Hetzner cost-optimized cloud pricing: <https://www.hetzner.com/cloud/cost-optimized/>
50. Caddy documentation: <https://caddyserver.com/docs/>
