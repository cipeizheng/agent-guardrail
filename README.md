# Agent Guardrail

**A security control layer for AI agents.**

English | [简体中文](README.zh-CN.md)

[![Version](https://img.shields.io/badge/version-0.1.0-3b82f6)](pyproject.toml) [![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](pyproject.toml) [![Status](https://img.shields.io/badge/status-alpha-f59e0b)](docs/roadmap.md) [![License](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

Agent Guardrail checks model requests, model output, tool calls, and tool results before they proceed to the next step, then allows, records, or blocks them according to YAML rules.

It preserves relationships among messages, model calls, and tool calls, and produces masked findings, error messages, and audit records.

## Project status

The current version is v0.1.0 alpha. The project provides in-process and HTTP Gateway integration, supports OpenAI, Anthropic, and MCP, and supports separate deployment of policy analysis. Responses `previous_response_id` is available through the Gateway's injected in-process state store or the external Agentic API topology. The current external integration uses one Agentic API instance with SQLite; the deployment serves one user, and the host environment supplies sandboxing, identity, durable storage, and resource isolation.

## Quick start

Requirements: Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/cipeizheng/agent-guardrail.git
cd agent-guardrail
uv sync --frozen --extra gateway --dev
uv run python examples/secret_email_demo.py
```

The demo uses local model and tool implementations, so it needs no API key. The model call runs, while the email tool call is blocked before execution. The final lines are:

```text
policy decision: block
model executions: 1
send_email executions: 0
```

## Policy configuration

Policies use the version-3 YAML format. This example checks a `send_email` call and blocks it before execution when its arguments contain a secret or other sensitive credential.

```yaml
version: 3
scopes: [pending]
rules:
  - id: prevent-secret-email
    action: block
    events:
      call: {kind: tool_call_proposal, domain: pending}
    where:
      all:
        - tool: {binding: call, name: send_email}
        - detector:
            id: secret_scan
            capability: secrets
            inputs:
              - value: {field: [call, payload, arguments]}
                encoding: canonical_json
    finding:
      code: secret_exfiltration
      message: The proposed tool call contains secret material.
      subjects: [call]
      evidence: [{source: detector, id: secret_scan}]
```

The loader checks the format, references, resource limits, and available detection capabilities before activating a policy. See the [Policy authoring guide](docs/guides/policy-authoring.md) for the complete syntax.

## Built-in detection capabilities

The default `local` profile provides the following local checks without model downloads or external services. The names in the table are used in policy files:

| What it checks | Purpose | Policy name |
| --- | --- | --- |
| Secrets and credentials | Finds private keys, cloud credentials, and API tokens | `secrets` |
| Personal information | Finds fixed types such as email, phone, identity, and financial numbers | `pii` |
| Prompt injection signals | Finds high-signal instruction overrides, prompt disclosure, and role changes | `prompt_injection` |
| Invisible or confusing text | Finds Unicode controls, zero-width characters, and limited mixed-script tricks | `unicode_security` |
| Python code structure | Reports imports, risky calls, and syntax facts | `python_ast_ipython` |
| Hidden web content | Finds hidden HTML, comments, and bounded encoded content | `hidden_content` |
| Numeric or length ranges | Checks numbers, text, arrays, and objects against bounds | `number_in_range`, `length_in_range` |
| URL host allowlists | Checks whether an HTTP(S) URL uses an allowed host | `url_host_allowed` |
| Approximate text matching | Finds text within a bounded edit distance | `fuzzy_contains` |

Other detection capabilities, integration methods, and status are maintained in the [capability matrix](docs/capability-status.yaml); detailed setup is in the [capability reference](docs/reference/capabilities.md) and [operations guide](docs/guides/operations.md).

Detection results are signals. Rules should also use the data source, destination, authorization, and relationships among the message, model call, and tool call involved in the protected operation.

## Deployment and security

Guardrail checks events submitted through its SDK and requests handled by its Gateway. With the SDK, application code reads the returned decision before performing the operation; the Gateway enforces that ordering for model and MCP requests. Agent code that can run shell commands, arbitrary code, direct network calls, or host operations still requires a separate sandbox with default-deny egress, minimal temporary storage, and resource limits. Keep provider or tool credentials and audit storage outside that sandbox. The [security model](docs/security-model.md) and [operations guide](docs/guides/operations.md) define the responsibility split.

The current deployment serves one user and the default Compose starts the Gateway only. The [Responses state-layer design](docs/design/responses-state-layer.md) describes the Gateway state interface and the selected external state-owner topology using vLLM Agentic API with SQLite. Future work is listed in the [roadmap](docs/roadmap.md); the [current architecture contract](docs/current-architecture-contract.md) defines current behavior.

## Documentation

| Read | For |
| --- | --- |
| [Documentation map](docs/README.md) | The shortest path for each task |
| [Architecture overview](docs/overview.md) | The end-to-end Event, Policy, Runtime, and Enforcement flow |
| [Policy authoring](docs/guides/policy-authoring.md) | Writing version-3 YAML |
| [Integration guide](docs/guides/integration.md) | Connecting application code, model clients, and MCP |
| [Capability reference](docs/reference/capabilities.md) | Detector and Predicate contracts |
| [Gateway protocol](docs/reference/gateway-protocol.md) | HTTP, streaming, and MCP wire behavior |
| [Responses state-layer design](docs/design/responses-state-layer.md) | `previous_response_id` state interface and external state-owner boundary |
| [Operations guide](docs/guides/operations.md) | Profiles, environment variables, Docker, audit, and health |
| [Security model](docs/security-model.md) | Assets, trust boundaries, and T01–T10 |
| [Separate analysis service design](docs/design/remote-core-deployment.md) | Deploying policy analysis separately |

## Development

```bash
uv sync --frozen --extra gateway --dev
uv run pytest --cov=agent_guardrail --cov-report=term-missing
uv run ruff check .
uv run pyright
uv build
git diff --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## License

Agent Guardrail is available under the [MIT License](LICENSE). Optional detector assets and dependencies retain their upstream licenses; consult the [operations guide](docs/guides/operations.md) before deploying a model profile.
