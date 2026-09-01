# Contributing to Agent Guardrail

Agent Guardrail is a personal project. I started it because I wanted agent safety controls that were understandable, testable, and close to the point where an LLM call or tool side effect actually happens.

You are very welcome to use it, open issues, share unusual agent workflows, suggest features, or question the design. If something feels confusing or unnecessarily complicated, that is useful feedback too. You do not need a finished solution or a formal security analysis before starting a conversation.

## Design ideas behind the project

The project currently follows a few ideas that I hope are useful beyond this repository:

- A guardrail should be able to stop a protected action, not only label text after the fact.
- Policies should be reviewable data rather than executable code with hidden I/O or imports.
- Detector results are evidence. A security decision also needs context such as the source, destination, and authorization.
- Events and their relationships should be explicit, so a decision can explain what matched and why.
- Sensitive inputs should not be copied into findings, errors, logs, or audit records.

These are design choices, not unquestionable rules. If one of them causes a real limitation, or you have found a cleaner model, please open an issue and explain the trade-off. Other projects are also welcome to reuse the ideas, documents, or implementation patterns that are helpful.

## Ways to help

Contributions do not have to be code. For example, you can:

- try the project in a real or experimental agent;
- report a bug, awkward API, missing example, or unclear document;
- share a policy or threat scenario the current model cannot express;
- compare the behavior with another guardrail project;
- propose a design change, Detector, adapter, test, or documentation improvement;
- send a pull request, whether it is a small typo fix or a larger implementation.

For an issue, a short description of what you tried, what you expected, and what happened is enough to begin. Please remove prompts, credentials, personal data, and other sensitive material before posting logs or examples.

## Trying the project locally

Agent Guardrail requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/cipeizheng/agent-guardrail.git
cd agent-guardrail
uv sync --frozen --extra gateway --dev
uv run python examples/secret_email_demo.py
```

If you plan to change code, the [development guide](docs/contributing.md) explains the repository layout and the full checklist. The [current architecture contract](docs/current-architecture-contract.md) records what is implemented today and which safety properties existing changes rely on. Those documents are there to preserve context, especially for AI-assisted contributions—not to prevent new ideas. A proposal can disagree with them; it should simply say why.

Before sending a pull request, please run the checks that apply to your change. The complete set is:

```bash
uv sync --frozen --extra gateway --dev
uv run pytest --cov=agent_guardrail --cov-report=term-missing
uv run ruff check .
uv run pyright
uv build
git diff --check
```

Small pull requests are often easier to discuss, but an early draft is completely fine when you want feedback on the direction. Please describe the behavior you changed and add tests when the change affects enforcement or security decisions.

## License

By contributing, you agree that your contribution may be distributed under the repository's [MIT License](LICENSE).
