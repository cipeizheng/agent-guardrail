from importlib.metadata import version

import agent_guardrail


def test_package_version() -> None:
    assert agent_guardrail.__version__ == version("agent-guardrail")
