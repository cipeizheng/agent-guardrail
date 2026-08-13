"""Side-effect checkpoints owned by Gateway/Enforcement, never by trace Events."""

from enum import StrEnum


class EnforcementCheckpoint(StrEnum):
    """A trusted boundary at which a side effect or output release is gated."""

    BEFORE_MODEL_CALL = "before_model_call"
    BEFORE_MODEL_OUTPUT_RELEASE = "before_model_output_release"
    BEFORE_TOOL_CALL = "before_tool_call"
    BEFORE_TOOL_OUTPUT_RELEASE = "before_tool_output_release"
