"""Fixed deployment-owned Detector profiles with optional real backends."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from enum import StrEnum
from hashlib import sha256
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from agent_guardrail.config.defaults import (
    create_default_detector_registry,
    create_detector_registry,
)
from agent_guardrail.core import DetectorRegistry
from agent_guardrail.detectors import (
    EmbeddingBackend,
    EmbeddingProfile,
    IsSimilarDetector,
    PresidioAnalyzerBackend,
    SemgrepCLIBackend,
    SemgrepDetector,
    SemgrepProfile,
    TransformersPipelineClassifier,
    YaraInjectionDetector,
    YaraInjectionProfile,
    YaraPythonBackend,
    YaraRuleBinding,
)

PROMPT_MODEL_REPOSITORY = "protectai/deberta-v3-base-prompt-injection-v2"
PROMPT_MODEL_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
PROMPT_MODEL_ASSETS = (
    (
        "added_tokens.json",
        23,
        "dc046d04c9b0ada7ae6f1dc89c465801799acdf0c9a6aab8c15a1b2d5ca4e91f",
    ),
    (
        "config.json",
        994,
        "05079f4735092040b780d459027afab413faa6eeb66a548571a58832304b60bb",
    ),
    (
        "model.safetensors",
        737_719_272,
        "6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424",
    ),
    (
        "special_tokens_map.json",
        286,
        "9463f61e1b109a8eb4688b829260d7c6b1e6dff04c98ff7269bb89e2b92369b9",
    ),
    (
        "spm.model",
        2_464_616,
        "c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd",
    ),
    (
        "tokenizer.json",
        8_656_744,
        "f0a66ad0d735d8dca9ecac4ff50fcdef4bb6adbadd2941a926844844d2c2059b",
    ),
    (
        "tokenizer_config.json",
        1_284,
        "557b3d33d3f41b81ad769244e506549e98a1857d41dd58160aacd4d98d710b5a",
    ),
)
FULL_LOCAL_PROFILE_VERSION = "1"
FULL_LOCAL_SEMGREP_VERSION = "1.170.0"
FULL_LOCAL_PACKAGE_VERSIONS = {
    "en-core-web-sm": "3.8.0",
    "presidio-analyzer": "2.2.363",
    "sentencepiece": "0.2.2",
    "spacy": "3.8.15",
    "torch": "2.13.0",
    "transformers": "4.57.6",
    "yara-python": "4.5.4",
}
FULL_LOCAL_SEMGREP_RULE_IDS = frozenset(
    {
        "agent-guardrail.python.destructive-delete",
        "agent-guardrail.python.dynamic-execution",
        "agent-guardrail.python.os-command",
        "agent-guardrail.python.subprocess-shell",
    }
)
FULL_LOCAL_YARA_BINDINGS = (
    YaraRuleBinding("ag_prompt_instruction_override", "yara_prompt_injection"),
    YaraRuleBinding("ag_sql_injection", "yara_sql_injection"),
    YaraRuleBinding("ag_template_injection", "yara_template_injection"),
    YaraRuleBinding("ag_xss_injection", "yara_xss"),
    YaraRuleBinding("ag_code_injection", "yara_code_injection"),
)


class DetectorDeploymentProfile(StrEnum):
    """Closed process-level profiles; structured Policy cannot select these."""

    LOCAL = "local"
    FULL_LOCAL_V1 = "full_local_v1"


class PromptModelDevice(StrEnum):
    """Explicit execution device for the fixed prompt model."""

    CPU = "cpu"
    CUDA = "cuda"


class DetectorProfileError(RuntimeError):
    """A fixed Detector profile could not start safely."""


def create_deployment_detector_registry(
    profile: DetectorDeploymentProfile | str = DetectorDeploymentProfile.LOCAL,
    *,
    prompt_model_device: PromptModelDevice | str = PromptModelDevice.CPU,
    detector_assets_dir: Path | None = None,
    embedding_backend: EmbeddingBackend | None = None,
    embedding_profile: EmbeddingProfile | None = None,
) -> DetectorRegistry:
    """Construct one deployment profile without allowing Policy-driven choices."""

    try:
        selected_profile = DetectorDeploymentProfile(profile)
        selected_device = PromptModelDevice(prompt_model_device)
    except ValueError as exc:
        raise DetectorProfileError("unknown Detector deployment profile setting") from exc
    if (embedding_backend is None) != (embedding_profile is None):
        raise DetectorProfileError(
            "embedding backend and embedding profile must be configured together"
        )
    similarity_detector = (
        IsSimilarDetector(embedding_backend, profile=embedding_profile)
        if embedding_backend is not None and embedding_profile is not None
        else None
    )
    if selected_profile is DetectorDeploymentProfile.LOCAL:
        if selected_device is not PromptModelDevice.CPU:
            raise DetectorProfileError("prompt model device requires the full_local_v1 profile")
        if similarity_detector is None:
            return create_default_detector_registry()
        return create_detector_registry(similarity_detector=similarity_detector)
    if detector_assets_dir is None:
        raise DetectorProfileError("full_local_v1 requires a Detector assets directory")

    semgrep_detector = _create_semgrep_detector()
    yara_detector = _create_yara_detector()
    pii_backend = _create_presidio_backend()
    prompt_classifier = _create_prompt_classifier(
        device=selected_device,
        assets_dir=detector_assets_dir,
    )
    return create_detector_registry(
        pii_backend=pii_backend,
        prompt_classifier=prompt_classifier,
        prompt_threshold=0.85,
        semgrep_detector=semgrep_detector,
        yara_detector=yara_detector,
        similarity_detector=similarity_detector,
    )


def prefetch_full_local_assets() -> None:
    """Download and verify the pinned prompt model during deployment setup."""

    raw_assets_dir = os.environ.get("AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR")
    if raw_assets_dir is None or not raw_assets_dir.strip():
        raise DetectorProfileError(
            "AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR is required for asset prefetch"
        )
    assets_dir = Path(raw_assets_dir).expanduser().resolve()
    model_dir = _prompt_model_directory(assets_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    for name, expected_size, expected_digest in PROMPT_MODEL_ASSETS:
        target = model_dir / name
        if _asset_matches(
            target,
            expected_size=expected_size,
            expected_digest=expected_digest,
        ):
            continue
        _download_asset(
            name,
            target=target,
            expected_size=expected_size,
            expected_digest=expected_digest,
        )
    _verify_prompt_model_assets(assets_dir)
    print(f"Pinned Detector assets are available at {model_dir}")


def _create_presidio_backend() -> PresidioAnalyzerBackend:
    presidio = _require_module("presidio_analyzer")
    nlp_engine_module = _require_module("presidio_analyzer.nlp_engine")
    provider_type = cast(Any, getattr(nlp_engine_module, "NlpEngineProvider", None))
    analyzer_type = cast(Any, getattr(presidio, "AnalyzerEngine", None))
    if not callable(provider_type) or not callable(analyzer_type):
        raise DetectorProfileError("the installed Presidio API is incompatible")
    try:
        provider = cast(
            Any,
            provider_type(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                }
            ),
        )
        nlp_engine = provider.create_engine()
        analyzer = analyzer_type(nlp_engine=nlp_engine, supported_languages=["en"])
    except Exception as exc:
        raise DetectorProfileError("the pinned Presidio NLP profile could not load") from exc
    version = ".".join(
        (
            f"presidio-{_required_package_version('presidio-analyzer')}",
            f"spacy-{_required_package_version('spacy')}",
            f"model-{_required_package_version('en-core-web-sm')}",
        )
    )
    return PresidioAnalyzerBackend(
        analyzer,
        backend_name="presidio-spacy-en",
        backend_version=version,
    )


def _create_prompt_classifier(
    *,
    device: PromptModelDevice,
    assets_dir: Path,
) -> TransformersPipelineClassifier:
    torch_version = _required_package_version("torch")
    transformers_version = _required_package_version("transformers")
    _required_package_version("sentencepiece")
    torch = _require_module("torch")
    transformers = _require_module("transformers")
    auto_model = cast(
        Any,
        getattr(transformers, "AutoModelForSequenceClassification", None),
    )
    auto_tokenizer = cast(Any, getattr(transformers, "AutoTokenizer", None))
    if not all(callable(item) for item in (auto_model, auto_tokenizer)):
        raise DetectorProfileError("the installed Transformers API is incompatible")

    cuda = getattr(torch, "cuda", None)
    cuda_available = getattr(cuda, "is_available", None)
    if device is PromptModelDevice.CUDA and (
        not callable(cuda_available) or not cuda_available()
    ):
        raise DetectorProfileError("CUDA was selected but PyTorch cannot access a CUDA device")
    try:
        model_path = _verify_prompt_model_assets(assets_dir)
        tokenizer = auto_tokenizer.from_pretrained(model_path, local_files_only=True)
        model = auto_model.from_pretrained(
            model_path,
            local_files_only=True,
            use_safetensors=True,
        )
        label_mapping = getattr(getattr(model, "config", None), "id2label", None)
        if label_mapping != {0: "SAFE", 1: "INJECTION"}:
            raise DetectorProfileError("the prompt model label mapping is not the pinned profile")
        inference_device = "cuda:0" if device is PromptModelDevice.CUDA else "cpu"
        model.to(inference_device)
        model.eval()
        classifier_pipeline = _PinnedTransformersCallable(
            tokenizer=tokenizer,
            model=model,
            torch=torch,
            device=inference_device,
        )
        classifier_pipeline(
            "Summarize this ordinary support request.",
            truncation=True,
            max_length=512,
        )
    except Exception as exc:
        raise DetectorProfileError(
            "the pinned prompt-injection model is not installed or could not load"
        ) from exc
    return TransformersPipelineClassifier(
        classifier_pipeline,
        model_name="protectai-deberta-v3-prompt-injection-v2",
        model_version=(
            f"{PROMPT_MODEL_REVISION}.torch-{torch_version}."
            f"transformers-{transformers_version}"
        ),
        injection_labels=frozenset({"injection"}),
        max_length=512,
    )


class _PinnedTransformersCallable:
    """Minimal text classifier callable without image/audio pipeline imports."""

    def __init__(
        self,
        *,
        tokenizer: Any,
        model: Any,
        torch: ModuleType,
        device: str,
    ) -> None:
        self._tokenizer = tokenizer
        self._model = model
        self._torch = torch
        self._device = device

    def __call__(
        self,
        text: str,
        *,
        truncation: bool,
        max_length: int,
    ) -> list[dict[str, object]]:
        encoded = self._tokenizer(
            text,
            truncation=truncation,
            max_length=max_length,
            return_tensors="pt",
        )
        device_inputs = {
            name: tensor.to(self._device) for name, tensor in encoded.items()
        }
        inference_mode = cast(Any, getattr(self._torch, "inference_mode", None))
        softmax = cast(Any, getattr(self._torch, "softmax", None))
        if not callable(inference_mode) or not callable(softmax):
            raise DetectorProfileError("the installed PyTorch inference API is incompatible")
        with cast(Any, inference_mode)():
            output = self._model(**device_inputs)
            probability = cast(Any, softmax)(output.logits, dim=-1)[0, 1].item()
        return [{"label": "INJECTION", "score": float(probability)}]


def _create_semgrep_detector() -> SemgrepDetector:
    executable = shutil.which("semgrep")
    if executable is None:
        raise DetectorProfileError("the full_local_v1 profile requires the Semgrep executable")
    rules_source = _profile_resource("semgrep-python.yaml")
    rules_digest = sha256(rules_source.encode("utf-8")).hexdigest()
    backend = SemgrepCLIBackend(
        executable=Path(executable),
        rules_source=rules_source,
        engine_version=_verified_semgrep_version(Path(executable)),
        language="python",
        max_findings=32,
        process_timeout_seconds=4.8,
    )
    return SemgrepDetector(
        backend,
        profile=SemgrepProfile(
            profile_id="full-local-python",
            profile_version=f"{FULL_LOCAL_PROFILE_VERSION}+rules.{rules_digest[:12]}",
            language="python",
            allowed_rule_ids=FULL_LOCAL_SEMGREP_RULE_IDS,
            max_findings=32,
        ),
    )


def _create_yara_detector() -> YaraInjectionDetector:
    yara = _require_module("yara")
    compile_rules = getattr(yara, "compile", None)
    if not callable(compile_rules):
        raise DetectorProfileError("the installed yara-python API is incompatible")
    rules_source = _profile_resource("injection.yar")
    rules_digest = sha256(rules_source.encode("utf-8")).hexdigest()
    try:
        compiled_rules = compile_rules(source=rules_source)
    except Exception as exc:
        raise DetectorProfileError("the packaged YARA rules could not compile") from exc
    backend = YaraPythonBackend(
        compiled_rules,
        engine_version=_required_package_version("yara-python"),
        ruleset_digest=rules_digest,
        max_matches=32,
    )
    return YaraInjectionDetector(
        backend,
        profile=YaraInjectionProfile(
            profile_id="full-local-injection",
            profile_version=f"{FULL_LOCAL_PROFILE_VERSION}+rules.{rules_digest[:12]}",
            rules=FULL_LOCAL_YARA_BINDINGS,
            max_matches=32,
        ),
    )


def _profile_resource(name: str) -> str:
    try:
        return (
            resources.files("agent_guardrail.detector_profiles")
            .joinpath("full_local_v1", name)
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise DetectorProfileError("a packaged Detector profile resource is missing") from exc


def _prompt_model_directory(assets_dir: Path) -> Path:
    return assets_dir / "full_local_v1" / f"prompt-model-{PROMPT_MODEL_REVISION}"


def _verify_prompt_model_assets(assets_dir: Path) -> Path:
    model_dir = _prompt_model_directory(assets_dir.expanduser().resolve())
    for name, expected_size, expected_digest in PROMPT_MODEL_ASSETS:
        if not _asset_matches(
            model_dir / name,
            expected_size=expected_size,
            expected_digest=expected_digest,
        ):
            raise DetectorProfileError("a pinned prompt-model asset is missing or invalid")
    return model_dir


def _asset_matches(
    path: Path,
    *,
    expected_size: int,
    expected_digest: str,
) -> bool:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected_size:
        return False
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest() == expected_digest


def _download_asset(
    name: str,
    *,
    target: Path,
    expected_size: int,
    expected_digest: str,
) -> None:
    url = (
        f"https://huggingface.co/{PROMPT_MODEL_REPOSITORY}/resolve/"
        f"{PROMPT_MODEL_REVISION}/{name}?download=true"
    )
    temporary = target.with_name(f".{target.name}.partial-{os.getpid()}")
    digest = sha256()
    total = 0
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "agent-guardrail-detector-prefetch/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open(
            "wb"
        ) as destination:
            while chunk := response.read(1_048_576):
                total += len(chunk)
                if total > expected_size:
                    raise DetectorProfileError("a prompt-model asset exceeded its pinned size")
                digest.update(chunk)
                destination.write(chunk)
        if total != expected_size or digest.hexdigest() != expected_digest:
            raise DetectorProfileError("a prompt-model asset failed integrity verification")
        os.replace(temporary, target)
    except (OSError, urllib.error.URLError) as exc:
        raise DetectorProfileError("a pinned prompt-model asset could not be downloaded") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _require_module(name: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        raise DetectorProfileError(
            "the selected Detector profile dependencies are not installed; "
            "install the detectors extra"
        ) from exc


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise DetectorProfileError("a pinned Detector dependency has no package metadata") from exc


def _required_package_version(name: str) -> str:
    expected = FULL_LOCAL_PACKAGE_VERSIONS[name]
    actual = _package_version(name)
    if actual != expected:
        raise DetectorProfileError(f"full_local_v1 requires {name} {expected}")
    return actual


def _verified_semgrep_version(executable: Path) -> str:
    try:
        result = subprocess.run(
            (str(executable), "--version"),
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
            env={
                "HOME": tempfile.gettempdir(),
                "LC_ALL": "C.UTF-8",
                "NO_COLOR": "1",
                "PATH": os.defpath,
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "SEMGREP_SEND_METRICS": "off",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DetectorProfileError("the Semgrep executable version could not be verified") from exc
    if result.returncode != 0 or result.stdout.strip() != FULL_LOCAL_SEMGREP_VERSION:
        raise DetectorProfileError(
            f"full_local_v1 requires Semgrep {FULL_LOCAL_SEMGREP_VERSION}"
        )
    return FULL_LOCAL_SEMGREP_VERSION
