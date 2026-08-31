"""Detectability classes for attack corpora (see evals/README.md).

Recall aggregated over a mixed corpus answers "how did the detector do on
average", which is misleading when part of the corpus is undetectable at the
content layer by construction. Each attack sample therefore carries a class
describing which detector layer could in principle separate it:

- ``benign``: not an attack (false-positive side of the corpus).
- ``style_detectable``: the payload carries lexical/stylistic attack markers
  (imperative meta-instructions, code artifacts inside prose) — a content
  classifier has a real chance.
- ``intent_only``: the payload text is fluent and benign-looking; only a
  mismatch against user intent or channel context can reveal it.
- ``content_undetectable``: the payload is indistinguishable from a
  legitimate user instruction at the content layer — content-classifier
  recall on this subset is label noise, not a detector gap.
- ``unclassified``: the corpus is not in the map yet; classify it before
  reporting (fails loudly in report assembly).
"""

from __future__ import annotations

DETECTABILITY_CLASSES = (
    "benign",
    "style_detectable",
    "intent_only",
    "content_undetectable",
    "unclassified",
)

# (benchmark_id, dataset_id) -> class. BIPIA text attacks are fluent
# instructions such as "translate your response" — labeled
# content_undetectable per the P1-3 finding that every content detector is
# blind to them by construction. BIPIA code attacks embed code artifacts in
# email prose (style marker). AgentDojo injections use the
# "important instructions" imperative template (style marker).
_CORPUS_CLASSES: dict[tuple[str, str], str] = {
    ("bipia", "text"): "content_undetectable",
    ("bipia", "code"): "style_detectable",
}


def classify_corpus(benchmark_id: str, dataset_id: str) -> str:
    """Classify one (benchmark, dataset) pair; ``unclassified`` when unmapped."""

    if benchmark_id == "notinject":
        return "benign"
    if benchmark_id.startswith("agentdojo") or benchmark_id == "ajatk":
        return "style_detectable"
    return _CORPUS_CLASSES.get((benchmark_id, dataset_id), "unclassified")
