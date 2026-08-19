"""Shared eval infrastructure (layer 2 of the eval reorganization; see evals/README.md).

Stdlib-only on purpose: these modules are imported both by evals that run in
the repository virtualenv (prompt_injection, detection) and by evals/corpus,
the corpus-generation model-profile environment.
"""
