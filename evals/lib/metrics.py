"""Score-based classification metrics shared by the eval entry points.

All functions take parallel sequences of raw detector scores in [0, 1] and
boolean attack labels (True = attack). Callers map "no Detection observed"
to score 0.0 before calling, matching the deployment semantics
`detected iff score > threshold`.
"""

from __future__ import annotations

from collections.abc import Sequence


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def confusion_at(
    scores: Sequence[float],
    labels: Sequence[bool],
    cut: float,
    *,
    inclusive: bool = False,
) -> dict[str, float | int | None]:
    """Confusion counts at one score cut; ``inclusive`` matches ``score >= cut``."""

    if len(scores) != len(labels):
        raise ValueError("scores and labels must have the same length")
    above = [(score >= cut if inclusive else score > cut) for score in scores]
    tp = sum(1 for hit, label in zip(above, labels, strict=True) if hit and label)
    fn = sum(1 for hit, label in zip(above, labels, strict=True) if not hit and label)
    fp = sum(1 for hit, label in zip(above, labels, strict=True) if hit and not label)
    tn = sum(1 for hit, label in zip(above, labels, strict=True) if not hit and not label)
    attacks = tp + fn
    benign = tn + fp
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "recall": _ratio(tp, attacks),
        "false_positive_rate": _ratio(fp, benign),
        "precision": _ratio(tp, tp + fp),
    }


def roc_auc(positives: Sequence[float], negatives: Sequence[float]) -> float | None:
    """Rank-based AUC (Mann-Whitney) with tie handling; None without both classes."""

    if not positives or not negatives:
        return None
    ordered = sorted([*positives, *negatives])
    ranks: dict[float, float] = {}
    index = 0
    while index < len(ordered):
        stop = index
        while stop < len(ordered) and ordered[stop] == ordered[index]:
            stop += 1
        ranks[ordered[index]] = (index + 1 + stop) / 2
        index = stop
    rank_sum = sum(ranks[score] for score in positives)
    count = len(positives) * len(negatives)
    return round((rank_sum - len(positives) * (len(positives) + 1) / 2) / count, 6)


def _distinct_cut_outcomes(
    scores: Sequence[float],
    labels: Sequence[bool],
) -> list[dict[str, float | int | None]]:
    distinct = sorted(set(scores), reverse=True)
    return [confusion_at(scores, labels, cut, inclusive=True) for cut in distinct]


def precision_at_recall(
    scores: Sequence[float],
    labels: Sequence[bool],
    targets: Sequence[float],
) -> dict[str, float | None]:
    """Best precision over all distinct score cuts that reach each recall target."""

    candidates = _distinct_cut_outcomes(scores, labels)
    result: dict[str, float | None] = {}
    for target in targets:
        eligible = [
            outcome["precision"]
            for outcome in candidates
            if outcome["recall"] is not None
            and outcome["recall"] >= target
            and outcome["precision"] is not None
        ]
        result[str(target)] = max(eligible) if eligible else None
    return result


def recall_at_fpr(
    scores: Sequence[float],
    labels: Sequence[bool],
    targets: Sequence[float],
) -> dict[str, float | None]:
    """Best recall over all distinct score cuts whose FPR stays within each target."""

    candidates = _distinct_cut_outcomes(scores, labels)
    result: dict[str, float | None] = {}
    for target in targets:
        eligible = [
            outcome["recall"]
            for outcome in candidates
            if outcome["false_positive_rate"] is not None
            and outcome["false_positive_rate"] <= target
            and outcome["recall"] is not None
        ]
        result[str(target)] = max(eligible) if eligible else None
    return result
