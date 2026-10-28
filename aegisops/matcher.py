"""Conservative matching; no LLM has execution authority."""

from .loader import parse_condition


def match(runbooks, observation):
    full, partial, blocked, unknown = [], [], [], False
    for rb in runbooks:
        applies = [parse_condition(c).test(observation) for c in rb["applies_when"]]
        excludes = [parse_condition(c).test(observation) for c in rb["not_when"]]
        if None in applies or None in excludes:
            unknown = True
        if any(v is True for v in excludes):
            if all(v is True for v in applies):
                blocked.append(rb["id"])
            continue
        if all(v is True for v in applies) and all(v is False for v in excludes):
            full.append(rb)
        elif any(v is True for v in applies):
            partial.append(rb["id"])
    ambiguous = len(full) > 1 or bool(partial)
    rb = full[0] if len(full) == 1 else None
    return {
        "runbook": rb,
        "confidence": 1.0 if rb else (0.5 if partial else 0.0),
        "ambiguous": ambiguous,
        "unknown": unknown,
        "full_matches": [r["id"] for r in full],
        "partial_matches": partial,
        "blocked": blocked,
    }
