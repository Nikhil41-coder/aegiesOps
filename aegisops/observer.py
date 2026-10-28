from copy import deepcopy
import math


def observe(adapter):
    state = adapter.read_state()
    if not isinstance(state, dict):
        raise ValueError("Adapter returned no observation")
    clean = {}
    for key, value in state.items():
        if not isinstance(key, str) or type(value) not in (
            str,
            int,
            float,
            bool,
            type(None),
        ):
            raise ValueError("Observation metrics must be named scalar values")
        clean[key] = (
            None if isinstance(value, float) and not math.isfinite(value) else value
        )
    return deepcopy(clean)
