import time
from .loader import parse_condition
from .observer import observe


def verify(
    adapter, health_check, boundary, expected, clock=time.monotonic, pause=time.sleep
):
    deadline = clock() + health_check["timeout_seconds"]
    while True:
        # Checking the kill switch and approval also protects the final boundary.
        boundary(expected, verification=True)
        values = [
            parse_condition(c).test(observe(adapter))
            for c in health_check["conditions"]
        ]
        if all(v is True for v in values):
            return clock() <= deadline
        if any(v is None for v in values) or clock() >= deadline:
            return False
        pause(min(0.02, max(0, deadline - clock())))


def rollback_once(runbook, execution, log):
    """One compensation pass in reverse order; never retry a failed restore."""
    receipts = execution["receipts"]
    if not any(original["action"] != "observe" for original, _ in receipts):
        return "NOT_NEEDED"
    errors = []

    def report(event, result):
        try:
            log(event, result)
        except Exception as exc:
            errors.append(f"Rollback audit unavailable: {exc}")

    for original, receipt in reversed(receipts):
        if original["action"] == "observe":
            continue
        options = [
            s
            for s in runbook["rollback"]
            if s["target"] == original["target"]
            and s.get("path") == original.get("path")
        ]
        try:
            if len(options) != 1:
                raise PermissionError("No unique declared compensation")
            current = observe(execution["guard"]._adapter)
            if any(
                current.get(k) != receipt["after"].get(k) for k in receipt["before"]
            ):
                raise RuntimeError(
                    "Rollback refused: affected state changed outside this action"
                )
            result = execution["guard"].rollback(options[0], receipt)
            restored = observe(execution["guard"]._adapter)
            if any(restored.get(k) != v for k, v in receipt["before"].items()):
                raise RuntimeError(
                    "Rollback verification failed: state was not restored"
                )
            report("rollback_step", {"target": original["target"], **result})
        except Exception as exc:
            errors.append(str(exc))
            report("rollback_failed", {"error": str(exc)})
    if errors:
        return "FAILED"
    return "COMPLETED"
