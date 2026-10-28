from copy import deepcopy
from .adapters.base import ScopedCredential
from .policy import inside


class ExecutionAborted(RuntimeError):
    pass


class CapabilityGuard:
    def __init__(self, adapter, runbook):
        self._adapter = adapter
        self.credential = ScopedCredential(
            runbook["id"], tuple(deepcopy(runbook["capabilities"]))
        )

    def check(self, step):
        for cap in self.credential.capabilities:
            if cap["action"] != step["action"] or cap["target"] != step["target"]:
                continue
            if ("path" in step) != ("path" in cap):
                continue
            # Exact resource scoping avoids implicit recursive directory privileges.
            if step.get("path") != cap.get("path"):
                continue
            if any(
                step.get(k, 0) > cap.get(k, 0)
                for k in ("bytes", "replicas", "restarts")
            ):
                continue
            return
        raise PermissionError(
            f"Capability rejected {step['action']} on {step['target']}"
        )

    def run(self, step):
        self.check(step)
        return self._adapter.run_step(deepcopy(step), self.credential)

    def rollback(self, step, receipt):
        self.check(step)
        return self._adapter.rollback_step(deepcopy(step), self.credential, receipt)


class Executor:
    def __init__(self, adapter, authority):
        self.adapter, self.authority = adapter, authority

    def run(self, action_id, runbook, token, initial_observation, boundary, log):
        if not self.authority.validate(token, action_id, runbook):
            raise PermissionError("A valid deterministic policy grant is required")
        if runbook["tier"] == "T3":
            raise PermissionError("T3 cannot enter execution")
        guard = CapabilityGuard(self.adapter, runbook)
        receipts = []
        results = []
        expected = deepcopy(initial_observation)
        try:
            # Reject the entire plan before the first adapter action.
            for step in runbook["steps"] + runbook["rollback"]:
                guard.check(step)
            for index, step in enumerate(runbook["steps"]):
                if not self.authority.validate(token, action_id, runbook):
                    raise ExecutionAborted("Policy grant revoked")
                boundary(expected)
                log("step_start", results)
                try:
                    receipt = guard.run(step)
                except Exception as exc:
                    receipt = getattr(exc, "receipt", None)
                    if receipt is not None:
                        receipts.append((step, receipt))
                    raise
                receipts.append((step, receipt))
                results.append(
                    {
                        "step": index + 1,
                        "action": step["action"],
                        "target": step["target"],
                        "status": "SUCCEEDED",
                    }
                )
                expected = receipt["after"]
                log("step_result", results)
            return {
                "receipts": receipts,
                "steps": results,
                "error": None,
                "guard": guard,
                "expected": expected,
            }
        except Exception as exc:
            results.append({"status": "ABORTED", "error": str(exc)})
            return {
                "receipts": receipts,
                "steps": results,
                "error": str(exc),
                "guard": guard,
                "expected": expected,
            }
