"""Six narrated, deterministic demonstrations; never contacts Docker."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aegisops.audit import check_complete
from aegisops.evaluation import SCENARIOS
from aegisops.orchestrator import Engine


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print decisions and plans without any adapter actions",
    )
    args = parser.parse_args()
    print("AEGISOPS — POLICY-GATED REMEDIATION DEMO")
    print("SIMULATE ONLY · Authored demo fixtures, not organizer ground truth.\n")
    for index, scenario in enumerate(SCENARIOS, 1):
        engine = Engine()
        engine.adapter.inject(scenario["fault"])
        if scenario.get("setup") == "fail_remediation":
            engine.adapter.fail_remediation = True
        elif scenario.get("setup") == "kill_after_step":
            engine.adapter.after_step = lambda *_: engine.killswitch.set(True)
        print("=" * 72)
        print(scenario["title"])
        result = engine.run(dry_run=args.dry_run)
        if result["outcome"] == "NEEDS_APPROVAL":
            print("Policy: NEEDS_APPROVAL. No action has executed.")
            engine.approvals.approve(
                result["approval_id"],
                "demo-on-call",
                "Reviewed exact certificate rotation plan and staging scope",
            )
            result = engine.resume(result["approval_id"])
        if args.dry_run:
            assert not engine.adapter.calls
            print("Plan:", json.dumps(result.get("plan", []), indent=2))
        else:
            assert result["outcome"] == scenario["expected"], (
                scenario["title"],
                result,
            )
        record = result["audit"]
        assert check_complete(record) == []
        print("Outcome:", result["outcome"], "| policy:", result["decision"]["outcome"])
        print("Reasons:", "; ".join(result["decision"]["reasons"]))
        print("Audit:", json.dumps(record, indent=2))
        print(
            f"Adapter calls: {len(engine.adapter.calls)} | change snapshots: {len(engine.store.changes())} | completeness: 100%\n"
        )
    print("All six demonstrations completed.")


if __name__ == "__main__":
    main()
