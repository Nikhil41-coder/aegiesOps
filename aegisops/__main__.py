import argparse
import json
from .adapters.mock import FAULTS
from .orchestrator import Engine


def main():
    parser = argparse.ArgumentParser(
        description="Run one AegisOps simulation detection cycle"
    )
    parser.add_argument("--fault", choices=sorted(FAULTS), default="log_full")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    engine = Engine()
    engine.adapter.inject(args.fault)
    print(json.dumps(engine.run(dry_run=args.dry_run), indent=2))


if __name__ == "__main__":
    main()
