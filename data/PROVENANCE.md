# Input provenance

`source_csv/` contains the eight unmodified files from the supplied ZIP. They describe 3,000 synthetic historical incidents and illustrative policies.

The task references `ao04-dataset/policy.yaml`, `runbooks/runbooks.yaml`, `scenarios.yaml`, `env/docker-compose.yml`, and `faults/inject.sh`. None was included. All YAML and scenario files outside `source_csv/` are authored demo fixtures, not conversions of or substitutes for organizer ground truth. Scenario test results apply only to these authored fixtures. Historical approvals never authorize a new action. No production credentials are included.

The optional live Docker integration is deliberately unavailable until authorized environment definitions and adapter implementations exist.
