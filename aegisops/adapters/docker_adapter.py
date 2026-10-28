"""Fail-closed placeholder: the authorized Docker environment was not supplied.

Do not mount a Docker socket into this demo: access to it is host-level authority.
Implement typed operations with workload-enforced scoped credentials before
replacing this adapter. The simulation never falls back to live commands.
"""

from .base import Adapter


class DockerAdapter(Adapter):
    def __init__(self, *args, **kwargs):
        raise RuntimeError(
            "Live Docker execution is unavailable: missing authorized environment and per-workload credentials"
        )

    def read_state(self):
        raise RuntimeError("Live mode disabled")

    def run_step(self, step, credential):
        raise RuntimeError("Live mode disabled")

    def rollback_step(self, step, credential, receipt):
        raise RuntimeError("Live mode disabled")
