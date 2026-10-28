from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ScopedCredential:
    runbook_id: str
    capabilities: tuple


class Adapter(ABC):
    @abstractmethod
    def read_state(self): ...

    @abstractmethod
    def run_step(self, step, credential): ...

    @abstractmethod
    def rollback_step(self, step, credential, receipt): ...


class StepError(RuntimeError):
    def __init__(self, message, receipt):
        super().__init__(message)
        self.receipt = receipt
