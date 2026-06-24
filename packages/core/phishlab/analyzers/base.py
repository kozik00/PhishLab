from __future__ import annotations

from abc import ABC, abstractmethod

from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Finding


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        ...
