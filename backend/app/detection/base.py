from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.alert import Alert
from app.models.event import LogEvent


class BaseDetector(ABC):
    name: str

    @abstractmethod
    def process(self, event: LogEvent) -> list[Alert]:
        raise NotImplementedError

    @abstractmethod
    def reset(self) -> None:
        raise NotImplementedError
