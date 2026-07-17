from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdGenerator(Protocol):
    def new(self, prefix: str, slug: str | None = None) -> str: ...


class ArtifactStore(Protocol):
    def put(self, source: Path, *, digest: str) -> str: ...
    def get(self, reference: str) -> Path: ...
