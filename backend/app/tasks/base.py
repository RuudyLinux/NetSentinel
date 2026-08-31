from collections.abc import Callable
from typing import Protocol


class TaskRunner(Protocol):
    """Deferred work seam. SP6 swaps this for a Celery-backed implementation."""

    def submit(self, fn: Callable[..., None], /, *args: object) -> None: ...
