from collections.abc import Callable

from app.tasks.base import TaskRunner

__all__ = ["InlineTaskRunner", "TaskRunner", "get_task_runner"]


class InlineTaskRunner:
    """Runs work synchronously.

    Slice 1 audits parse a file under 5 MB and evaluate 16 rules — well inside a
    request. Making this async before it is slow would buy complexity, not speed.
    """

    def submit(self, fn: Callable[..., None], /, *args: object) -> None:
        fn(*args)


def get_task_runner() -> TaskRunner:
    return InlineTaskRunner()
