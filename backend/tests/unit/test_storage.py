from pathlib import Path

import pytest

from app.storage.local import LocalFileStorage, StorageError


def test_round_trips_bytes(tmp_path: Path) -> None:
    storage = LocalFileStorage(tmp_path)
    storage.put("configs/abc.cfg", b"hostname router")
    assert storage.get("configs/abc.cfg") == b"hostname router"
    assert storage.exists("configs/abc.cfg")


def test_missing_key_reports_absence_not_a_crash(tmp_path: Path) -> None:
    storage = LocalFileStorage(tmp_path)
    assert not storage.exists("nope")
    with pytest.raises(StorageError):
        storage.get("nope")


def test_nested_keys_create_directories(tmp_path: Path) -> None:
    storage = LocalFileStorage(tmp_path)
    storage.put("a/b/c/d.bin", b"x")
    assert (tmp_path / "a" / "b" / "c" / "d.bin").exists()


@pytest.mark.parametrize("key", ["../escape", "a/../../escape", "/absolute", "a/./../../x"])
def test_keys_cannot_escape_the_storage_root(tmp_path: Path, key: str) -> None:
    """Blob keys derive from user input; traversal must be impossible, not merely unlikely."""
    storage = LocalFileStorage(tmp_path)
    with pytest.raises(StorageError):
        storage.put(key, b"x")
