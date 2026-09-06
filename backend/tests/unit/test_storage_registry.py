from typing import Any

import pytest

from app.config import settings
from app.storage.local import LocalFileStorage
from app.storage.registry import get_storage


def test_default_backend_is_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "storage_backend", "local")
    assert isinstance(get_storage(), LocalFileStorage)


def test_s3_backend_is_selected_and_configured_from_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeS3Storage:
        def __init__(self, bucket: str, **kwargs: Any) -> None:
            captured["bucket"] = bucket
            captured.update(kwargs)

    monkeypatch.setattr(settings, "storage_backend", "s3")
    monkeypatch.setattr(settings, "s3_bucket", "netsentinel-test")
    monkeypatch.setattr(settings, "s3_endpoint_url", "http://minio:9000")
    monkeypatch.setattr(settings, "s3_access_key", "key")
    monkeypatch.setattr(settings, "s3_secret_key", "secret")
    monkeypatch.setattr(settings, "s3_region", "eu-west-1")
    monkeypatch.setattr("app.storage.s3.S3Storage", FakeS3Storage)

    storage = get_storage()

    assert isinstance(storage, FakeS3Storage)
    assert captured == {
        "bucket": "netsentinel-test",
        "endpoint_url": "http://minio:9000",
        "access_key": "key",
        "secret_key": "secret",
        "region": "eu-west-1",
    }
