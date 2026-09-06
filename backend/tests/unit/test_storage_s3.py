from io import BytesIO
from typing import Any

import pytest
from botocore.exceptions import ClientError

from app.storage.base import StorageError
from app.storage.s3 import S3Storage


def _not_found(operation: str) -> ClientError:
    return ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, operation)


class FakeS3Client:
    """A minimal in-memory stand-in for boto3's S3 client — just enough surface
    for S3Storage, so these tests exercise real S3Storage code against realistic
    success/failure responses without needing network access or a dependency
    like moto."""

    def __init__(self) -> None:
        self.buckets: set[str] = set()
        self.objects: dict[tuple[str, str], bytes] = {}

    def head_bucket(self, *, Bucket: str) -> None:  # noqa: N803 - matches boto3's own kwarg casing
        if Bucket not in self.buckets:
            raise _not_found("HeadBucket")

    def create_bucket(self, *, Bucket: str) -> None:  # noqa: N803
        self.buckets.add(Bucket)

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> None:  # noqa: N803
        if Bucket not in self.buckets:
            raise _not_found("PutObject")
        self.objects[(Bucket, Key)] = Body

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        try:
            data = self.objects[(Bucket, Key)]
        except KeyError:
            raise _not_found("GetObject") from None
        return {"Body": BytesIO(data)}

    def head_object(self, *, Bucket: str, Key: str) -> None:  # noqa: N803
        if (Bucket, Key) not in self.objects:
            raise _not_found("HeadObject")


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> FakeS3Client:
    client = FakeS3Client()
    monkeypatch.setattr("app.storage.s3.boto3.client", lambda *a, **k: client)
    return client


def test_bucket_is_created_automatically_if_missing(fake_client: FakeS3Client) -> None:
    assert "netsentinel" not in fake_client.buckets
    S3Storage("netsentinel")
    assert "netsentinel" in fake_client.buckets


def test_existing_bucket_is_reused_not_recreated(fake_client: FakeS3Client) -> None:
    fake_client.buckets.add("netsentinel")
    S3Storage("netsentinel")
    assert fake_client.buckets == {"netsentinel"}


def test_round_trips_bytes(fake_client: FakeS3Client) -> None:
    storage = S3Storage("netsentinel")
    storage.put("configs/abc.cfg", b"hostname router")
    assert storage.get("configs/abc.cfg") == b"hostname router"
    assert storage.exists("configs/abc.cfg")


def test_missing_key_reports_absence_not_a_crash(fake_client: FakeS3Client) -> None:
    storage = S3Storage("netsentinel")
    assert not storage.exists("nope")
    with pytest.raises(StorageError):
        storage.get("nope")


def test_bucket_creation_failure_is_a_storage_error(
    monkeypatch: pytest.MonkeyPatch, fake_client: FakeS3Client
) -> None:
    def deny_create(*, Bucket: str) -> None:  # noqa: N803
        raise _not_found("CreateBucket")

    monkeypatch.setattr(fake_client, "create_bucket", deny_create)
    with pytest.raises(StorageError, match="cannot create or reach bucket"):
        S3Storage("netsentinel")


def test_put_failure_is_a_storage_error(
    monkeypatch: pytest.MonkeyPatch, fake_client: FakeS3Client
) -> None:
    storage = S3Storage("netsentinel")

    def deny_put(*, Bucket: str, Key: str, Body: bytes) -> None:  # noqa: N803
        raise _not_found("PutObject")

    monkeypatch.setattr(fake_client, "put_object", deny_put)
    with pytest.raises(StorageError, match="failed to write blob"):
        storage.put("configs/abc.cfg", b"data")


def test_endpoint_and_credentials_are_forwarded_to_boto3(
    monkeypatch: pytest.MonkeyPatch, fake_client: FakeS3Client
) -> None:
    captured: dict[str, Any] = {}

    def fake_client_factory(service: str, **kwargs: Any) -> FakeS3Client:
        captured.update(kwargs)
        return fake_client

    monkeypatch.setattr("app.storage.s3.boto3.client", fake_client_factory)
    S3Storage(
        "netsentinel",
        endpoint_url="http://minio:9000",
        access_key="netsentinel",
        secret_key="netsentinel-dev-only",
        region="us-east-1",
    )
    assert captured["endpoint_url"] == "http://minio:9000"
    assert captured["aws_access_key_id"] == "netsentinel"
    assert captured["aws_secret_access_key"] == "netsentinel-dev-only"
    assert captured["region_name"] == "us-east-1"
