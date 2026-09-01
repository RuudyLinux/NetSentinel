import pytest

from app.services.ingestion import connect as connect_module
from app.services.ingestion.connect import DeviceConnectionError, fetch_running_config


class _FakeConnection:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.disconnected = False

    def send_command(self, command: str) -> str:
        assert command == "show running-config"
        return "hostname fake-device\nend\n"

    def disconnect(self) -> None:
        self.disconnected = True


class _FailingConnection:
    def __init__(self, **kwargs: object) -> None:
        raise TimeoutError("connection timed out")


def test_fetch_running_config_returns_the_device_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(connect_module, "ConnectHandler", _FakeConnection)
    text = fetch_running_config("10.0.0.1", 22, "admin", "secret", None)
    assert text == "hostname fake-device\nend\n"


def test_fetch_running_config_disconnects_after_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[_FakeConnection] = []

    def factory(**kwargs: object) -> _FakeConnection:
        conn = _FakeConnection(**kwargs)
        created.append(conn)
        return conn

    monkeypatch.setattr(connect_module, "ConnectHandler", factory)
    fetch_running_config("10.0.0.1", 22, "admin", "secret", "enable-secret")
    assert created[0].disconnected is True
    assert created[0].kwargs["secret"] == "enable-secret"


def test_connection_failure_is_wrapped_as_device_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connect_module, "ConnectHandler", _FailingConnection)
    with pytest.raises(DeviceConnectionError) as exc_info:
        fetch_running_config("10.0.0.1", 22, "admin", "wrong-password", None)
    # The device's own error surfaces, but the password never does.
    assert "wrong-password" not in str(exc_info.value)
    assert "10.0.0.1" in str(exc_info.value)
