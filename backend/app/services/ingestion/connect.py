from netmiko import ConnectHandler

_CONNECT_TIMEOUT_SECONDS = 10


class DeviceConnectionError(Exception):
    """Raised when a live device could not be reached or authenticated to.

    Collapses Netmiko's various timeout/auth/SSH exceptions into one type so the API
    layer has a single thing to catch and map to a response.
    """


def fetch_running_config(
    host: str,
    port: int,
    username: str,
    password: str,
    enable_password: str | None,
) -> str:
    """Open an SSH session to a Cisco IOS/IOS-XE device and return `show running-config`.

    Credentials are used only for the duration of this call and never persisted or logged.
    """
    try:
        connection = ConnectHandler(
            device_type="cisco_ios",
            host=host,
            port=port,
            username=username,
            password=password,
            secret=enable_password or "",
            timeout=_CONNECT_TIMEOUT_SECONDS,
        )
        try:
            # send_command's return type is a union covering its use_textfsm/use_genie
            # structured-output modes; neither is requested here, so it's always plain text.
            output = connection.send_command("show running-config")
            assert isinstance(output, str)
            return output
        finally:
            connection.disconnect()
    except Exception as exc:
        raise DeviceConnectionError(f"could not fetch config from {host}:{port} ({exc})") from exc
