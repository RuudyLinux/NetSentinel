import logging
from typing import Protocol

logger = logging.getLogger(__name__)


class PasswordResetDelivery(Protocol):
    """Seam for actually getting a reset token to the user (email, SMS, ...).

    Mirrors app/tasks/base.py's TaskRunner seam: the token-issuance architecture
    is real (see api/auth.py), but no deployment target is wired yet. Swap
    `get_reset_delivery()` for a real implementation (SMTP/SES/etc.) once one
    exists — nothing else in the reset flow needs to change.
    """

    def deliver(self, *, email: str, token: str) -> None: ...


class LoggingPasswordResetDelivery:
    """Development-only stand-in: logs the token instead of emailing it.

    This makes the reset flow usable end-to-end (e.g. for local testing or a
    demo) without pretending an email was actually sent. Never wire this into
    a production deployment — see the docstring on PasswordResetDelivery.
    """

    def deliver(self, *, email: str, token: str) -> None:
        logger.info(
            "Password reset requested for %s; token=%s "
            "(no email provider configured — see app/security/reset_delivery.py)",
            email,
            token,
        )


def get_reset_delivery() -> PasswordResetDelivery:
    return LoggingPasswordResetDelivery()
