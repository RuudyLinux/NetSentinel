from enum import StrEnum


class Permission(StrEnum):
    DEVICE_READ = "DEVICE_READ"
    DEVICE_WRITE = "DEVICE_WRITE"
    CONFIG_UPLOAD = "CONFIG_UPLOAD"
    AUDIT_RUN = "AUDIT_RUN"
    AUDIT_READ = "AUDIT_READ"
    FINDING_READ = "FINDING_READ"
    FINDING_TRIAGE = "FINDING_TRIAGE"
    REPORT_GENERATE = "REPORT_GENERATE"
    REPORT_READ = "REPORT_READ"
    USER_ADMIN = "USER_ADMIN"
    # Defined now so the role matrix is correct from the start; consumed by SP4.
    MAPPING_SUGGEST = "MAPPING_SUGGEST"
    MAPPING_APPROVE = "MAPPING_APPROVE"


_READ_ONLY = frozenset(
    {
        Permission.DEVICE_READ,
        Permission.AUDIT_READ,
        Permission.FINDING_READ,
        Permission.REPORT_READ,
        Permission.REPORT_GENERATE,
    }
)

_OPERATOR = _READ_ONLY | {
    Permission.CONFIG_UPLOAD,
    Permission.AUDIT_RUN,
    Permission.FINDING_TRIAGE,
    Permission.MAPPING_SUGGEST,
}

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "Security Admin": frozenset(_OPERATOR | {Permission.DEVICE_WRITE, Permission.MAPPING_APPROVE}),
    "Network Engineer": frozenset(_OPERATOR),
    "Security Analyst": frozenset(
        (_OPERATOR - {Permission.CONFIG_UPLOAD}) | {Permission.MAPPING_SUGGEST}
    ),
    "CISO": frozenset(_READ_ONLY),
    "Auditor": frozenset(_READ_ONLY),
    "Platform Admin": frozenset(Permission),
}

ROLE_NAMES: tuple[str, ...] = tuple(ROLE_PERMISSIONS)
