from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require
from app.config import settings
from app.models import User
from app.schemas.findings import FrameworkOut
from app.security.permissions import Permission
from app.services.compliance.rules import load_all_packs

router = APIRouter(prefix="/frameworks", tags=["frameworks"])


@router.get("", response_model=list[FrameworkOut])
def list_frameworks(
    _: User = Depends(require(Permission.AUDIT_READ)),
) -> list[FrameworkOut]:
    return [
        FrameworkOut(
            framework=pack.framework,
            framework_version=pack.framework_version,
            rule_count=len(pack.rules),
            sha256=pack.sha256,
        )
        for pack in load_all_packs(settings.rules_dir)
    ]


@router.get("/{framework}/rules")
def list_rules(
    framework: str,
    _: User = Depends(require(Permission.AUDIT_READ)),
) -> list[dict[str, object]]:
    for pack in load_all_packs(settings.rules_dir):
        if pack.framework.upper() == framework.upper():
            return [rule.model_dump(mode="json") for rule in pack.rules]
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Framework not found")
