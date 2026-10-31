from api.common.audit_logs_repository import AuditLogRepository
from api.common.base_repository import BaseRepository
from api.domain.dtos.audit_logs_dto import AuditLogDto
from api.domain.entities.user_password_reset import UserPasswordReset
from beanie import PydanticObjectId
from api.common.utils import get_utc_now, get_logger
logger = get_logger(__name__)

class UserPasswordResetRepository(BaseRepository[UserPasswordReset], AuditLogRepository):
    def __init__(self):
        super().__init__(UserPasswordReset)

    async def set_password_reset(self, user_id: str, first_name: str, tenant_id: str | None = None) -> UserPasswordReset:
        existing = await self.single_or_none(user_id=PydanticObjectId(user_id))
        token_secret = PydanticObjectId()
        if existing:
            existing.token_secret = str(token_secret)
            existing.reset_secret_updated_at = get_utc_now()
            logger.info(f"Updating password reset for user {user_id}")
            ex = await existing.save()
            await self.add_audit_log(AuditLogDto(
                action="update",
                entity="UserPasswordReset",
                user_id=user_id,
                changes={"Info": "Updated password with reset token"},
                tenant_id=tenant_id
            ))
            return ex
        new_reset = UserPasswordReset(
            user_id = user_id,
            token_secret = str(token_secret),
            reset_secret_updated_at = get_utc_now(),
            tenant_id=tenant_id,
            first_name=first_name
        )
        logger.info(f"Creating password reset for user {user_id}")
        res = await self.create(data = new_reset.model_dump())
        await self.add_audit_log(AuditLogDto(
            action="create",
            entity="UserPasswordReset",
            user_id=user_id,
            changes={"Info": "Created password reset with token"},
            tenant_id=tenant_id
        ))
        return res
    

    async def delete_by_user_id(self, user_id: str) -> bool:
        # Same malformed-id guard as retrieve_password_reset_data_by_user_id
        # and the magic-link validate path: a tampered/truncated user_id
        # cannot match any stored record, so treat it as "not found"
        # (False, with the same audit entry) instead of letting the
        # PydanticObjectId() conversion escape as a 500. This is the
        # last unguarded direct conversion on a caller-supplied id in
        # the repositories: the sibling lookups are already guarded,
        # and the user-preference conversions only ever receive the
        # JWT-validated current_user.id. The catch is broad on purpose,
        # as in BaseRepository.get: bson raises InvalidId while the
        # pydantic-validated paths raise ValidationError.
        try:
            user_oid = PydanticObjectId(user_id)
        except Exception:
            logger.warning(f"Password reset not found for malformed user {user_id}")
            await self.add_audit_log(AuditLogDto(
                action="delete",
                entity="UserPasswordReset",
                user_id=user_id,
                changes={"Info": "Attempted to delete non-existing password reset"},
                tenant_id=None
            ))
            return False
        existing = await self.single_or_none(user_id=user_oid)
        if existing is None:
            logger.warning(f"Password reset not found for user {user_id}")
            await self.add_audit_log(AuditLogDto(
                action="delete",
                entity="UserPasswordReset",
                user_id=user_id,
                changes={"Info": "Attempted to delete non-existing password reset"},
                tenant_id=None
            ))
            return False
        await existing.delete()
        logger.info(f"Deleted password reset for user {user_id}")
        await self.add_audit_log(AuditLogDto(
            action="delete",
            entity="UserPasswordReset",
            user_id=user_id,
            changes={"Info": "Deleted password reset"},
            tenant_id=existing.tenant_id if existing.tenant_id else None
        ))
        return True
