from typing import Optional
from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError
from api.common.audit_logs_repository import AuditLogRepository
from api.common.base_repository import BaseRepository
from api.common.utils import get_logger
from api.core.exceptions import RoleAlreadyExistsException
from api.domain.dtos.audit_logs_dto import AuditLogDto
from api.domain.dtos.role_dto import CreateRoleDto, RoleListDto, UpdateRoleDto
from api.domain.entities.role import Role

logger = get_logger(__name__)


def _safe_log_value(value) -> str:
    # Path ids arrive percent-decoded, and BaseRepository.get() returns
    # None (rather than raising) for a malformed id, so a newline-bearing
    # id reaches the "not found" warnings below and could forge extra log
    # lines. Flatten CR/LF in the logged copy only; the raw id still
    # drives the lookup and the audit-log entries.
    return str(value).replace("\r", " ").replace("\n", " ")


class RoleRepository(BaseRepository[Role], AuditLogRepository):
    def __init__(self):
        super().__init__(Role)

    async def list (self, skip: int = 0, limit: int = 10, tenant_id: PydanticObjectId | None = None) -> RoleListDto:
        # Tenant-scoped listing: the filter applies to both the page
        # and the total, so pagination metadata (total/has_next) does
        # not leak another tenant's role count. No filter means the
        # historic global view (host callers).
        query = {"tenant_id": tenant_id} if tenant_id is not None else {}
        docs = await self.model.find(query).skip(skip).limit(limit).to_list()
        total = await self.model.find(query).count()
        result = RoleListDto(
            roles=[await doc.to_serializable_dict() for doc in docs],
            skip=skip,
            limit=limit,
            total=total,
            has_previous=skip > 0,
            has_next=skip + limit < total
        )
        return result

    async def create(
            self,
            data: CreateRoleDto,
        ) -> PydanticObjectId | None:
        new_role = Role(
           name=data.name,
           description=data.description,
           tenant_id=data.tenant_id
        )
        try:
            result = await super().create(new_role.model_dump())
        except DuplicateKeyError:
            # Race backstop for the service-level duplicate-name guard
            # (role_service.create_role): two concurrent creates with
            # the same name can both pass the single_or_none check
            # before either writes, so the second insert hits Role.name's
            # unique index. Map it to the same 409 the service check
            # returns instead of letting it escape as a 500 (the
            # central handler maps only ApiBaseException /
            # StarletteHTTPException). Name is the only unique index on
            # Role, so any DuplicateKeyError here is a name collision,
            # and data.name is the colliding name (the DTO requires it
            # and trims it via its model validator).
            logger.warning(f"Duplicate role name on create: {_safe_log_value(data.name)}")
            raise RoleAlreadyExistsException(name=data.name)
        await self.add_audit_log(AuditLogDto(
            action="create",
            changes={"Info": f"Create new role with name {data.name} and id {result.id}"},
            entity="Role",
            tenant_id=str(data.tenant_id) if data.tenant_id else None,
            user_id=None # Todo: Need to add a new property in role.. to determine who added it.
        ))
        return result.id


    async def update(self, role_id: str, data: UpdateRoleDto) -> Optional[Role]:
        existing_role = await super().get(role_id)

        try:
            updated_role = await super().update(id=role_id, data=data.model_dump(exclude_unset=True))
        except DuplicateKeyError:
            # Race backstop for the service-level duplicate-name guard
            # (role_service.update_role): two concurrent renames onto
            # the same name can both pass the single_or_none check
            # before either writes, so the second write hits Role.name's
            # unique index. Map it to the same 409 the service check
            # returns instead of letting it escape as a 500 (the
            # central handler maps only ApiBaseException /
            # StarletteHTTPException). Name is the only unique index on
            # Role, so any DuplicateKeyError here is a name collision,
            # and data.name is the colliding name (the DTO requires it,
            # and the update carries no name change when it is unset).
            logger.warning(f"Duplicate role name on update: {_safe_log_value(data.name)}")
            raise RoleAlreadyExistsException(name=data.name)
        if updated_role:
            existing_role_doc = await existing_role.to_serializable_dict()
            await self.add_audit_log(AuditLogDto(
                action="update",
                changes={"new": data.model_dump(exclude_unset=True, exclude_none=True), "old": existing_role_doc},
                entity="Role",
                tenant_id=str(updated_role.tenant_id) if updated_role.tenant_id else None,
                user_id=None # Todo: Need to add a new property in role.. to determine who updated it.
            ))
            return updated_role
        logger.warning(f"No role found for the given role id: {_safe_log_value(role_id)}")
        await self.add_audit_log(AuditLogDto(
            action="update",
            changes={"Info": f"Attempted to update role with id {role_id}, but it was not found."},
            entity="Role",
            tenant_id=str(data.tenant_id) if data.tenant_id else None,
            user_id=None # Todo: Need to add a new property in role.. to determine who updated it.
        ))
        return None

    async def delete(self, id: str) -> bool:
        existing_role = await super().get(id)
        if not existing_role:
            logger.warning(f"No role found for the given role id: {_safe_log_value(id)}")
            await self.add_audit_log(AuditLogDto(
                action="delete",
                changes={"Info": f"Attempted to delete role with id {id}, but it was not found."},
                entity="Role",
                tenant_id=None,
                user_id=None # Todo: Need to add a new property in role.. to determine who deleted it.
            ))
            return False

        await super().delete(id)
        await self.add_audit_log(AuditLogDto(
            action="delete",
            changes={"Info": f"Deleted role with id {id}"},
            entity="Role",
            tenant_id=str(existing_role.tenant_id) if existing_role.tenant_id else None,
            user_id=None # Todo: Need to add a new property in role.. to determine who deleted it.
        ))

        return True
