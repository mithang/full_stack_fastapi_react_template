import re

from beanie import PydanticObjectId
from api.common.utils import get_logger
from api.core.exceptions import RoleAlreadyExistsException, RoleNotFoundException
from api.domain.dtos.role_dto import CreateRoleDto, RoleListDto, UpdateRoleDto, UpdateRoleDto
from api.domain.entities.role import Role
from api.infrastructure.persistence.repositories.role_repository_impl import RoleRepository

logger = get_logger(__name__)


def _caller_may_access(record_tenant_id: PydanticObjectId | None, caller_tenant_id: str | PydanticObjectId | None) -> bool:
    # Single-record scope rule, mirroring list_roles(): host callers
    # (tenant_id None) may access any record; a tenant caller may
    # access only records stamped with their own tenant_id. A
    # malformed caller id cannot match any record, so it fails closed.
    if caller_tenant_id is None:
        return True
    try:
        caller_oid = PydanticObjectId(caller_tenant_id)
    except Exception:
        return False
    return record_tenant_id == caller_oid


class RoleService:
    def __init__(self, role_repository: RoleRepository):
        self.role_repository = role_repository
        logger.info("Initialized.")

    async def list_roles(self, skip: int = 0, limit: int = 10, tenant_id: str | PydanticObjectId | None = None) -> RoleListDto:
        # Tenant callers see only their tenant's roles; host callers
        # (tenant_id None) keep the global view. A malformed tenant id
        # cannot match any role, so fail closed with an empty page
        # rather than falling back to the unscoped list.
        tenant_oid = None
        if tenant_id:
            try:
                tenant_oid = PydanticObjectId(tenant_id)
            except Exception:
                return RoleListDto(roles=[], skip=skip, limit=limit, total=0, has_previous=skip > 0, has_next=False)
        return await self.role_repository.list(skip=skip, limit=limit, tenant_id=tenant_oid)
    
    async def find_by_name(self, name: str) -> Role:
        """Find a role by its name. Raises RoleNotFoundException if not found."""
        existing = await self.role_repository.single_or_none(name=name)
        if existing is None:
            raise RoleNotFoundException(role_id=name)
        return existing

    async def search_role_by_name(self, name: str, tenant_id: str | PydanticObjectId | None = None) -> list[Role]:
        # Escape the user-supplied name: it is a literal role name, not a
        # pattern, so unescaped metacharacters (e.g. ".*", "[") previously
        # changed the match semantics or errored on an invalid pattern.
        # Escaping keeps the case-insensitive substring match intact.
        # Tenant callers see only their tenant's roles; host callers
        # (tenant_id None) keep the global view, the same scope rule as
        # list_roles. A malformed tenant id cannot match any role, so
        # fail closed with an empty list rather than falling back to
        # the unscoped search.
        # Trim before searching: stored role names are always trimmed
        # (CreateRoleDto/UpdateRoleDto validator), so a padded query
        # can never match by its spaces — it only turns a real match
        # into an empty result. The frontend already trims, but a
        # direct API client bypasses the form; and because this is a
        # substring match, trimming can only widen results (any string
        # containing " Admin " also contains "Admin"), never narrow
        # them, so no stored name stops matching.
        name = name.strip()
        query: dict = {"name": {"$regex": re.escape(name), "$options": "i"}}
        if tenant_id:
            try:
                query["tenant_id"] = PydanticObjectId(tenant_id)
            except Exception:
                return []
        return await self.role_repository.search(query)

    async def get_role_by_id(self, role_id: str, tenant_id: str | PydanticObjectId | None = None) -> Role:
        existing = await self.role_repository.get(id=role_id)
        if existing is None:
            raise RoleNotFoundException(role_id=role_id)
        if not _caller_may_access(existing.tenant_id, tenant_id):
            # Cross-tenant read: same 404 as an unknown id, so probing
            # another tenant's id reveals neither its existence nor its
            # name/permissions. Host callers (tenant_id None) keep the
            # global view, the same scope rule as list_roles() — and a
            # host-stamped record (tenant_id None) is not visible to a
            # tenant caller, matching the list filter which only returns
            # the caller's own rows.
            raise RoleNotFoundException(role_id=role_id)
        return existing

    async def create_role(self, role_data: CreateRoleDto) -> PydanticObjectId:
        existing = await self.role_repository.single_or_none(name=role_data.name)
        if existing is not None:
            raise RoleAlreadyExistsException(name=role_data.name)
        return await self.role_repository.create(data=role_data) 

    async def update_role(self, role_id: str, role_data: UpdateRoleDto, tenant_id: str | PydanticObjectId | None = None) -> Role | None:
        existing = await self.role_repository.get(id=role_id)
        if existing is None:
            raise RoleNotFoundException(role_id=role_id)
        if not _caller_may_access(existing.tenant_id, tenant_id):
            # Cross-tenant write: same 404 as an unknown id (and raised
            # before any write), so probing another tenant's id reveals
            # nothing and cannot overwrite its name or permissions.
            raise RoleNotFoundException(role_id=role_id)
        # Pin the tenant stamp server-side, mirroring the create path
        # (iteration 870): UpdateRoleDto inherits the client-supplied
        # tenant_id from CreateRoleDto, and the repository applies
        # whatever it carries, so a caller who may update their own
        # role could otherwise re-stamp it to another tenant's id —
        # moving it into that tenant's role list — or to None, making
        # it host-visible. The legitimate frontend sends only name and
        # description on update, so no legitimate update is affected.
        role_data.tenant_id = existing.tenant_id
        return await self.role_repository.update(role_id=role_id, data=role_data)

    async def delete_role(self, role_id: str, tenant_id: str | PydanticObjectId | None = None) -> None:
        # Scope check first: a cross-tenant delete must be
        # indistinguishable from deleting an unknown id, so the same
        # 404 is raised before any delete — and before the endpoint's
        # assigned-users check, which would otherwise confirm the
        # record exists via its "cannot delete" error.
        await self.get_role_by_id(role_id, tenant_id=tenant_id)
        if await self.role_repository.delete(id=role_id) is False:
            raise RoleNotFoundException(role_id=role_id)

    async def total_count(self) -> int:
        return await self.role_repository.count()