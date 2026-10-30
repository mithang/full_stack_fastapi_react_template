from typing import Any
from beanie import PydanticObjectId
from pydantic import EmailStr
from api.common.exceptions import InvalidOperationException
from api.common.utils import get_logger, get_utc_now, validate_password
from api.core.exceptions import EmailAlreadyExistsException, RoleNotFoundException, UserNotFoundException
from api.domain.dtos.dashboard_dto import TimeSeriesDto
from api.domain.entities.user import User
from api.domain.dtos.user_dto import CreateUserDto, UpdateUserDto, UserListDto
from api.domain.entities.user_password_reset import UserPasswordReset
from api.infrastructure.persistence.repositories.user_password_reset_repository_impl import UserPasswordResetRepository
from api.infrastructure.persistence.repositories.user_repository_impl import UserRepository
from api.common.security import hash_it

logger = get_logger(__name__)


def _caller_may_access(record_tenant_id: PydanticObjectId | None, caller_tenant_id: str | PydanticObjectId | None) -> bool:
    # Single-record scope rule, mirroring list_users() and the role
    # service's get_role_by_id(): host callers (tenant_id None) may
    # access any record; a tenant caller may access only records
    # stamped with their own tenant_id. A malformed caller id cannot
    # match any record, so it fails closed. Self-access is unaffected:
    # a caller's tenant_id comes from their own user record, so their
    # own record always carries that same tenant_id.
    if caller_tenant_id is None:
        return True
    try:
        caller_oid = PydanticObjectId(caller_tenant_id)
    except Exception:
        return False
    return record_tenant_id == caller_oid


class UserService:
    def __init__(
            self,
            user_repository: UserRepository,
            user_password_reset_repository: UserPasswordResetRepository
        ):

        self.user_repository = user_repository
        self.user_password_reset_repository = user_password_reset_repository
        logger.info("Initialized.")


    async def list_users(self, skip: int = 0, limit: int = 10, tenant_id: str | None = None) -> UserListDto:
        # Tenant callers see only their tenant's users; host callers
        # (tenant_id None) keep the global view. A malformed tenant id
        # cannot match any user, so fail closed with an empty page
        # rather than falling back to the unscoped list.
        tenant_oid = None
        if tenant_id:
            try:
                tenant_oid = PydanticObjectId(tenant_id)
            except Exception:
                return UserListDto(users=[], skip=skip, limit=limit, total=0, has_previous=skip > 0, has_next=False)
        return await self.user_repository.list(skip=skip, limit=limit, tenant_id=tenant_oid)

    async def find_by_email(self, email: EmailStr) -> User:
        """Find user by email. Returns User model. Raises UserNotFoundException if not found."""
        existing = await self.user_repository.single_or_none(email=email)
        if existing is None:
            raise UserNotFoundException(email)
        return existing
    
    async def get_user_by_id(self, user_id: str, tenant_id: str | PydanticObjectId | None = None) -> User:
        """Get user by ID. Returns User model. Raises UserNotFoundException if not found."""
        existing = await self.user_repository.get(id=user_id)
        if existing is None:
            raise UserNotFoundException(user_id)
        if not _caller_may_access(existing.tenant_id, tenant_id):
            # Cross-tenant read: same 404 as an unknown id, so probing
            # another tenant's id reveals neither its existence nor its
            # name/email/role. Host callers (tenant_id None) keep the
            # global view, the same scope rule as list_users() — and a
            # host-stamped record (tenant_id None) is not visible to a
            # tenant caller, matching the list filter which only returns
            # the caller's own rows. Callers that omit tenant_id (auth,
            # current-user resolution, background jobs) are unaffected.
            raise UserNotFoundException(user_id)
        return existing

    async def assert_profile_image_owned(self, image_key: str, tenant_id: str | PydanticObjectId | None = None) -> None:
        """Fail unless some user in the caller's scope stores this key as their profile picture.

        The profile-image endpoint mints a presigned URL for an arbitrary
        storage key, and the scope guard in the controller only checks
        which database served the request — so any authenticated caller
        with USER_VIEW_ONLY could mint URLs for any object in the shared
        bucket (another tenant's avatar, or any other stored object whose
        uuid-prefixed key they learn) as long as the request hit their
        own tenant DB. Legitimate callers only ever pass a user's stored
        image_url (the auth provider and the user table both pass the
        value verbatim, and both already tolerate a rejection with a
        fallback avatar), so requiring an owning user record closes the
        arbitrary-key minting without changing those flows. Ownership is
        checked with the same stamp rule as get_user_by_id(): host
        callers (tenant_id None) keep the global view, a tenant caller
        needs an owner stamped with their own tenant, and an unknown or
        cross-tenant key answers with the same 404 as an unknown user
        id, so probing a key reveals neither its existence nor its
        owner. All owners are considered (not just the first match) so
        a key legitimately stored on two users is not denied because
        the first match belongs to another tenant.
        """
        owners = await self.user_repository.search({"image_url": image_key})
        if not any(_caller_may_access(owner.tenant_id, tenant_id) for owner in owners):
            raise UserNotFoundException(image_key)

    async def create_user(self, user_data: CreateUserDto, *, skip_password_validation: bool = False, skip_password_hashing: bool = False) -> PydanticObjectId:
        """Create a new user and returns its ID. Raises EmailAlreadyExistsException if email already exists."""
        # Enforce the same password policy as tenant creation (iteration 427)
        # and password reset (iteration 428) for user-chosen passwords.
        # Only SSO signups skip it: they pass a random, undisclosed
        # password (iteration 429) that need not match the policy, and
        # SSO login never checks the password.
        if not skip_password_validation:
            validate_password(user_data.password)
        existing = await self.user_repository.single_or_none(email=user_data.email)
        if existing is not None:
            raise EmailAlreadyExistsException(user_data.email)
        # skip_password_hashing is only for the post-tenant-creation
        # Celery path (iteration 1004): its payload carries a password
        # already hashed at the enqueue site, so hashing again here
        # would double-hash and break login. Every other caller passes
        # a plaintext password and keeps the default hashing.
        if not skip_password_hashing:
            user_data.password = hash_it(user_data.password)
        user_id = await self.user_repository.create(user_data)
        
        # Todo: Refactor this to use Celery task to Or fire and forget 
        
        # avoid circular import
        # from api.core.container import get_auth_service

        # auth_service = get_auth_service()
        # welcome_email = UserResendActivationEmailRequestDto(
        #     email=user_data.email,
        #     first_name=user_data.first_name,
        #     tenant_id=str(user_data.tenant_id),
        #     id=str(user_id)
        # )
        # await auth_service.send_activation_email(welcome_email) 
        return user_id

    async def update_user(self, user_id: str, user_data: UpdateUserDto, tenant_id: str | PydanticObjectId | None = None) -> User | None:
        """Update user by ID. Returns updated User model. Raises UserNotFoundException if user does not exist."""
        existing = await self.user_repository.get(id=user_id)
        if existing is None or not _caller_may_access(existing.tenant_id, tenant_id):
            # Scope to the caller's tenant, mirroring delete_user():
            # the detail read, list and delete were already scoped,
            # but this update was not, so a tenant admin with
            # USER_READ_AND_WRITE_ONLY (or role-assign permission)
            # could rewrite any other tenant's user by id — name,
            # role, or avatar. A cross-tenant id now answers with
            # the same 404 as an unknown id; host callers
            # (tenant_id None) and callers that omit tenant_id keep
            # the unscoped behaviour, and self-access is unaffected
            # since the caller's tenant_id comes from their own
            # record, which carries that same tenant_id.
            raise UserNotFoundException(user_id)
        # Todo: Refactor email update logic or check if email is being updated
        # existing_email = user_data.email
        # if existing_email and existing_email != existing.email:
        #     email_in_use = await self.user_repository.single_or_none(email=existing_email)
        #     if email_in_use is not None:
        #         raise EmailAlreadyExistsException(existing_email)
        #     existing.email = existing_email
        existing.first_name = user_data.first_name or existing.first_name
        existing.last_name = user_data.last_name or existing.last_name
        existing.gender = user_data.gender or existing.gender
        if user_data.role_id:
            try:
                existing.role_id = PydanticObjectId(user_data.role_id)
            except Exception:
                # role_id arrives as a plain str (UpdateUserDto /
                # UserRoleUpdateRequestDto do not validate it as an
                # ObjectId), so a malformed value from an assign-role
                # request raised InvalidId inside PydanticObjectId()
                # and escaped as a 500 instead of the clean 404 the
                # role lookup itself returns for an unknown id. A
                # malformed id cannot match any role, so report it
                # the same way; the catch is broad on purpose, as in
                # BaseRepository.get: bson raises InvalidId while
                # pydantic-validated paths raise ValidationError.
                # A None role_id still keeps the existing role.
                raise RoleNotFoundException(role_id=user_data.role_id)
        doc = await existing.to_serializable_dict()
        doc["image_url"] = user_data.image_url or existing.image_url
        # to_serializable_dict() is a full model_dump(), so doc carries the
        # hashed password — logging it would leak a credential hash into
        # server logs (same class as the token/password logs removed in
        # iterations 18-20 and 426). Log everything except the password.
        # first_name/last_name are plain strs with no validator and
        # image_url/sso_provider_id are plain strs too, so strip CR/LF
        # from string values before logging (same shape as the tenant
        # name, preference key and cache-path fixes in iterations
        # 951-953) — otherwise a newline in a stored name could forge
        # extra log lines. The stored doc itself is untouched.
        log_doc = {
            k: (v.replace("\r", " ").replace("\n", " ") if isinstance(v, str) else v)
            for k, v in doc.items()
            if k != "password"
        }
        logger.info(f"Updating user {user_id} with data: {log_doc}")
        return await self.user_repository.update(user_id=user_id, data=UpdateUserDto(**doc))
     

    async def delete_user(self, user_id: str, tenant_id: str | PydanticObjectId | None = None) -> None:
        """Delete user by ID. Returns None otherwise, Raises UserNotFoundException if user does not exist."""
        # Scope to the caller's tenant, mirroring get_user_by_id():
        # the detail read and the list were already scoped, but this
        # delete was not, so a tenant admin with USER_DELETE_ONLY
        # could delete any other tenant's user by id. A cross-tenant
        # id now answers with the same 404 as an unknown id; host
        # callers (tenant_id None) and callers that omit tenant_id
        # keep the unscoped behaviour, and the endpoint's own
        # self-delete guard still runs first, so self-access
        # semantics are unchanged.
        existing = await self.user_repository.get(id=user_id)
        if existing is None or not _caller_may_access(existing.tenant_id, tenant_id):
            raise UserNotFoundException(user_id)
        if await self.user_repository.delete(user_id=user_id) is False:
            raise UserNotFoundException(user_id)
        

    async def update_user_password(self, user_id: str, new_password: str) -> User | None:
        """Update user password by ID. Returns updated User model. Raises UserNotFoundException if user does not exist."""
        existing = await self.user_repository.get(id=user_id)
        if existing is None:
            raise UserNotFoundException(user_id)
        # Same password policy as tenant creation (iteration 427): without
        # this, a reset password bypassed validate_password entirely, so a
        # weak password could replace a strong one. Validated after the
        # existence check so unknown users still get the 404 as before.
        validate_password(new_password)
        hashed_password = hash_it(new_password)
        existing.password = hashed_password
        # Direct .save() bypasses BaseRepository.update()'s central
        # updated_at stamp (iteration 411), so stamp it here or a password
        # change leaves updated_at at creation time forever.
        existing.updated_at = get_utc_now()
        await existing.save()
        return existing

    async def total_count(self, params: Any | None = None) -> int:
        """Get total user count."""
        return await self.user_repository.count(params=params)
    
    async def request_password_reset(self, email: EmailStr) -> UserPasswordReset:
        """Set password reset for user by ID. Returns None otherwise, Raises InvalidOperationException on failure."""
        try:
            user = await self.find_by_email(email=email)
            return await self.user_password_reset_repository.set_password_reset(user_id=str(user.id), first_name=user.first_name, tenant_id=user.tenant_id)
        except Exception as e:
            logger.error(f"Error setting password reset for user with an email: {email} wasn't successful: {e}")
            raise InvalidOperationException(message="Failed to set password reset.")

    async def retrieve_password_reset_data_by_user_id(self, user_id: str) -> UserPasswordReset | None:
        """Get password reset entry by token. Returns UserPasswordReset model or None if not found."""
        try:
            object_id = PydanticObjectId(user_id)
        except Exception:
            # A malformed user_id (tampered/truncated reset link) cannot match any
            # stored record, so treat it as "no reset data" instead of escaping as
            # a 500; the caller raises its invalid-token error for None.
            # The catch is broad on purpose, as in BaseRepository.get and
            # update_user above: direct PydanticObjectId() construction raises
            # bson InvalidId for a malformed value, not the pydantic
            # ValidationError this previously caught alone, so catching only
            # ValidationError left a malformed reset-link user_id escaping
            # as a raw 500 instead of the caller's invalid-token error.
            return None
        return await self.user_password_reset_repository.single_or_none(user_id=object_id)

    async def clear_password_reset_data_by_user_id(self, user_id: str) -> bool:
        """Clear password reset entry by user ID. Returns boolean."""
        logger.info(f"Clearing password reset data for user_id: {user_id}")
        # BaseRepository.delete(id=...) deletes by the reset document's
        # own _id, not by its user_id field, so passing the user id there
        # found no document and returned False while the reset record
        # stayed usable. Delete by the user_id field instead, via the
        # repository's delete_by_user_id (which also audits the delete).
        return await self.user_password_reset_repository.delete_by_user_id(user_id=user_id)
    
    async def check_email_exists(self, email: EmailStr) -> bool:
        """Check if email exists. Returns boolean."""
        existing = await self.user_repository.single_or_none(email=email)
        return existing is not None
    
    async def aggregate(self, pipeline: list[dict]) -> list[TimeSeriesDto]:
        """Aggregate users based on the provided pipeline. Returns an async list[TimeSeriesDto]."""
        return await self.user_repository.aggregate(pipeline, projection_model=TimeSeriesDto)
    

