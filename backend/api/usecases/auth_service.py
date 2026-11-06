import secrets
from datetime import timedelta, timezone

from beanie import PydanticObjectId
from fastapi_mail import MessageType
from fastapi_sso import OpenID
from pydantic import EmailStr
from api.common.dtos.token_dto import ActivationTokenPayloadDto, RefreshTokenPayloadDto, TokenPayloadDto, TokenRefreshRequestDto, TokenSetDto
from api.common.exceptions import ForbiddenException, InvalidOperationException, UnauthorizedException
from api.common.security import hash_it, verify_password
from api.common.utils import get_logger, get_utc_now, is_tenancy_enabled, get_email_sharing_link
from api.core.exceptions import TenantNotFoundException, UserNotFoundException
from api.domain.dtos.audit_logs_dto import AuditLogDto
from api.domain.dtos.login_dto import LoginRequestDto
from api.domain.dtos.role_dto import RoleDto
from api.domain.dtos.tenant_dto import CreateTenantDto
from api.domain.dtos.user_dto import CreateUserDto, UserActivationRequestDto, UserResendActivationEmailRequestDto
from api.domain.entities.role import Role
from api.domain.entities.sso_settings import SSOProvider
from api.domain.entities.tenant import validate_subdomain
from api.domain.entities.user import User
from api.domain.enum.permission import Permission
from api.domain.enum.role import RoleType
from api.domain.interfaces.email_service import IEmailService
from api.infrastructure.security.jwt_token_service import JwtTokenService
from api.interfaces.email_templates.password_reset_email_template_html import password_reset_email_template_html
from api.interfaces.email_templates.notify_password_changes_template_html import notify_password_change_template_html
from api.interfaces.email_templates.activation_template_html import activation_template_html
from api.interfaces.email_templates.email_changes_confirmation_template_html import email_changes_confirmation_template_html
from api.interfaces.email_templates.notify_email_changes_template_html import notify_email_change_template_html
from api.usecases.audit_logs_service import AuditLogsService
from api.usecases.role_service import RoleService
from api.usecases.sso_settings_service import SSOSettingsService
from api.usecases.tenant_service import TenantService
from api.usecases.user_service import UserService
from typing import Callable, Optional

logger = get_logger(__name__)


def _safe_log_value(value) -> str:
    # login_with_magic_link's user_id arrives as a Query(str) that
    # Starlette percent-decodes, so a newline in a magic-link validation
    # attempt could otherwise forge extra log lines — unauthenticated
    # (same class as the endpoint log lines fixed in iteration 958).
    # Only the logged copy is flattened.
    return str(value).replace("\r", " ").replace("\n", " ")

# Dummy password hash, computed once per process, used only to equalize
# login timing for unknown emails (see AuthService.login): it hashes a
# random value, so no supplied password can ever match it, and the
# result is always discarded.
_DUMMY_PASSWORD_HASH = hash_it(secrets.token_hex(32))

# Minimum gap between password-reset emails for the same user. Each
# reset request rotates the single stored token_secret and re-signs the
# JWT with it, so without a cooldown an unbounded caller could both
# flood the victim's inbox and invalidate the reset link the victim
# already holds. Five minutes bounds an attacker to 12 emails/hour
# while a legitimate user waiting on a delayed email can re-request
# after a short wait; the endpoint always answers the generic "If the
# email exists..." 200, so throttling reveals nothing about the account.
PASSWORD_RESET_REQUEST_COOLDOWN = timedelta(minutes=5)

# Minimum gap between activation-email resends for the same user. The
# activation token is signed with the global JWT secret, so unlike a
# password reset a resend does not invalidate the link the user already
# holds — but without a cooldown an unbounded caller (the resend route
# is admin-gated, so this needs an admin session or a compromised one)
# could flood the victim's inbox. Five minutes bounds that to
# 12 emails/hour while a legitimate admin re-sending after a delayed
# email waits only briefly; the endpoint always answers 202, so
# throttling reveals nothing, and the already-issued link stays valid.
ACTIVATION_EMAIL_REQUEST_COOLDOWN = timedelta(minutes=5)

# Minimum gap between change-email confirmation emails for the same
# user. The confirmation token is signed with the global JWT secret,
# so unlike a password reset a re-request does not invalidate the link
# the user already holds — but without a cooldown an unbounded caller
# with the victim's session (the route is authenticated, so this needs
# a logged-in session or a compromised one) could flood the user's
# inbox with confirmation emails. Five minutes bounds that to
# 12 emails/hour while a legitimate user re-requesting after a delayed
# email waits only briefly; the endpoint always answers 202, so
# throttling reveals nothing, and the already-issued link stays valid.
CHANGE_EMAIL_REQUEST_COOLDOWN = timedelta(minutes=5)

# Maximum consecutive failed password logins before the account is
# temporarily locked out of password login, and how long the lockout
# lasts. Five failures in fifteen minutes bounds an online guessing
# attack to about 20 attempts/hour per account while a legitimate
# user who mistypes a few times waits only briefly; the endpoint
# always answers the same generic 401, so a lockout is
# indistinguishable from a wrong password and reveals nothing about
# the account. Failures older than the window do not accumulate
# (see login), and a successful login resets the count. The same
# threshold and window bound guessing through the authenticated
# change-password endpoint (see change_password_authenticated),
# which keeps its own counters so the two channels never lock each
# other out.
MAX_FAILED_LOGIN_ATTEMPTS = 5
FAILED_LOGIN_LOCKOUT_WINDOW = timedelta(minutes=15)


def _is_login_locked_out(user: User, now) -> bool:
    # Pure lockout decision, kept separate from login() so the
    # threshold/window logic can be reasoned about on its own: locked
    # only once the failure count reaches the threshold AND the last
    # failure is still inside the window. A None timestamp (a count
    # with no recorded time, which cannot arise from login() but
    # could from a hand-edited document) is treated as not locked.
    if user.failed_login_attempts < MAX_FAILED_LOGIN_ATTEMPTS:
        return False
    last = user.last_failed_login_at
    if last is None:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return now - last < FAILED_LOGIN_LOCKOUT_WINDOW


def _is_password_change_locked_out(user: User, now) -> bool:
    # Pure lockout decision for the authenticated change-password
    # endpoint, mirroring _is_login_locked_out on its own counters:
    # locked only once the failure count reaches the threshold AND
    # the last failure is still inside the window. A None timestamp
    # is treated as not locked. Separate counters mean this lockout
    # blocks only change-password attempts, never login.
    if user.failed_password_change_attempts < MAX_FAILED_LOGIN_ATTEMPTS:
        return False
    last = user.last_failed_password_change_at
    if last is None:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return now - last < FAILED_LOGIN_LOCKOUT_WINDOW


async def _clear_login_lockout(user: User, now) -> None:
    # Clear the password-login failure record after a successful
    # login through any other channel (magic link, passkey, SSO).
    # login() already resets on a password success, but the other
    # three login paths returned their token set without touching
    # these counters, so a user who mistyped five times and then
    # proved their identity through a magic link still could not
    # use password login until the 15-minute window expired.
    # Best-effort on purpose: the caller has already minted the
    # token set by the time this runs, and a failed counter save
    # must never turn a successful login into an error — the
    # lockout expires on its own, so the worst case is a stale
    # count for the rest of the window. A failure is logged so it
    # is visible instead of silent.
    if not user.failed_login_attempts:
        return
    try:
        user.failed_login_attempts = 0
        user.last_failed_login_at = None
        user.updated_at = now
        await user.save()
    except Exception:
        logger.warning(f"Failed to clear login lockout counters for user {user.id}; the lockout expires on its own.")


async def _clear_password_failure_records(user: User, now) -> None:
    # Clear BOTH password-guessing failure records after a
    # successful token-based password reset: the password-login
    # counters AND the authenticated change-password counters.
    # change_password is the one success path that proved identity
    # through the email token yet touched neither record, so a
    # user who had failed five password logins (or five
    # change-password attempts) and then reset via email still
    # could not log in with the new password — or use
    # /change-password — until the 15-minute window expired.
    # Same best-effort contract as _clear_login_lockout: the
    # password is already rotated by the time this runs, and a
    # failed counter save must never turn a successful reset into
    # an error — the lockouts expire on their own.
    if not user.failed_login_attempts and not user.failed_password_change_attempts:
        return
    try:
        user.failed_login_attempts = 0
        user.last_failed_login_at = None
        user.failed_password_change_attempts = 0
        user.last_failed_password_change_at = None
        user.updated_at = now
        await user.save()
    except Exception:
        logger.warning(f"Failed to clear password failure records for user {user.id}; the lockouts expire on their own.")

class AuthService:
    def __init__(self,
            user_service: UserService,
            tenant_service: TenantService,
            role_service: RoleService,
            jwt_token_service: JwtTokenService,
            email_service: IEmailService,
            audit_log_service: AuditLogsService,
            sso_settings_service: SSOSettingsService
        ):
        self.user_service: UserService = user_service
        self.tenant_service: TenantService = tenant_service
        self.role_service: RoleService = role_service
        self.jwt_token_service: JwtTokenService = jwt_token_service
        self.email_service: IEmailService = email_service
        self.audit_log_service: AuditLogsService = audit_log_service
        self.sso_settings_service: SSOSettingsService = sso_settings_service
        logger.info("Initialized.")
        # Note: no print() here by design — AuthService is a singleton, but a
        # stray stdout print of the email service object is debug noise that
        # bypasses the logger (and would leak config if the service ever
        # gained a __repr__); the logger line above is the record.

    async def _get_token_set(self, user: User) -> TokenSetDto:
        """
            Helper method to generate a TokenSetDto for the given user. Dont use this method outside this class.
        """
        role = await self.role_service.get_role_by_id(role_id=user.role_id)
        role_doc = await role.to_serializable_dict()
        payload = TokenPayloadDto(
                sub=user.id,
                email=user.email,
                is_active=user.is_active,
                activated_at=user.activated_at,
                role=RoleDto(**role_doc) if role_doc is not None else None,
                tenant_id=user.tenant_id
            )

        res = await self.jwt_token_service.generate_tokens(payload)
        await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
            entity="User",
            action="login",
            user_id=str(user.id),
            tenant_id=str(user.tenant_id) if user.tenant_id else None,
            changes={"Info": f"User received tokens and logged in."}
        ))

        # Host audit log for tenant admin login
        if user.tenant_id and Permission.FULL_ACCESS in (role.permissions if role.permissions else []):
            logger.info(f"Tenant ID: {user.tenant_id} logged in. Updating an audit log in the host.")
            await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
                entity="User",
                action="login",
                user_id=str(user.id),
                tenant_id=None,
                changes={"Info": f"Tenant admin user logged in."}
            ))
        return res


    async def login_with_magic_link(self, user_id: str) -> TokenSetDto:
        try:

            user = await self.user_service.get_user_by_id(user_id=user_id)
            await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
                entity="User",
                action="login",
                user_id=user_id,
                changes={"Info": f"User attempted to log in with magic link."},
                tenant_id=str(user.tenant_id) if user.tenant_id else None
            ))
            token_set = await self._get_token_set(user)
            await _clear_login_lockout(user, get_utc_now())
            return token_set
        except Exception:
            # "except UserNotFoundException or Exception" was NOT a
            # catch-all: `or` evaluates to the first truthy operand, so
            # it caught only UserNotFoundException — and this handler
            # then read the unbound `user` when get_user_by_id itself
            # failed, turning the intended generic 401 into a NameError
            # 500 (the validate endpoint does not wrap this call). The
            # error audit log uses only the user_id parameter, which is
            # always bound, so every failure path now yields the generic
            # 401 instead of leaking internals.
            logger.error(f"Login attempt failed for user_id: {_safe_log_value(user_id)}")
            await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
                entity="User",
                action="error",
                user_id=user_id,
                tenant_id=None,
                changes={"Info": f"Magic link login failed for user_id: {user_id}."}
            ))
            raise UnauthorizedException("Authentication failed. Please check your credentials.")


    async def login_with_passkey(self, email: str) -> TokenSetDto:
        try:
            user = await self.user_service.find_by_email(email=email)
            await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
                entity="User",
                action="login",
                user_id=str(user.id),
                tenant_id=str(user.tenant_id) if user.tenant_id else None,
                changes={"Info": f"User attempted to log in with passkey."}
            ))
            token_set = await self._get_token_set(user)
            await _clear_login_lockout(user, get_utc_now())
            return token_set
        except Exception:
            # Same `or`-in-except idiom bug as login_with_magic_link:
            # "except UserNotFoundException or Exception" caught only
            # UserNotFoundException. This handler uses only the bound
            # `email` parameter, so no NameError arose here, but other
            # failures escaped the generic 401; now all are caught and
            # logged, and the passkey endpoint still maps the 401 to
            # its generic 406, so the user-visible response is unchanged.
            logger.error(f"Login attempt failed for email: {email}")
            await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
                entity="User",
                action="error",
                user_id="unknown",
                changes={"Info": f"User with an email: {email} failed to log in with passkey."}
            ))
            raise UnauthorizedException("Authentication failed. Please check your credentials.")


    async def login(self, req: LoginRequestDto) -> TokenSetDto:
        try:
            user = await self.user_service.find_by_email(email=req.email)
        except UserNotFoundException:
            # Same generic 401 as a wrong password: previously an unknown
            # email raised UserNotFoundException, which the exception
            # handler maps to 404 "User with identifier <email> not
            # found.", letting anyone probe whether an email has an
            # account. Run a dummy password check first so this path
            # takes about as long as a wrong-password attempt (one
            # pbkdf2 verify in both), closing the remaining timing
            # channel; the result is discarded and the 401 follows.
            verify_password(req.password, _DUMMY_PASSWORD_HASH)
            raise UnauthorizedException("Authentication failed. Please check your credentials.")
        now = get_utc_now()
        if _is_login_locked_out(user, now):
            # Same generic 401 as a wrong password, with the same dummy
            # verify so a locked account takes about as long as a wrong
            # password attempt and the two stay indistinguishable. The
            # failure is NOT recorded again: the count stays at the
            # threshold and the window keeps running from the last real
            # failure, so the lockout expires on its own instead of
            # being extended by every probe.
            verify_password(req.password, _DUMMY_PASSWORD_HASH)
            raise UnauthorizedException("Authentication failed. Please check your credentials.")
        if verify_password(req.password, user.password) is False:
            # Record the failure before raising, so the 401 the caller
            # sees is unchanged. Failures older than the window do not
            # accumulate toward a lockout, so a user who mistypes once
            # a month never locks out. Stored datetimes come back from
            # Mongo as naive UTC, so normalise before comparing with
            # get_utc_now()'s aware value. Direct .save() bypasses
            # BaseRepository.update()'s central updated_at stamp (see
            # activate_account), so stamp it here.
            last = user.last_failed_login_at
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if last is None or now - last >= FAILED_LOGIN_LOCKOUT_WINDOW:
                user.failed_login_attempts = 1
            else:
                user.failed_login_attempts = user.failed_login_attempts + 1
            user.last_failed_login_at = now
            user.updated_at = now
            await user.save()
            raise UnauthorizedException("Authentication failed. Please check your credentials.")
        if user.failed_login_attempts:
            # A successful login clears the failure record, so a
            # legitimate user is never locked out by old mistakes.
            user.failed_login_attempts = 0
            user.last_failed_login_at = None
            user.updated_at = now
            await user.save()

        return await self._get_token_set(user)

    async def login_with_sso(self, provider_name: SSOProvider, user_info: OpenID, tenant_id: PydanticObjectId | None) -> TokenSetDto:
        email = user_info.email
        display_name = user_info.display_name
        first_name = user_info.first_name
        last_name = user_info.last_name

        if email is None:
            raise InvalidOperationException("SSO provider did not return an email address.")
        try:
            user = await self.user_service.find_by_email(email=email)
            if user.sso_provider_id != provider_name:
                user.sso_provider_id = provider_name
                # Direct .save() bypasses BaseRepository.update()'s central
                # updated_at stamp (iteration 411), so stamp it here.
                user.updated_at = get_utc_now()
                await user.save()
            token_set = await self._get_token_set(user)
            await _clear_login_lockout(user, get_utc_now())
            return token_set
        except UserNotFoundException:
            # The email here comes from the IdP's OpenID claims, not from
            # a validated DTO, so it reaches this log before any EmailStr
            # check: a newline-bearing claim would otherwise forge extra
            # log lines. Flatten the logged copy only, mirroring the
            # magic-link log line above; the raw value still drives the
            # user creation below.
            logger.error(f"User not found for email: {_safe_log_value(email)}")
            role: Role = await self.role_service.find_by_name(name=RoleType.GUEST)  # Ensure default role exists
            await self.user_service.create_user(
                user_data=CreateUserDto(
                    email=email,
                    first_name=first_name or display_name or "N/A",
                    last_name=last_name or display_name or "N/A",
                    # Random, undisclosed password: the previous placeholder was
                    # predictable (provider name only), and password login checks
                    # only the hash, so anyone knowing the victim's email and SSO
                    # provider could log in as an SSO-created user. SSO login
                    # never uses this password, so a random value breaks nothing.
                    password=secrets.token_urlsafe(32),
                    gender="prefer_not_to_say",
                    role_id=role.id if role else None,
                    tenant_id=tenant_id if tenant_id else None,
                    # Carry the SSO linkage on the created row itself:
                    # UserRepository.create persists sso_provider_id
                    # (iteration 02:14 fix), but this call site never
                    # supplied it, so the linkage depended entirely on
                    # the re-fetch-and-set block below, gated on
                    # is_active is False. A freshly created user always
                    # satisfies that guard today (create hardcodes
                    # is_active=False), so the linkage landed, but only
                    # via a second write, and any future path that
                    # creates the user active would silently drop it.
                    # The block below still activates the user and
                    # re-asserts the same value idempotently.
                    sso_provider_id=provider_name,
                ),
                # Skip policy validation for this random SSO password (see
                # UserService.create_user): it need not match the policy.
                skip_password_validation=True)

        user = await self.user_service.find_by_email(email=email)
        if user.is_active is False:
            user.is_active = True
            user.activated_at = get_utc_now()
            user.sso_provider_id = provider_name
            # Direct .save() bypasses BaseRepository.update()'s central
            # updated_at stamp (iteration 411), so stamp it here.
            user.updated_at = get_utc_now()
            await user.save()
        return await self._get_token_set(user)

    async def new_user_creation(self, new_user: CreateUserDto, tenant_id: Optional[str] = None) -> None:
            new_user.tenant_id = tenant_id
            not_found = True
            try:
                enabled_sso = await self.sso_settings_service.get_only_enabled_providers()
                if len(enabled_sso.items) > 0:
                    user = await self.user_service.find_by_email(email = new_user.email)
                    logger.debug(f"found user {user.sso_provider_id}")
                    if user.sso_provider_id:
                        logger.debug(f"This email already has logged using sso {user.sso_provider_id} hence, skip the new user creation.")
                        not_found = False
            except UserNotFoundException as u:
                logger.debug("No user found! Hence creating a new user..")
                not_found = True

            if not_found:
                await self.user_service.create_user(user_data=new_user)


    async def register(self, new_user: CreateUserDto, cb: Callable) -> None:
        """
            Register a new user. In multi-tenant mode, if the subdomain is unique, a new tenant will be created.
            The callback function `cb` will be called with the newly created tenant ID after tenant creation.
            In single-tenant mode, the user will be created without a tenant.
            Raises InvalidOperationException if the subdomain is already taken in multi-tenant mode.
            The user will be created with the provided details.
        """

        if is_tenancy_enabled() is False:
            await self.new_user_creation(new_user=new_user)
            logger.info("New user registered in single-tenant mode.")
            return

        tenant = None

        # Normalize once: validate_subdomain() (iteration 1209) strips
        # before validating, but register() discarded its trimmed
        # return value and looked the raw sub_domain up instead. With
        # tenant_id None the validator is short-circuited entirely, so
        # a padded subdomain missed the existing tenant, and
        # CreateTenantDto (whose Subdomain validator strips) then
        # created a duplicate tenant for it. The trimmed value drives
        # the lookup, the taken-check, the derived name and creation;
        # None passes through unchanged, as before. Lowercased here
        # too: validate_subdomain now lowercases on storage, so an
        # uppercase register attempt must look up the lowercased form
        # or the taken-check misses the existing tenant, exactly like
        # the padded-subdomain miss above.
        subdomain = new_user.sub_domain.strip().lower() if isinstance(new_user.sub_domain, str) else new_user.sub_domain

        if new_user.tenant_id is None or validate_subdomain(subdomain) is not None:
            try:
                tenant = await self.tenant_service.find_by_subdomain(subdomain=subdomain)
                if tenant is not None:
                    await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
                        entity="Tenant",
                        action="error",
                        user_id="unknown",
                        changes={"Info": f"Tenant with subdomain: {subdomain} is already taken."},
                        tenant_id=str(tenant.id)
                    ))
                    raise InvalidOperationException(f"Subdomain '{subdomain}' is already taken.")
            except InvalidOperationException as ioe:
                logger.warning(f"Subdomain validation failed for '{_safe_log_value(subdomain)}': {ioe}")
                # If it is coming here.. that means the request is valid and made by a legit tenant.. because the tenant middleware has already validated it.
                await self.user_service.create_user(user_data=new_user)

            except TenantNotFoundException as tnfe:
                logger.warning(f"Tenant not found for subdomain '{_safe_log_value(subdomain)}': {tnfe} - Proceeding to create new tenant.")
                create_new_tenant = CreateTenantDto(
                    name=subdomain.split('.')[0],
                    subdomain=subdomain,
                    admin_email=new_user.email,
                    admin_password=new_user.password,
                    first_name=new_user.first_name,
                    last_name=new_user.last_name,
                    gender=new_user.gender,
                )
                newly_created_tenant_id = await self.tenant_service.create_tenant(tenant_data=create_new_tenant)
                logger.info(f"New tenant created with ID: {newly_created_tenant_id} for subdomain '{_safe_log_value(subdomain)}' and user creation will be procssed...")
                cb(newly_created_tenant_id)



    async def logout(self, user_id: str, tenant_id: str | None) -> None:
        # Do not claim token invalidation here: logout only deletes the
        # refresh cookie (account_endpoint) — there is no server-side
        # token denylist, so a copied refresh token stays valid until
        # expiry. Recording "invalidated" in the audit trail would
        # mislead an incident responder into believing a compromised
        # session was killed. A real denylist remains a larger change.
        await self.audit_log_service.create_audit_log(audit_log=AuditLogDto(
            entity="User",
            action="logout",
            user_id=user_id,
            tenant_id=tenant_id,
            changes={"Info": f"User logged out."}
        ))
        logger.info(f"User {user_id} logged out successfully.")

    async def refresh_token(self, token: TokenRefreshRequestDto) -> TokenSetDto:
        """
            Refresh the access token using the provided refresh token.
            On success, returns a new TokenSetDto containing the new access and refresh tokens.
            Raises UnauthorizedException if the refresh token is invalid or expired.
        """
        refresh_token_payload: RefreshTokenPayloadDto = await self.jwt_token_service.decode_token(token=token.refresh_token, type="refresh_token")

        if refresh_token_payload is None:
            raise UnauthorizedException("Invalid refresh token")

        user = await self.user_service.get_user_by_id(user_id=str(refresh_token_payload.sub))
        role = await self.role_service.get_role_by_id(role_id=user.role_id)
        role_doc = await role.to_serializable_dict()
        payload = TokenPayloadDto(
            sub=user.id,
            email=user.email,
            is_active=user.is_active,
            activated_at=user.activated_at,
            role=RoleDto(**role_doc) if role_doc is not None else None,
            tenant_id=user.tenant_id
        )
        return await self.jwt_token_service.generate_tokens(payload)



    async def initate_password_reset(self, email: EmailStr, domain: str) -> None:
        """
            Initiate the password reset process by sending a password reset email to the user.
            Raises InvalidOperationException if the user with the provided email does not exist.
            Sends a password reset email with a link to reset the password.
        """
        # Throttle repeat requests for the same user before rotating
        # anything: request_password_reset() rotates the single stored
        # token_secret on every call, so a second request within the
        # cooldown window would both send another email and invalidate
        # the reset link the user already holds. Return silently
        # instead — the endpoint always answers the generic "If the
        # email exists..." 200, so this reveals nothing about the
        # account, and the already-issued link stays valid. A
        # re-request after the window rotates and re-sends as before.
        # The unknown-email failure is mapped exactly as
        # request_password_reset() used to raise it, so that path is
        # unchanged. reset_secret_updated_at is stored by Mongo as
        # naive UTC, so normalise it before comparing with
        # get_utc_now()'s aware value.
        try:
            user = await self.user_service.find_by_email(email=email)
        except UserNotFoundException:
            raise InvalidOperationException(message="Failed to set password reset.") from None
        existing = await self.user_service.retrieve_password_reset_data_by_user_id(user_id=str(user.id))
        if existing is not None:
            updated_at = existing.reset_secret_updated_at
            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            if get_utc_now() - updated_at < PASSWORD_RESET_REQUEST_COOLDOWN:
                logger.info(f"Password reset request for user {user.id} throttled: a reset link was already sent within the cooldown window; the existing link stays valid.")
                return
        reset_data = await self.user_service.request_password_reset(email)
        data = ActivationTokenPayloadDto(
            user_id=str(reset_data.user_id),
            email=email,
            type="password_reset_confirmation",
            jwt_secret=reset_data.token_secret,
            tenant_id=str(reset_data.tenant_id)
        )
        token = await self.jwt_token_service.encode_activation_token(data)
        link = get_email_sharing_link(token=token, user_id=str(reset_data.user_id), domain=domain, type=data.type, tenant_id=str(reset_data.tenant_id))
        html = password_reset_email_template_html(user_first_name=reset_data.first_name, password_reset_link=link)
        await self.email_service.send_email(
            to=email,
            subject="Password Reset Request",
            body=html,
            type=MessageType.html
        )
        logger.info(f"Password reset initiated for user {reset_data.user_id} ({email})")


    async def change_password(self, new_password: str, token: str, user_id: str) -> None:
        """
            Change the user's password using the provided password reset token.
            Raises InvalidOperationException if the token is invalid or expired.
            On success, updates the user's password and clears the password reset data.
        """
        reset_data = await self.user_service.retrieve_password_reset_data_by_user_id(user_id=user_id)
        if reset_data is None:
            raise InvalidOperationException("Invalid or expired password reset token.")
        payload = await self.jwt_token_service.verify_password_reset_token(token=token, jwt_secret=reset_data.token_secret)
        if payload.user_id != user_id:
            raise InvalidOperationException("Invalid password reset token.")
        await self.user_service.update_user_password(user_id=user_id, new_password=new_password)
        await reset_data.delete()
        logger.info(f"Password reset successful for user {user_id}. Cleared reset data.")
        # The user just proved identity through the email token and
        # rotated the password, so both password-guessing failure
        # records are cleared: without this, a user locked out of
        # password login (or of /change-password) still could not
        # log in with the new password until the 15-minute window
        # expired. The re-read holds the freshly saved hash, so
        # clearing the counters on it cannot clobber the new
        # password. Best-effort (see
        # _clear_password_failure_records): a failed counter save
        # never turns a successful reset into an error.
        updated_user = await self.user_service.get_user_by_id(user_id=user_id)
        await _clear_password_failure_records(updated_user, get_utc_now())
        html = notify_password_change_template_html(user_first_name=reset_data.first_name)
        await self.email_service.send_email(
            to=payload.email,
            subject="Your Password Has Been Changed",
            body=html,
            type=MessageType.html
        )


    async def change_password_authenticated(self, user_id: str, current_password: str, new_password: str) -> None:
        """
            Change the password of the currently authenticated user.
            Raises UnauthorizedException if the current password is
            incorrect. Previously a logged-in user had no way to change
            their password without the email reset flow: the only
            change_password path took a reset token, so a session
            hijack aside, a user who simply wanted to rotate a
            password they knew had to request an email link. The
            current password is verified against the stored hash
            before anything is written, so knowing the session alone
            is not enough; the new password goes through
            update_user_password, which enforces the same policy as
            the reset path. The notification email uses the default
            best-effort send (raise_on_failure=False), so an SMTP
            failure cannot report a completed change as failed.
        """
        user = await self.user_service.get_user_by_id(user_id=user_id)
        now = get_utc_now()
        if _is_password_change_locked_out(user, now):
            # Same generic 401 as a wrong current password, with the
            # same dummy verify so a locked-out attempt takes about
            # as long as a wrong-password attempt and the two stay
            # indistinguishable. The failure is NOT recorded again:
            # the count stays at the threshold and the window keeps
            # running from the last real failure, so the lockout
            # expires on its own instead of being extended by every
            # probe.
            verify_password(current_password, _DUMMY_PASSWORD_HASH)
            raise UnauthorizedException("Current password is incorrect.")
        if not user.password or verify_password(current_password, user.password) is False:
            # Record the failure before raising, so the 401 the caller
            # sees is unchanged. Without a bound, a session (or a
            # hijacked one) could guess the current password
            # indefinitely — and a guessed current password lets the
            # attacker rotate the password and lock the owner out.
            # Failures older than the window do not accumulate toward
            # a lockout. Stored datetimes come back from Mongo as
            # naive UTC, so normalise before comparing with
            # get_utc_now()'s aware value. Direct .save() bypasses
            # BaseRepository.update()'s central updated_at stamp (see
            # activate_account), so stamp it here.
            last = user.last_failed_password_change_at
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if last is None or now - last >= FAILED_LOGIN_LOCKOUT_WINDOW:
                user.failed_password_change_attempts = 1
            else:
                user.failed_password_change_attempts = user.failed_password_change_attempts + 1
            user.last_failed_password_change_at = now
            user.updated_at = now
            await user.save()
            raise UnauthorizedException("Current password is incorrect.")
        if user.failed_password_change_attempts or user.failed_login_attempts:
            # A successful change clears the failure record, so a
            # legitimate user is never locked out by old mistakes.
            # The password-login counters are cleared too: entering
            # the correct current password proves the same identity
            # a password login would, so a user who was locked out
            # of login (five mistyped passwords) and then rotated
            # the password from a still-valid session must be able
            # to log in with the new password right away — otherwise
            # the login lockout would survive a proven-legitimate
            # password change for the rest of the window, and the
            # user would be locked out of the account they just
            # secured. Saved here; update_user_password below
            # re-reads the user and saves only the new hash, so the
            # reset is kept.
            user.failed_password_change_attempts = 0
            user.last_failed_password_change_at = None
            user.failed_login_attempts = 0
            user.last_failed_login_at = None
            user.updated_at = now
            await user.save()
        await self.user_service.update_user_password(user_id=user_id, new_password=new_password)
        logger.info(f"Password changed for user {user_id}.")
        html = notify_password_change_template_html(user_first_name=user.first_name)
        await self.email_service.send_email(
            to=user.email,
            subject="Your Password Has Been Changed",
            body=html,
            type=MessageType.html
        )


    async def send_activation_email(self, payload: UserResendActivationEmailRequestDto, domain: str) -> None:
        """
            Resend the activation email to the user.
            Raises InvalidOperationException if the user is already active.
            Sends an activation email with a link to activate the account.
        """
        user = await self.user_service.find_by_email(email=payload.email)
        if user.is_active:
            raise InvalidOperationException("User is already active.")
        # Throttle repeat resends for the same user before sending
        # anything: without a cooldown an unbounded caller could flood
        # the victim's inbox with activation emails. Return silently
        # instead — the endpoint always answers 202, so this reveals
        # nothing, and the already-issued link stays valid (activation
        # tokens are signed with the global secret, not rotated per
        # send). A re-request after the window sends as before. The
        # timestamp is only stamped after a successful send, so a
        # failed send does not start the cooldown. Stored datetimes
        # come back from Mongo as naive UTC, so normalise before
        # comparing with get_utc_now()'s aware value.
        if user.activation_email_sent_at is not None:
            sent_at = user.activation_email_sent_at
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=timezone.utc)
            if get_utc_now() - sent_at < ACTIVATION_EMAIL_REQUEST_COOLDOWN:
                logger.info(f"Activation email resend for user {user.id} throttled: an activation email was already sent within the cooldown window; the existing link stays valid.")
                return
        activation_token = await self.jwt_token_service.encode_activation_token(payload=ActivationTokenPayloadDto(
            user_id=str(payload.id),
            email=payload.email,
            type="activation",
            tenant_id=payload.tenant_id
        ))
        link = get_email_sharing_link(token=activation_token, user_id=payload.id, domain=domain, type="activation", tenant_id=payload.tenant_id)
        html = activation_template_html(user_first_name=payload.first_name, activation_link=link)
        # The resend endpoint returns 202 with no other success signal, so
        # a swallowed SMTP failure would falsely report success; opt in to
        # surfacing it (clean 406 via the InvalidOperationException handler).
        # Notification-after-action sends stay best-effort (see SmtpEmail).
        await self.email_service.send_email(
            to=payload.email,
            subject="Account Activation",
            body=html,
            type=MessageType.html,
            raise_on_failure=True
        )
        # Direct .save() bypasses BaseRepository.update()'s central
        # updated_at stamp (see activate_account), so stamp it here.
        user.activation_email_sent_at = get_utc_now()
        user.updated_at = get_utc_now()
        await user.save()
        logger.info(f"Activation email sent to {payload.email}")


    async def activate_account(self, req: UserActivationRequestDto) -> None:
        """
            Activate a user account using the provided activation token.
            Raises InvalidOperationException if the user is already active or if the token is invalid.
        """
        payload = await self.jwt_token_service.verify_activation_token(token=req.token)
        user = await self.user_service.get_user_by_id(user_id=payload.user_id)


        if user.is_active:
            raise InvalidOperationException("User is already active.")

        if user.email != payload.email:
            raise ForbiddenException("Oh no, You are not allowed to perform this operation.")

        user.is_active = True
        user.activated_at = get_utc_now()
        # Direct .save() bypasses BaseRepository.update()'s central
        # updated_at stamp (iteration 411), so stamp it here.
        user.updated_at = get_utc_now()
        await user.save()
        logger.info(f"User {user.id} ({user.email}) has been activated.")


    async def change_email_request(self, current_email: EmailStr, new_email: EmailStr, domain: str) -> None:
        """
            Initiate the email change process by sending a confirmation email to the new email address.
            Raises InvalidOperationException if the new email is the same as the current email or if the new email is already in use.
            Sends a confirmation email to the new email address with a link to confirm the email change.
            The actual email change is completed in the `change_email_confirmation` method.
        """
        if current_email == new_email:
            raise InvalidOperationException("The new email address must be different from the current email address.")

        does_exist = await self.user_service.check_email_exists(email=new_email)
        if does_exist is True:
            raise InvalidOperationException(f"The email '{new_email}' is already in use by another account.")

        user = await self.user_service.find_by_email(email=current_email)
        # Throttle repeat requests for the same user before sending
        # anything: without a cooldown an unbounded caller with the
        # user's session could flood the user's inbox with
        # confirmation emails. Return silently instead — the endpoint
        # always answers 202, so this reveals nothing, and the
        # already-issued link stays valid (tokens are signed with the
        # global secret, not rotated per send). A re-request after the
        # window sends as before. The timestamp is only stamped after
        # a successful send, so a failed send does not start the
        # cooldown. Stored datetimes come back from Mongo as naive
        # UTC, so normalise before comparing with get_utc_now()'s
        # aware value. Validation above (same email / already in use)
        # still raises before this check, so those responses are
        # unchanged.
        if user.change_email_sent_at is not None:
            sent_at = user.change_email_sent_at
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=timezone.utc)
            if get_utc_now() - sent_at < CHANGE_EMAIL_REQUEST_COOLDOWN:
                logger.info(f"Change-email request for user {user.id} throttled: a confirmation email was already sent within the cooldown window; the existing link stays valid.")
                return
        activation_token = await self.jwt_token_service.encode_activation_token(payload=ActivationTokenPayloadDto(
            user_id=str(user.id),
            email=new_email,
            type="change_email_confirmation",
            tenant_id=user.tenant_id
        ))
        link = get_email_sharing_link(token=activation_token, user_id=str(user.id), domain=domain, type="change_email_confirmation", tenant_id=str(user.tenant_id))
        html = email_changes_confirmation_template_html(user_first_name=user.first_name, email_change_link=link)
        # The request endpoint returns bare 202 with no other success signal,
        # and this confirmation link IS the requested action (not a
        # post-action notification), so a swallowed SMTP failure would falsely
        # report success; opt in to surfacing it. The endpoint comment
        # already assumes email-send failures surface as
        # InvalidOperationException (clean 406 via its handler).
        await self.email_service.send_email(
            to=user.email,
            subject="Confirm Your Email Change",
            body=html,
            type=MessageType.html,
            raise_on_failure=True
        )
        # Direct .save() bypasses BaseRepository.update()'s central
        # updated_at stamp (see activate_account), so stamp it here.
        user.change_email_sent_at = get_utc_now()
        user.updated_at = get_utc_now()
        await user.save()

    async def change_email_confirmation(self, token: str, current_user_id: str) -> None:
        """
            Confirm and complete the email change process.
            Raises InvalidOperationException if the new email is already in use.
            Updates the user's email to the new email address after confirmation.
            Sends a notification email to the user about the email change.
            The token's user must be the authenticated caller: the endpoint
            is authenticated, so applying a token issued for another user
            would let any logged-in session change that user's email (and
            then password-reset into the account) from a leaked token.
        """
        payload = await self.jwt_token_service.verify_change_email_token(token=token)
        if payload.user_id != current_user_id:
            raise InvalidOperationException("Email change token does not belong to the authenticated user.")
        user = await self.user_service.get_user_by_id(user_id=payload.user_id)
        does_exist = await self.user_service.check_email_exists(email=payload.email)
        if does_exist is True:
            raise InvalidOperationException(f"The email '{payload.email}' is already in use by another account. Cannot change email.")

        user.email = payload.email
        # Direct .save() bypasses BaseRepository.update()'s central
        # updated_at stamp (iteration 411), so stamp it here.
        user.updated_at = get_utc_now()
        logger.info(f"User {user.id} changed email to {payload.email}.")
        await user.save()
        html = notify_email_change_template_html(user_first_name=user.first_name)
        await self.email_service.send_email(
            to=user.email,
            subject="Your Email Has Been Changed Successfully",
            body=html,
            type=MessageType.html
        )


    async def get_user_service(self) -> UserService:
        return self.user_service
