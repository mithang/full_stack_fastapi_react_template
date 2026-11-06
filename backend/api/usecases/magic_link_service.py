from datetime import timedelta, timezone

from beanie import PydanticObjectId
from fastapi_mail import MessageType
from api.common.exceptions import ApiBaseException
from api.common.utils import get_email_sharing_link, get_host_main_domain_name, get_logger, get_utc_now
from api.domain.dtos.user_dto import UserDto
from api.domain.interfaces.email_service import IEmailService
from api.infrastructure.persistence.repositories.user_magic_link_repository_impl import UserMagicLinkRepository
from api.interfaces.email_templates.magic_link_login_template_html import magic_link_login_template
from api.usecases.tenant_service import TenantService
from api.common.security import hash_it, JWT_SECRET, validate_hashed_value

logger = get_logger(__name__)

# Minimum gap between magic-link emails for the same user. The
# repository already caps outstanding links at 4 with a 15-minute TTL,
# but without a time gap an unbounded caller could still fire all 4 in
# a burst and repeat every 15 minutes (16 identical emails/hour to the
# victim). Five minutes bounds an attacker to 12 emails/hour with no
# burst, matching the password-reset, activation-email and
# change-email cooldowns; the endpoint always answers the generic "If
# the email exists..." 200, so throttling reveals nothing about the
# account, and the already-issued link stays valid (the token is
# deterministic per user, so a re-request inside the window would
# have sent the identical link anyway).
MAGIC_LINK_REQUEST_COOLDOWN = timedelta(minutes=5)


class EmailMagicLinkService:
    def __init__(
        self,
        user_magic_link_repo: UserMagicLinkRepository,
        email_service: IEmailService,
        tenant_service: TenantService,

    ):
        self.user_magic_link_repo: UserMagicLinkRepository = user_magic_link_repo
        self.email_service: IEmailService = email_service
        self.tenant_service: TenantService = tenant_service

    async def create_magic_link(self, user_dto: UserDto):
        """
        Create a magic link for the user and store it in the database. And valid for 15 minutes. Tries to send an email with the magic link.
        Args:
            user_dto (UserDto): The user data transfer object containing user information.
        """
        try:
            # Throttle repeat requests for the same user before creating
            # (and emailing) another link: the token is deterministic
            # per user, so a re-request inside the window would send
            # the identical link again. Return silently instead — the
            # endpoint always answers the generic "If the email
            # exists..." 200, so this reveals nothing about the
            # account, and the already-issued link stays valid. A
            # re-request after the window creates and sends as before.
            # created_at is stored by Mongo as naive UTC, so normalise
            # it before comparing with get_utc_now()'s aware value.
            existing = await self.user_magic_link_repo.search({"user_id": PydanticObjectId(user_dto.id)})
            now = get_utc_now()
            for link in existing:
                sent_at = link.created_at
                if sent_at.tzinfo is None:
                    sent_at = sent_at.replace(tzinfo=timezone.utc)
                if now - sent_at < MAGIC_LINK_REQUEST_COOLDOWN:
                    logger.info(f"Magic link request for user {user_dto.id} throttled: a magic link was already sent within the cooldown window; the existing link stays valid.")
                    return
            token = hash_it(user_dto.id + JWT_SECRET)
            record = await self.user_magic_link_repo.create_magic_link(user_id=user_dto.id, token=token)
            domain = get_host_main_domain_name()
            if user_dto.tenant_id:
                tenant = await self.tenant_service.get_tenant_by_id(tenant_id=user_dto.tenant_id)
                # get_tenant_by_id raises for an unknown tenant, so tenant is
                # never None here; but a tenant may have neither a custom
                # domain nor a subdomain (both nullable on the entity), in
                # which case the old `else tenant.subdomain` produced
                # domain=None and an unusable "https://None/..." magic link
                # in the email. Fall back to the main domain, mirroring
                # get_sso_redirect_uri's fallback for the same situation.
                domain = tenant.custom_domain or tenant.subdomain or get_host_main_domain_name()

            link = get_email_sharing_link(token=record.token, user_id=str(record.user_id), domain=domain, type="magic_link_login", tenant_id=str(record.tenant_id))
            html_content = magic_link_login_template(user_first_name=user_dto.first_name, magic_link=link)
            # The email IS the requested action, and the endpoint's contract
            # is that a send failure for an existing user must NOT be
            # reported as success (only the unknown-email response stays
            # generic, to avoid enumerating accounts) — so opt in to
            # surfacing it instead of the best-effort default swallow,
            # which would return "a magic link has been sent" for a link
            # that was never sent.
            await self.email_service.send_email(
                to=user_dto.email,
                subject="Your Magic Login Link",
                type=MessageType.html,
                body=html_content,
                raise_on_failure=True
            )
        except ApiBaseException as e:
            raise e


    async def validate_magic_link(self, user_id: str, token: str) -> bool:
        """
        Validate the magic link token for the given user ID.
        Args:
            user_id (str): The ID of the user to validate the magic link for.
            token (str): The token to validate.
        Returns:
            bool: True if the token is valid, False otherwise.
        """
        try:
            record = await self.user_magic_link_repo.single_or_none(user_id=PydanticObjectId(user_id), token=token)
        except Exception:
            # A malformed user_id cannot match any stored record, so the
            # link is invalid — not a 500. The endpoint then raises its
            # Forbidden "Invalid or expired magic link." error, matching
            # the wrong-shape-token handling in jwt_token_service.py.
            # The catch is broad on purpose, as in BaseRepository.get
            # and the password-reset lookup: direct PydanticObjectId()
            # construction raises bson InvalidId for a malformed value,
            # not the pydantic ValidationError this previously caught
            # alone, so catching only ValidationError left a tampered
            # magic-link user_id escaping as a raw 500 instead of the
            # caller's invalid-link error.
            return False
        # No logging of the record here: it carries the magic-link token
        # itself, so printing it would leak a still-valid login token
        # into server stdout/logs.
        if record is None:
            return False

        result = validate_hashed_value(value=user_id, hashed_value=token)
        if result:
            # A successful validation consumes every outstanding link
            # for this user, not just the one presented: requesting a
            # second link (impatience, a resent email) left the first
            # one valid alongside it, so an old link stayed usable
            # after the user had already logged in through another
            # one. The creation cap (4 outstanding) and the 15-minute
            # TTL bound the window, but a used link must end the whole
            # set — the same single-use class as the password-reset
            # record, which is deleted on use.
            links = await self.user_magic_link_repo.search({"user_id": PydanticObjectId(user_id)})
            for link in links:
                await self.user_magic_link_repo.delete(id=str(link.id))

        return result

