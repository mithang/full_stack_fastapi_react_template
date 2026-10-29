from api.core.exceptions import StripeSettingsNotFoundException
from api.domain.dtos.stripe_setting_dto import CreateStripeSettingDto, StripeSettingDto, StripeSettingSecretDto
from api.infrastructure.externals.stripe_resolver import StripeResolver
from api.infrastructure.persistence.repositories.payment_repository_impl import PaymentRepository
from api.usecases.tenant_service import TenantService


class StripeSettingService:
    def __init__(self, payment_repository: PaymentRepository, stripe_resolver: StripeResolver, tenant_service: TenantService):
        self.payment_repository: PaymentRepository = payment_repository
        self.stripe_resolver: StripeResolver = stripe_resolver
        self.tenant_service: TenantService = tenant_service

    async def configure_stripe_settings(self, settings: CreateStripeSettingDto, tenant_id: str) -> None:
        """
        Configure Stripe settings for the application.
        Args:
            settings (CreateStripeSettingDto): The Stripe settings to configure.
        Raises:
            StripeSettingsException: If there is an error configuring the settings.
            TenantNotFoundException: If the tenant does not exist.
        """
        await self.tenant_service.get_tenant_by_id(tenant_id)
        # Stamp server-side from the authenticated caller, not the DTO:
        # the endpoint already requires a tenant context and validates
        # this tenant exists, but the repository's creation branch stored
        # settings.tenant_id verbatim, so a client could stamp the record
        # with another tenant's id (or a bogus one the caller never
        # validated). The legitimate frontend sends current_tenant.id,
        # which equals the caller's tenant, so this is a no-op there.
        settings.tenant_id = tenant_id
        await self.payment_repository.store_stripe_settings(stripe_config=settings)
        
    async def get_stripe_settings(self, tenant_id: str) -> StripeSettingDto:
        """
        Get the Stripe settings for the application.
        Returns:
            StripeSettingDto: The Stripe settings.
        Raises:
            StripeSettingsNotFoundException: If there is an error retrieving the settings.
        """
        result = await self.payment_repository.get_stored_stripe_settings()
        # Scope to the caller's tenant, mirroring the GET /storage/
        # scoping: the repository returns the single record in the
        # current DB with no tenant filter, and the endpoint already
        # requires a tenant context — but a tenant caller without a
        # tenant DB selected (no X-Tenant-ID/subdomain, hitting the
        # host DB) would otherwise read whatever settings record sits
        # in the host DB, stamped with another tenant's id. A record
        # stamped with a different tenant (or none) is indistinguishable
        # from no settings at all, so it raises the same 404 the
        # repository raises when nothing is stored. The secret path
        # (get_stripe_secret, used by the webhook and the Stripe client
        # resolver) is deliberately unchanged: it resolves its own
        # tenant scope from the request/DB context, not the caller.
        if str(result.tenant_id) != str(tenant_id):
            raise StripeSettingsNotFoundException("Stripe settings not found.")
        return StripeSettingDto(
            id=str(result.id),
            tenant_id=str(result.tenant_id),
            default_currency=result.default_currency,
            mode=result.mode,
            trial_period_days=result.trial_period_days
        )
    
    async def get_stripe_secret(self) -> StripeSettingSecretDto:
        """
        Get the Stripe Webhook Secret.
        Returns:
            StripeSettingSecretDto: The Webhook secret from Stripe settings.
        Raises:
            StripeSettingsNotFoundException: If there is an error retrieving the settings.
        """
        result = await self.payment_repository.get_stored_stripe_settings()
        return StripeSettingSecretDto(
            stripe_webhook_secret=result.stripe_webhook_secret,
        )
