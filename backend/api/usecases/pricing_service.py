from api.common.utils import get_logger
from api.core.exceptions import PricingException, PricingNotFoundException
from api.domain.dtos.pricing_dto import CreatePricingDto, PricingListDto, UpdatePricingDto
from api.domain.entities.stripe_settings import ScopeType
from api.infrastructure.externals.stripe_resolver import StripeResolver
from api.infrastructure.persistence.repositories.payment_repository_impl import PaymentRepository

logger = get_logger(__name__)

class PricingService:
    def __init__(self, payment_repository: PaymentRepository, stripe_resolver: StripeResolver):
        self.payment_repository: PaymentRepository = payment_repository
        self.stripe_resolver: StripeResolver = stripe_resolver
    
    async def create_price(self, price: CreatePricingDto, scope: ScopeType) -> None:
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            return await sc.v1.prices.create_async(params=price.model_dump())
        except Exception as e:
            logger.error(f"Error creating price: {e}")
            raise PricingException(str(e))

    async def list_prices(self, scope: ScopeType) -> PricingListDto:
        # Wrap the Stripe calls, mirroring create_price/update_price in
        # this file: any failure here (bad key, Stripe outage) previously
        # propagated as a raw Stripe exception past the ApiBaseException-only
        # handler and surfaced as a 500. No 404 distinction is needed for
        # a list: an empty catalogue is a valid empty result, so a failure
        # is never a not-found.
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            result = await sc.v1.prices.list_async(params={"limit": 100})
        except Exception as e:
            logger.error(f"Error listing prices: {e}")
            raise PricingException(str(e))
        return PricingListDto(pricings=[pricing for pricing in result.data],  has_more=result.has_more)
    
    async def update_price(self, price_id: str, update: UpdatePricingDto, scope: ScopeType) -> None:
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            await sc.v1.prices.update_async(price=price_id, params={
                "active": update.active,
                "tax_behavior": update.tax_behavior,
                "metadata": update.metadata or {}
            })
        except Exception as e:
            logger.error(f"Error updating price {price_id}: {e}")
            # Only a Stripe 404 (unknown price id; stripe errors carry
            # http_status) is a genuine not-found, mirroring the
            # product-delete and billing get/delete fixes. Anything else
            # — auth failure, Stripe outage, resolver error — is a
            # pricing error, not a 404 claiming the price does not exist.
            if getattr(e, "http_status", None) == 404:
                raise PricingNotFoundException(price_id) from e
            raise PricingException(str(e))
    
