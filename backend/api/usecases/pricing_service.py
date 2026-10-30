from api.common.utils import get_logger
from api.core.exceptions import PricingException, PricingNotFoundException, ProductNotFoundException
from api.domain.dtos.pricing_dto import CreatePricingDto, PricingListDto, UpdatePricingDto
from api.domain.entities.stripe_settings import ScopeType
from api.infrastructure.externals.stripe_resolver import StripeResolver
from api.infrastructure.persistence.repositories.payment_repository_impl import PaymentRepository

logger = get_logger(__name__)


def _safe_log_value(value: object) -> str:
    # Price/product ids arrive as a {price_id:path} URL param (Starlette
    # percent-decodes it) or as a plain JSON-body str, so a
    # newline-bearing id would otherwise reach log lines and the
    # ApiBaseException handler's ex.message log line verbatim.
    return str(value).replace("\r", " ").replace("\n", " ")

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
            # Only a Stripe 404 is a genuine not-found, mirroring
            # create_plan in billing_record_service.py: a price create
            # references exactly one id — its product — so a 404 means
            # that product does not exist, not the price being created.
            # Anything else is a pricing error, not a 404.
            if getattr(e, "http_status", None) == 404:
                raise ProductNotFoundException(_safe_log_value(price.product)) from e
            # Generic message only: the Stripe/resolver detail stays in
            # the logger.error line above instead of reaching the client
            # verbatim via the ApiBaseException handler.
            raise PricingException("Failed to create price.")

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
            # Generic message only: the Stripe/resolver detail stays in
            # the logger.error line above instead of reaching the client
            # verbatim via the ApiBaseException handler.
            raise PricingException("Failed to list prices.")
        return PricingListDto(pricings=[pricing for pricing in result.data],  has_more=result.has_more)
    
    async def update_price(self, price_id: str, update: UpdatePricingDto, scope: ScopeType) -> None:
        # Same padded-id class as the product/plan-id fixes: price ids
        # arrive as a {price_id:path} param and reach Stripe verbatim,
        # so a padded id (copied/pasted, %20-encoded) failed the Stripe
        # call and surfaced as a 404 for a price that exists. Stripe
        # ids never legitimately carry surrounding whitespace; clean
        # ids are unchanged and whitespace-only/unknown ids still map
        # to PricingNotFound exactly as before.
        if isinstance(price_id, str):
            price_id = price_id.strip()
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            await sc.v1.prices.update_async(price=price_id, params={
                "active": update.active,
                "tax_behavior": update.tax_behavior,
                "metadata": update.metadata or {}
            })
        except Exception as e:
            logger.error(f"Error updating price {_safe_log_value(price_id)}: {e}")
            # Only a Stripe 404 (unknown price id; stripe errors carry
            # http_status) is a genuine not-found, mirroring the
            # product-delete and billing get/delete fixes. Anything else
            # — auth failure, Stripe outage, resolver error — is a
            # pricing error, not a 404 claiming the price does not exist.
            if getattr(e, "http_status", None) == 404:
                raise PricingNotFoundException(_safe_log_value(price_id)) from e
            # Generic message only, with the id sanitized: the raw id
            # would otherwise reach the logs again via the
            # ApiBaseException handler's ex.message log line. The
            # Stripe/resolver detail stays in the logger.error line
            # above instead of reaching the client verbatim.
            raise PricingException(f"Failed to update price {_safe_log_value(price_id)}.")
    
