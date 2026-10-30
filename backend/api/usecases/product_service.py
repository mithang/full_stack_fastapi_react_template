from api.common.utils import get_logger
from api.core.exceptions import ProductException, ProductNotFoundException
from api.domain.dtos.product_dto import CreateProductDto, ProductDto, ProductListDto
from api.domain.entities.stripe_settings import ScopeType
from api.infrastructure.externals.stripe_resolver import StripeResolver
from api.infrastructure.persistence.repositories.payment_repository_impl import PaymentRepository

logger = get_logger(__name__)


def _safe_log_value(value: object) -> str:
    # Product ids arrive as a {product_id:path} URL param, which
    # Starlette percent-decodes, so a newline-bearing id would
    # otherwise reach the log lines below (and, via the exception
    # messages, the API exception handler's log line) and forge extra
    # log lines. Only the logged/reported copy is flattened; the raw
    # id still drives the Stripe calls, and normal ids render
    # identically.
    return str(value).replace("\r", " ").replace("\n", " ")


class ProductService:
    def __init__(self, payment_repository: PaymentRepository, stripe_resolver: StripeResolver):
        self.payment_repository: PaymentRepository = payment_repository
        self.stripe_resolver: StripeResolver = stripe_resolver

    async def list_products(self, scope: ScopeType, show_active: bool = True) -> ProductListDto:
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            result =  await sc.v1.products.list_async(params={"limit": 100, "active": show_active})
        except Exception as e:
            # The list was unwrapped, so a Stripe failure (bad key,
            # outage, resolver error) reached the client as a raw 500
            # instead of a mapped API error — unlike every
            # single-product operation, which now raises
            # ProductException. A list failure is never a not-found
            # (an empty catalogue is a valid empty result), so it
            # always becomes a product error (406 via ProductException).
            logger.error(f"Failed to list products: {str(e)}")
            # Detail stays server-side in the log above: the handler
            # returns the exception message verbatim, so appending
            # str(e) would leak Stripe/resolver internals to the client.
            raise ProductException("Failed to list products.") from e
        return ProductListDto(products=[product for product in result.data],  has_more=result.has_more)
    
    async def get_product_by_id(self, product_id: str,  scope: ScopeType) -> ProductDto:
        # Strip before the Stripe lookup: unlike ObjectId path ids,
        # which BaseRepository.get() now strips centrally, Stripe
        # product ids reach Stripe verbatim, so a padded id
        # (copied/pasted, %20-encoded in the path param) failed the
        # Stripe retrieve and surfaced as a 404 for a product that
        # exists. Stripe ids never legitimately carry surrounding
        # whitespace; clean ids are unchanged and whitespace-only /
        # unknown ids still map to ProductNotFound exactly as before.
        if isinstance(product_id, str):
            product_id = product_id.strip()
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            product = await sc.v1.products.retrieve_async(id=product_id)
        except Exception as e:
            logger.error(f"Failed to retrieve product {_safe_log_value(product_id)}: {str(e)}")
            # The retrieve is unwrapped, so a Stripe failure reached the
            # client as a raw 500 instead of a mapped API error — and
            # an unknown product id was indistinguishable from an outage.
            # Only a Stripe 404 (stripe errors carry http_status) is a
            # genuine not-found, mirroring the get_plan fix; anything
            # else — auth failure, Stripe outage, resolver error — is a
            # product error (406 via ProductException).
            if getattr(e, "http_status", None) == 404:
                raise ProductNotFoundException(_safe_log_value(product_id)) from e
            raise ProductException(f"Failed to retrieve product {_safe_log_value(product_id)}.") from e
        if not product:
            raise ProductNotFoundException(f"Product with ID {_safe_log_value(product_id)} not found.")
        return ProductDto(id=product.id, name=product.name, description=product.description, active=product.active, tax_code=product.tax_code) 

    async def create_product(self, product_dto: CreateProductDto, scope: ScopeType):
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            params = product_dto.model_dump()
            await sc.v1.products.create_async(params=params)
            logger.debug(f"Product created successfully in {scope} scope.")
        except Exception as e:
            # Handle specific exceptions if needed
            logger.error(f"Failed to create product: {str(e)}")
            raise ProductException("Failed to create product.") from e

    async def update_product(self, product_id: str, product_dto: CreateProductDto, scope: ScopeType):
        # Same padded-id class as get_product_by_id above: strip
        # before both the pre-update retrieve and the update call.
        if isinstance(product_id, str):
            product_id = product_id.strip()
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            existing_product = await sc.v1.products.retrieve_async(id=product_id)
            if not existing_product:
                raise ProductNotFoundException(f"Product with ID {_safe_log_value(product_id)} not found.")
            
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            params = product_dto.model_dump()
            await sc.v1.products.update_async(id=product_id, params=params)
            logger.debug(f"Product with ID {product_id} updated successfully in {scope} scope.")
        except ProductNotFoundException:
            # A genuinely missing product (raised above) keeps its 404;
            # only Stripe/update failures below become a product error.
            raise
        except Exception as e:
            # Only a Stripe 404 (unknown product id, from the pre-update
            # retrieve; stripe errors carry http_status) is a genuine
            # not-found, mirroring get_product_by_id and delete_product
            # in this file and the billing/pricing update fixes. Anything
            # else — bad payload, Stripe outage, resolver error — is a
            # product error (406 via ProductException), not a 404.
            logger.error(f"Failed to update product: {str(e)}")
            if getattr(e, "http_status", None) == 404:
                raise ProductNotFoundException(f"Product with ID {_safe_log_value(product_id)} not found.") from e
            raise ProductException(f"Failed to update product {_safe_log_value(product_id)}.") from e

    async def delete_product(self, product_id: str, scope: ScopeType):
        # Same padded-id class as get_product_by_id above.
        if isinstance(product_id, str):
            product_id = product_id.strip()
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            await sc.v1.products.delete_async(id=product_id)
            logger.debug(f"Product with ID {product_id} deleted successfully in {scope} scope.")
        except Exception as e:
            # Handle specific exceptions if needed
            logger.error(f"Failed to delete product: {str(e)}")
            # Only a Stripe 404 (unknown product id; stripe errors carry
            # http_status) is a genuine not-found. Anything else — auth
            # failure, Stripe outage, resolver error — is a product error,
            # not a 404 claiming the product does not exist.
            if getattr(e, "http_status", None) == 404:
                raise ProductNotFoundException(f"Product with ID {_safe_log_value(product_id)} not found.") from e
            raise ProductException(f"Failed to delete product {_safe_log_value(product_id)}.") from e
