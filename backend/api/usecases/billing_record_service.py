from typing import Any, Literal, Optional, get_args

from api.common.utils import get_logger
from api.core.exceptions import (BillingRecordException,
                                 BillingRecordNotFoundException)
from api.domain.dtos.billing_dto import (BillingRecordDto,
                                         BillingRecordListDto, CreatePlanDto,
                                         InvoiceListDto, PlanDto, PlanListDto,
                                         UpdatePlanDto)
from api.domain.dtos.checkout_dto import CheckoutRequestDto
from api.domain.entities.stripe_settings import (BillingRecord,
                                                 ScopeType, StatusType)
from api.infrastructure.externals.stripe_resolver import StripeResolver
from api.infrastructure.persistence.repositories.billing_record_repository_impl import \
    BillingRecordRepository
from api.infrastructure.persistence.repositories.payment_repository_impl import \
    PaymentRepository
from beanie import PydanticObjectId
from stripe import StripeClient

logger = get_logger(__name__)


class BillingRecordService:
    def __init__(
        self,
        payment_repository: PaymentRepository,
        billing_record_repository: BillingRecordRepository,
        stripe_resolver: StripeResolver,
    ):
        self.payment_repository: PaymentRepository = payment_repository
        self.billing_record_repository: BillingRecordRepository = (
            billing_record_repository
        )
        self.stripe_resolver: StripeResolver = stripe_resolver

    # Helper methods
    def _extract_period(
        self, line: dict[str, Any]
    ) -> tuple[Optional[int], Optional[int]]:
        # Guard an explicit null period the same way the invoice-lines
        # and line-metadata guards do: a null would otherwise raise
        # AttributeError here, outside the save try/catch, turning a
        # valid invoice.paid delivery into a 500 that Stripe retries
        # forever. Missing/null periods yield (None, None), as for a
        # period object without start/end.
        # Guard a non-dict period the same way _extract_tenant_id guards
        # its metadata lookups: an explicit null was already guarded,
        # but a truthy non-dict value (e.g. a string) would still raise
        # AttributeError here, outside the save try/catch, turning a
        # valid invoice.paid delivery into a 500 that Stripe retries
        # forever.
        period = line.get("period")
        if not isinstance(period, dict):
            period = {}
        return period.get("start"), period.get("end")

    def _extract_pricing(
        self, line: dict[str, Any]
    ) -> tuple[Optional[str], Optional[str]]:
        pricing = line.get("pricing") or line.get("price")
        if not pricing or not isinstance(pricing, dict):
            return None, None

        # New Stripe format
        details = pricing.get("price_details")
        if isinstance(details, dict):
            return details.get("price"), details.get("product")
        # Legacy line-item format: no price_details wrapper, so the price
        # object itself carries the id/product. Indexing price_details
        # unconditionally raised KeyError here, turning a valid
        # invoice.paid delivery into a 500 that Stripe retries forever.
        return pricing.get("id"), pricing.get("product")

    def _extract_tenant_id(self, line: dict[str, Any], scope: str) -> Optional[str]:
        if scope != "tenant":
            return None

        # Most reliable: line metadata. Guard a null/non-dict metadata
        # value the same way the parent/subscription lookups below do
        # (and as the invoice-level metadata guard does): an explicit
        # null was already guarded, but a truthy non-dict value (e.g. a
        # string) would still raise AttributeError here, outside the
        # save try/catch, turning a valid invoice.paid delivery into a
        # 500 that Stripe retries forever.
        line_metadata = line.get("metadata")
        tenant_id = (
            line_metadata.get("tenant_id")
            if isinstance(line_metadata, dict)
            else None
        )
        if tenant_id:
            return tenant_id

        # Fallback: subscription metadata. Guard null/non-dict values the
        # same way _extract_pricing guards price_details: a null or
        # non-dict parent or subscription_details value would otherwise
        # raise AttributeError here, outside the save try/catch, turning
        # a valid invoice.paid delivery into a 500 that Stripe retries
        # forever.
        parent = line.get("parent")
        sub_details = (
            parent.get("subscription_details") if isinstance(parent, dict) else None
        )
        metadata = (
            sub_details.get("metadata") if isinstance(sub_details, dict) else None
        )

        if isinstance(metadata, dict):
            return metadata.get("tenant_id")

        return None

    # Helper methods end here

    async def list_plans(self, scope: ScopeType) -> PlanListDto:
        sc = await self.stripe_resolver.get_stripe_client(scope=scope)
        result = await sc.v1.plans.list_async(params={"limit": 100})
        if len(result.data) == 0:
            return PlanListDto(plans=[], has_more=False)
        return PlanListDto(
            plans=[plan for plan in result.data], has_more=result.has_more
        )

    async def create_plan(self, new_plan: CreatePlanDto, scope: ScopeType) -> None:
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            await sc.v1.plans.create_async(
                params={
                    "amount": new_plan.amount,
                    "interval": new_plan.interval,
                    "currency": new_plan.currency,
                    "product": new_plan.product_id,
                }
            )
        except Exception as e:
            logger.error(f"Error creating plan : {e}")
            raise BillingRecordException(str(e))

    async def update_plan(
        self, plan_id: str, update_plan: UpdatePlanDto, scope: ScopeType
    ) -> None:
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            await sc.v1.plans.update_async(
                plan=plan_id,
                params={
                    "active": update_plan.active,
                    "trial_period_days": update_plan.trial_period_days,
                    "metadata": update_plan.metadata or {},
                },
            )
        except Exception as e:
            logger.error(f"Error updating plan {plan_id}: {e}")
            raise BillingRecordNotFoundException(plan_id)

    async def get_plan(self, plan_id: str, scope: ScopeType) -> PlanDto:
        try:
            sc = await self.stripe_resolver.get_stripe_client(scope=scope)
            return await sc.v1.plans.retrieve_async(plan=plan_id)
        except Exception as e:
            logger.error(f"Error retrieving plan {plan_id}: {e}")
            raise BillingRecordNotFoundException(plan_id)

    async def delete_plan(self, plan_id: str, scope: ScopeType) -> None:
        sc = await self.stripe_resolver.get_stripe_client(scope=scope)
        result = await sc.v1.plans.delete_async(plan=plan_id)
        if result.deleted is False:
            raise BillingRecordException(f"Unable to delete the plan {plan_id}.")

    async def list_invoices(self, scope: ScopeType) -> InvoiceListDto:
        sc = await self.stripe_resolver.get_stripe_client(scope=scope)
        result = await sc.v1.invoices.list_async(params={"limit": 100})
        return InvoiceListDto(
            invoices=[invoice for invoice in result.data], has_more=result.has_more
        )

    async def create_host_check_out_session_for_tenant(
        self, frontend_url: str, checkout_req: CheckoutRequestDto
    ) -> str:
        """
        Create a Stripe checkout session for host scope for a tenant
        """
        sc: StripeClient = await self.stripe_resolver.get_stripe_client(scope="host")
        customer = await sc.v1.customers.create_async(
            params={
                "metadata": {"tenant_id": checkout_req.tenant_id},
                "email": checkout_req.email,
            }
        )

        checkout_session = await sc.v1.checkout.sessions.create_async(
            params={
                "mode": checkout_req.mode,
                "customer": customer.id,
                "line_items": [{"price": checkout_req.price_id, "quantity": 1}],
                "success_url": f"{frontend_url}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}&tenant_id={checkout_req.tenant_id}",
                "cancel_url": f"{frontend_url}/checkout/cancel?tenant_id={checkout_req.tenant_id}",
            }
        )
        billing_record = BillingRecord(
            scope="host",
            actor="tenant",
            tenant_id=checkout_req.tenant_id,
            payment_type=checkout_req.mode,
            price_id=checkout_req.price_id,
            stripe_customer_id=customer.id,
            stripe_session_id=checkout_session.id,
            currency=checkout_session.currency if checkout_session.currency else "eur",
            status="pending",
        )
        await self.billing_record_repository.create(billing_record.model_dump())
        return checkout_session.url

    async def create_tenant_check_out_session_for_tenant_users(
        self, frontend_url: str, user_id: str, checkout_req: CheckoutRequestDto
    ) -> str:
        """
        Create a Stripe checkout session for tenant scope for tenant's users
        """
        sc: StripeClient = await self.stripe_resolver.get_stripe_client(scope="tenant")
        customer = await sc.v1.customers.create_async(
            params={
                "email": checkout_req.email,
                "metadata": {"tenant_id": checkout_req.tenant_id, "user_id": user_id},
            }
        )

        checkout_session = await sc.v1.checkout.sessions.create_async(
            params={
                "mode": checkout_req.mode,
                "customer": customer.id,
                "line_items": [{"price": checkout_req.price_id, "quantity": 1}],
                "success_url": f"{frontend_url}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}&user_id={user_id}",
                "cancel_url": f"{frontend_url}/checkout/cancel?user_id={user_id}",
            }
        )

        billing_record = BillingRecord(
            scope="tenant",
            actor="end_user",
            tenant_id=checkout_req.tenant_id,
            user_id=user_id,
            payment_type=checkout_req.mode,
            price_id=checkout_req.price_id,
            stripe_customer_id=customer.id,
            stripe_session_id=checkout_session.id,
            currency=checkout_session.currency if checkout_session.currency else "eur",
            status="pending",
        )

        await self.billing_record_repository.create(billing_record.model_dump())
        return checkout_session.url

    async def handle_host_checkout_success(
        self, session_id: str, tenant_id: str
    ) -> None:
        """
        Handle successful checkout for host scope
        """
        sc: StripeClient = await self.stripe_resolver.get_stripe_client(scope="host")
        session = await sc.v1.checkout.sessions.retrieve_async(session=session_id)
        if session.payment_status != "paid":
            raise BillingRecordException(
                f"Payment not completed for session {session_id}"
            )

        # The Stripe session id is stored as stripe_session_id (see the
        # create_*_check_out_session methods above), not session_id, so
        # looking it up as session_id could never match and every host
        # success finalisation raised NotFound instead of flipping the
        # record to "succeeded".
        billing_record = await self.billing_record_repository.single_or_none(
            stripe_session_id=session_id
        )
        if billing_record is None:
            raise BillingRecordNotFoundException(session_id)
        # Scope-guard the record: tenant-scope checkouts store the same
        # tenant_id, so the tenant check below alone would also accept a
        # tenant-scope record here (the host-cancel handler got the same
        # scope filter in an earlier iteration). A tenant-scope session
        # must finalise through the tenant success handler instead.
        if billing_record.scope != "host":
            raise BillingRecordException(
                f"Scope mismatch for the billing record {session_id}"
            )
        # billing_record.tenant_id is a PydanticObjectId while the caller
        # passes current_user.tenant_id, a str (UserDto.tenant_id is str),
        # so a raw != is always true and every host success finalisation
        # raised a mismatch. Compare as strings, mirroring the tenant
        # success handler's str(billing_record.user_id) check below.
        if str(billing_record.tenant_id) != tenant_id:
            raise BillingRecordException(
                f"Tenant ID mismatch for the billing record {session_id}"
            )

        billing_record.status = "succeeded"
        await self.billing_record_repository.update(
            billing_record.id, billing_record.model_dump()
        )

    async def handle_host_checkout_canceled(self, tenant_id: str) -> None:
        """
        Handle cancelled checkout for host scope
        """
        # The stored tenant_id is a PydanticObjectId (see ApiBaseModel),
        # so searching with the raw str (as before) never matched and
        # pending host records were silently never marked canceled —
        # the same class as the tenant-cancel fix, which converts the
        # string user id. The endpoint already guarantees tenant_id is
        # a non-empty string equal to current_user.tenant_id, so the
        # conversion cannot fail on a missing/invalid value here.
        # Scope the search to host records: tenant-scope checkouts store
        # the same tenant_id (see create_tenant_check_out_session_for_tenant_users),
        # so without this filter cancelling a host checkout would also mark
        # any still-open tenant-scope checkout for the tenant as canceled.
        billing_records = await self.billing_record_repository.search(
            {"tenant_id": PydanticObjectId(tenant_id), "scope": "host", "status": "pending"}
        )
        for record in billing_records:
            record.status = "canceled"
            await self.billing_record_repository.update(record.id, record.model_dump())

    async def handle_tenant_checkout_success(
        self, session_id: str, user_id: str, tenant_id: str
    ) -> None:
        """
        Handle successful checkout for tenant scope
        """
        sc: StripeClient = await self.stripe_resolver.get_stripe_client(scope="tenant")
        session = await sc.v1.checkout.sessions.retrieve_async(session=session_id)
        if session.payment_status != "paid":
            raise BillingRecordException(
                f"Payment not completed for session {session_id}"
            )

        # Same field-name fix as the host handler above: the session id is
        # stored as stripe_session_id, so a session_id lookup never matched.
        billing_record = await self.billing_record_repository.single_or_none(
            stripe_session_id=session_id
        )
        if billing_record is None:
            raise BillingRecordNotFoundException(session_id)
        # Scope-guard the record, mirroring the host success handler:
        # host-scope records carry no user_id, so the user check below
        # only rejects them incidentally (str(None) == "None" never
        # matches a real user id). A host record must finalise through
        # the host success handler instead, regardless of what user_id
        # it may carry in future.
        if billing_record.scope != "tenant":
            raise BillingRecordException(
                f"Scope mismatch for the billing record {session_id}"
            )
        # Tenant-guard the record, mirroring the host success handler:
        # the user check below alone would accept a tenant-scope record
        # created under a different tenant for the same user (e.g. a
        # user who has since moved tenants), finalising another tenant's
        # billing. Compare as strings, as billing_record.tenant_id is a
        # PydanticObjectId while the caller passes a str.
        if str(billing_record.tenant_id) != tenant_id:
            raise BillingRecordException(
                f"Tenant ID mismatch for the billing record {session_id}"
            )
        if str(billing_record.user_id) != user_id:
            raise BillingRecordException(
                f"User ID mismatch for the billing record {session_id}"
            )

        billing_record.status = "succeeded"
        await self.billing_record_repository.update(
            billing_record.id, billing_record.model_dump()
        )

    async def handle_tenant_checkout_canceled(
        self, user_id: str, tenant_id: str
    ) -> None:
        """
        Handle cancelled checkout for tenant scope
        """
        # BillingRecordRepository.list() takes (skip, limit) and returns a
        # BillingRecordListDto, so passing a filter dict to it (as before)
        # could never work: the dict reached .skip() and the DTO is not
        # iterable, so POST /checkouts/tenant/payment/cancel always
        # failed and pending records were never marked canceled. Mirror
        # the host handler and use search(), which returns model docs;
        # convert the string user id to PydanticObjectId, as the stored
        # user_id field is an ObjectId (repo convention elsewhere).
        # Scope the search to tenant records, mirroring the host-cancel
        # handler's scope filter: host records currently carry no user_id,
        # so this changes nothing today, but a host record must never be
        # canceled by a tenant cancel even if it ever gains a user_id.
        billing_records = await self.billing_record_repository.search(
            {"user_id": PydanticObjectId(user_id), "scope": "tenant", "status": "pending"}
        )
        for record in billing_records:
            # Tenant-guard the record, mirroring the tenant success
            # handler's tenant check: the user check alone would also
            # cancel a tenant-scope record created under a different
            # tenant for the same user (e.g. a user who has since moved
            # tenants). Compared as strings, as record.tenant_id is a
            # PydanticObjectId while the caller passes a str; a None
            # tenant_id fails closed (matches nothing) rather than
            # cancelling another tenant's records.
            if str(record.tenant_id) != tenant_id:
                continue
            record.status = "canceled"
            await self.billing_record_repository.update(record.id, record.model_dump())

    async def list_checkout_records(
        self, skip: int = 0, limit: int = 100
    ) -> BillingRecordListDto:
        """
        List checkout records
        """
        return await self.billing_record_repository.list(skip=skip, limit=limit)

    async def from_stripe_invoice_paid(
        self,
        invoice: dict[str, Any],
        scope: Literal["tenant", "host"],
        tenant_id: Optional[str] = None,
    ) -> Optional[BillingRecord]:
        """
        Converts a Stripe `invoice.paid` event into a BillingRecordDto.
        Returns None if not applicable (e.g. no subscription).
        """
        # Extract first line item (99.9% of cases there's only one).
        # Guard a null lines value the same way the metadata lookups
        # already do: an explicit null would otherwise raise
        # AttributeError here, outside the save try/catch, turning a
        # valid invoice.paid delivery into a 500 that Stripe retries
        # forever. A null data list falls through to the falsy check
        # below and returns None, as for an empty list.
        # Guard a non-dict lines value the same way the metadata
        # lookups already do: (invoice.get("lines") or {}).get(...)
        # raises AttributeError on a truthy non-dict value (e.g. a
        # string or list), outside the save try/catch, turning a
        # valid invoice.paid delivery into a 500 that Stripe retries
        # forever. A non-dict lines value is treated like no lines
        # at all and returns None, as for an empty list.
        lines_container = invoice.get("lines")
        lines = (
            lines_container.get("data", [])
            if isinstance(lines_container, dict)
            else []
        )
        # Guard a non-list data value the same way the period and
        # metadata lookups already guard non-dict values: a dict data
        # value would raise KeyError on lines[0] below, and a string
        # data value would hand a character to _extract_period, raising
        # AttributeError there — both outside the save try/catch,
        # turning a valid invoice.paid delivery into a 500 that Stripe
        # retries forever. A non-list data value is treated like an
        # empty list and returns None, as for no lines at all.
        if not isinstance(lines, list) or not lines:
            return None

        line = lines[0]
        # Guard a non-dict line element the same way the lines data
        # itself is guarded above: a string/int/null element would
        # otherwise raise AttributeError inside _extract_period (which
        # calls line.get), outside the save try/catch, turning a valid
        # invoice.paid delivery into a 500 that Stripe retries forever.
        # A non-dict first line is treated like no lines at all and
        # returns None, as for an empty list.
        if not isinstance(line, dict):
            return None

        period_start, period_end = self._extract_period(line)
        price_id, product_id = self._extract_pricing(line)
        tenant_id = tenant_id or self._extract_tenant_id(line, scope)

        # Guard the currency the same way the lines/period/metadata
        # lookups above guard null/non-dict values: invoice["currency"]
        # raises KeyError when absent and .upper() raises AttributeError
        # on a null/non-string value — both outside the save try/catch,
        # turning a valid invoice.paid delivery into a 500 that Stripe
        # retries forever. A malformed currency is treated like no lines
        # at all and returns None, as for an empty list.
        currency = invoice.get("currency")
        if not isinstance(currency, str) or not currency:
            return None

        # Guard the amount the same way the currency above guards a
        # malformed value: invoice["amount_paid"] raises KeyError when
        # absent, and a null/non-int value would fail BillingRecord
        # validation — both outside the save try/catch, turning a valid
        # invoice.paid delivery into a 500 that Stripe retries forever.
        # Amount is Optional[int] on the record, so a malformed value
        # falls back to None and the paid record is still persisted,
        # as for a record with no amount at all. bool is excluded
        # explicitly since it is an int subclass in Python.
        amount_paid = invoice.get("amount_paid")
        if isinstance(amount_paid, bool) or not isinstance(amount_paid, int):
            amount_paid = None

        # Guard the customer the same way the amount above guards a
        # malformed value: invoice["customer"] raises KeyError when
        # absent, and a null/non-string value would fail BillingRecord
        # validation — both outside the save try/catch, turning a valid
        # invoice.paid delivery into a 500 that Stripe retries forever.
        # stripe_customer_id is Optional[str] on the record, so a
        # malformed value falls back to None and the paid record is
        # still persisted, as for a record with no amount at all.
        stripe_customer_id = invoice.get("customer")
        if not isinstance(stripe_customer_id, str) or not stripe_customer_id:
            stripe_customer_id = None

        # Guard the status the same way the customer above guards a
        # malformed value: invoice["status"] raises KeyError when
        # absent, and a value outside StatusType (e.g. a Stripe "open"
        # or "void" invoice status, which the record's Literal does not
        # allow) would fail BillingRecord validation — both outside
        # the save try/catch, turning a valid invoice.paid delivery
        # into a 500 that Stripe retries forever. A usable status is
        # kept; anything else falls back to "paid", which the
        # invoice.paid event itself guarantees.
        status = invoice.get("status")
        if status not in get_args(StatusType):
            status = "paid"

        # Guard the invoice id the same way the status above guards a
        # malformed value: invoice["id"] raises KeyError when absent,
        # and a null/non-string value would fail the metadata
        # Dict[str, str] validation — both outside the save try/catch,
        # turning a valid invoice.paid delivery into a 500 that Stripe
        # retries forever. The id is metadata only (not a record
        # field), so a malformed value falls back to "" and the paid
        # record is still persisted, as for a record with no amount
        # at all.
        invoice_id = invoice.get("id")
        if not isinstance(invoice_id, str) or not invoice_id:
            invoice_id = ""

        # Guard the subscription the same way the customer above guards
        # a malformed value: invoice.get("subscription") is passed
        # straight to stripe_subscription_id (Optional[str]), so an
        # expanded subscription object (a dict, when the invoice was
        # fetched with expand[]) or a null/non-string value would fail
        # BillingRecord validation — outside the save try/catch,
        # turning a valid invoice.paid delivery into a 500 that Stripe
        # retries forever. An expanded object keeps its id (the useful
        # linkage); anything else malformed falls back to None and the
        # paid record is still persisted, as for a record with no
        # customer at all.
        stripe_subscription_id = invoice.get("subscription")
        if isinstance(stripe_subscription_id, dict):
            stripe_subscription_id = stripe_subscription_id.get("id")
        if not isinstance(stripe_subscription_id, str) or not stripe_subscription_id:
            stripe_subscription_id = None

        # Build Object
        return BillingRecord(
            scope=scope,
            actor="tenant" if tenant_id else "end_user",
            tenant_id=PydanticObjectId(tenant_id) if tenant_id else None,
            user_id=None,
            payment_type="card",
            currency=currency.upper(),
            amount=amount_paid,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            stripe_session_id=None,
            product_id=product_id,
            price_id=price_id,
            status=status,
            current_period_end=period_end,
            canceled_at=None,
            cancellation_reason=None,
            # Guard the metadata values the same way the status/id above
            # guard malformed values: metadata is Dict[str, str] on
            # BillingRecord, so a null/non-string billing_reason,
            # hosted_invoice_url, or invoice_pdf (all nullable in
            # Stripe's invoice object) would fail validation — outside
            # the save try/catch, turning a valid invoice.paid delivery
            # into a 500 that Stripe retries forever. Non-string values
            # are dropped; the id/period entries are already strings, so
            # they are always kept, and metadata is informational only.
            metadata={
                key: value
                for key, value in {
                    "invoice_id": invoice_id,
                    "stripe_event_id": invoice_id,
                    "billing_reason": invoice.get("billing_reason"),
                    "hosted_invoice_url": invoice.get("hosted_invoice_url"),
                    "invoice_pdf": invoice.get("invoice_pdf"),
                    "period_start": str(period_start),
                    "period_end": str(period_end),
                }.items()
                if isinstance(value, str)
            },
        )

    async def create_billing_record(self, billing_record: BillingRecord) -> None:
        """
        Create a billing record in the database
        """
        await self.billing_record_repository.create(billing_record.model_dump())
