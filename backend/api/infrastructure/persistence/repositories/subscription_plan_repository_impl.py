# This repository is used to represent subscription plans in the system Not used by Stripe directly

from beanie import PydanticObjectId
from api.common.audit_logs_repository import AuditLogRepository
from api.common.base_repository import BaseRepository
from api.domain.dtos.audit_logs_dto import AuditLogDto
from api.domain.dtos.subcription_plan_dto import CreateSubscriptionPlanDto
from api.domain.entities.subscription_plan import SubscriptionPlan


class SubscriptionPlanRepository(BaseRepository[SubscriptionPlan], AuditLogRepository):
    def __init__(self):
        super().__init__(SubscriptionPlan)

    async def get_subscription_plan_by_id(self, subscription_id: str) -> SubscriptionPlan | None:
        return await super().get(id=subscription_id)

    async def get_subscription_plan_by_user_id(self, user_id: str) -> SubscriptionPlan | None:
        # Strip before conversion, as BaseRepository.get does (iteration
        # 1353): PydanticObjectId() requires exactly 24 hex chars, so a
        # padded id failed conversion and returned None for a plan that
        # exists. Clean ids unchanged; malformed ids still fail below.
        if isinstance(user_id, str):
            user_id = user_id.strip()
        try:
            user_oid = PydanticObjectId(user_id)
        except Exception:
            # A malformed id (e.g. a tampered path param) cannot match
            # any plan, so treat it as "not found" instead of escaping
            # as a 500; callers already handle None. Same broad catch
            # as BaseRepository.get: bson raises InvalidId, pydantic
            # paths raise ValidationError.
            return None
        return await super().single_or_none(user_id=user_oid)

    async def get_subscription_plans_by_tenant(self, tenant_id: str) -> SubscriptionPlan | None:
        # Same strip as get_subscription_plan_by_user_id above: a padded
        # tenant_id otherwise failed conversion and returned None.
        if isinstance(tenant_id, str):
            tenant_id = tenant_id.strip()
        try:
            tenant_oid = PydanticObjectId(tenant_id)
        except Exception:
            # As above: a malformed tenant_id (e.g. a tampered
            # activate_trial_plan path param) cannot match any plan.
            return None
        return await super().single_or_none(tenant_id=tenant_oid)

    async def create_subscription_plan(self, subscription_plan: CreateSubscriptionPlanDto) -> PydanticObjectId | None:
        # Strip before conversion, as above: create_trial_plan_for_tenant
        # passes the activate_trial_plan path tenant_id verbatim, and
        # BaseRepository.get (iteration 1353) already strips it for the
        # tenant fetch, so a padded path id reached this conversion and
        # failed — returning None and surfacing as "Failed to create
        # trial subscription plan." for a tenant that exists. Clean and
        # malformed ids behave exactly as before.
        # A whitespace-only id keeps its original value (truthy, so the
        # conversion below raises and returns None exactly as before)
        # instead of collapsing to "" and silently becoming a None id.
        tenant_id = subscription_plan.tenant_id.strip() if isinstance(subscription_plan.tenant_id, str) and subscription_plan.tenant_id.strip() else subscription_plan.tenant_id
        user_id = subscription_plan.user_id.strip() if isinstance(subscription_plan.user_id, str) and subscription_plan.user_id.strip() else subscription_plan.user_id
        try:
            tenant_oid = PydanticObjectId(tenant_id) if tenant_id else None
            user_oid = PydanticObjectId(user_id) if user_id else None
        except Exception:
            # DTO ids are plain strs, so a malformed tenant_id (e.g.
            # from the activate_trial_plan path param) would otherwise
            # escape as a 500 before anything is created. Return None
            # instead; the service maps None to InvalidOperationException
            # ("Failed to create trial subscription plan."), a clean
            # mapped error, and no plan row is created.
            return None
        subcription = SubscriptionPlan(
            tenant_id=tenant_oid,
            user_id=user_oid,
            plan_id=subscription_plan.plan_id,
            is_trial=subscription_plan.is_trial,
            actor=subscription_plan.actor,
            plan_level=subscription_plan.plan_level,
        )
        result = await super().create(subcription.model_dump(exclude_none=True))
        await self.add_audit_log(AuditLogDto(
            action="create",
            entity="SubscriptionPlan",
            user_id=str(subscription_plan.user_id),
            changes={"Info": "Created new subscription plan with id " + str(result.id)},
            tenant_id=str(subscription_plan.tenant_id) if subscription_plan.tenant_id else None
        ))
        return result.id

    async def update_subscription_plan(self, subscription_id: str, update_data: SubscriptionPlan) -> None:
        await super().update(subscription_id, update_data.model_dump(exclude_none=True))
        await self.add_audit_log(AuditLogDto(
            action="update",
            entity="SubscriptionPlan",
            user_id=str(update_data.user_id),
            changes={"Info": "Updated subscription plan with id " + subscription_id},
            tenant_id=str(update_data.tenant_id) if update_data.tenant_id else None
        ))

    async def delete_subscription_plan(self, subscription_id: str) -> None:
        exisiting =  await self.get_subscription_plan_by_id(subscription_id)
        if exisiting is None:
            await self.add_audit_log(AuditLogDto(
                action="delete",
                entity="SubscriptionPlan",
                user_id=None,
                changes={"Info": "Attempted to delete non-existing subscription plan with id " + subscription_id},
                tenant_id=None
            ))
            return
        await super().delete(subscription_id)
        await self.add_audit_log(AuditLogDto(
            action="delete",
            entity="SubscriptionPlan",
            user_id=str(exisiting.user_id) if exisiting.user_id else None,
            changes={"Info": "Deleted subscription plan with id " + subscription_id},
            tenant_id=str(exisiting.tenant_id) if exisiting.tenant_id else None
        ))
