from typing import Literal

from fastapi import Depends, Query, APIRouter, Response
from api.common.exceptions import ForbiddenException
from api.common.utils import get_date_range
from api.core.container import get_user_service
from api.domain.dtos.dashboard_dto import DashboardMetricsDto
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.usecases.user_service import UserService


router = APIRouter(prefix="/dashboard") # type: ignore
router.tags = ["Dashboard"]


def _assert_dashboard_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Read-in-wrong-DB guard, mirroring the user-list and invoice
    # guards: the metrics below are already filtered to the caller's
    # tenant stamp, but nothing checks which database served the
    # request. So a tenant caller hitting the host DB (no
    # X-Tenant-ID/subdomain, request scope None) would still read
    # tenant-stamped users sitting in the host DB (e.g. planted
    # before the user-create guard) — user counts and a signup
    # timeseries from the wrong database, presented as the tenant's
    # own dashboard. Legitimate tenant dashboard calls go through
    # ApiClient, which sends X-Tenant-ID whenever a tenant is
    # selected, so the middleware scope equals their tenant id;
    # host callers (tenant_id None) are unaffected. A mismatched
    # scope fails closed before any aggregation runs.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Dashboard metrics cannot be read outside your tenant's scope.")


@router.get("/",  response_model=DashboardMetricsDto)
async def get_dashboard_metrics(
    response: Response,
    current_user: CurrentUser,
    filter: Literal["today", "this_week", "last_3_months", "all"] = Query("all"),
    user_service: UserService = Depends(get_user_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_dashboard_scope(current_user, request_tenant_id)
    # Per-tenant metrics (user counts, signup timeseries): a
    # browser/proxy-cached 200 could serve one tenant's metrics to
    # another admin after an account switch, or hide fresh signups —
    # same no-store hardening as the /invoices and /ssos fixes.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Simulate fetching data based on the filter
    start, end, group_format = get_date_range(filter)

     # Base match query
    match_stage = {}
    if start:
        match_stage = {"created_at": {"$gte": start, "$lte": end}}

    # Scope to the caller's tenant: this endpoint has no permission
    # gate (it backs the landing page for every role), so without this
    # any authenticated tenant user saw global user counts and the
    # cross-tenant signup timeseries. Host users (tenant_id None) keep
    # the global view — the same scope rule as the /invoices and
    # /products lists. Merged into match_stage so it scopes the
    # timeseries, the joined count, and (via tenant_filter) the total.
    tenant_filter = {}
    if current_user.tenant_id:
        tenant_filter = {"tenant_id": current_user.tenant_id}
        match_stage = {**match_stage, **tenant_filter}

     # Aggregation pipeline for time series
    pipeline = [
        {"$match": match_stage} if match_stage else {"$match": {}},
        {
            "$group": {
                "_id": {"$dateToString": {"format": group_format, "date": "$created_at"}},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
        {
            "$project": {
                "time_or_date": "$_id",
                "count": "$count",
                "_id": 0
            }
        }
    ]

    timeseries =  await user_service.aggregate(pipeline)
    total_users = await user_service.total_count(tenant_filter) if tenant_filter else await user_service.total_count()
    joined_users = await user_service.total_count(match_stage) if match_stage else total_users

    data = {
        "filter": filter,
        "joined_users": joined_users,
        "total_users": total_users,
        "timeseries": timeseries
    }
    return DashboardMetricsDto(**data)
