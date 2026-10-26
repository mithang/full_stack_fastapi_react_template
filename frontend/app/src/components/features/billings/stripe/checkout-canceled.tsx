import { useEffect, useRef } from "react";
import { Link, useSearchParams } from "react-router";
import { useAuthContext } from "@/components/providers/auth-provider";
import { getApiClient } from "@/lib/utils";

export function CheckoutCanceled() {
    const [searchParams] = useSearchParams();
    const { accessToken } = useAuthContext();
    const tenantId = searchParams.get("tenant_id");
    const userId = searchParams.get("user_id");
    const notifiedRef = useRef<string | null>(null);

    // Finalise the cancellation server-side: until now this page was a
    // static stub, so a payer returning from Stripe never POSTed to the
    // /checkouts/*/payment/cancel endpoint and their billing record stayed
    // "pending". The cancel handlers only flip pending records to
    // canceled (a repeat call finds none), and the backend enforces the
    // tenant/user match, so this cannot cancel another tenant's records.
    // Skipped while no access token is held: this page is public and the
    // fetchUser effect skips it, so a fresh load has no in-memory token
    // yet — the effect re-runs when the worker refresh populates one.
    // Posting unauthenticated would only 401 and finalise nothing.
    // Failures are swallowed deliberately: the cancellation already
    // happened at Stripe, so a failed finalisation just leaves the record
    // pending (exactly as today) and must not turn this confirmation page
    // into an error page. The guard is assigned before the await so a
    // StrictMode double-invoke sends only once.
    useEffect(() => {
        if ((!tenantId && !userId) || !accessToken) return;
        const key = tenantId ?? `user:${userId}`;
        if (notifiedRef.current === key) return;
        notifiedRef.current = key;
        const client = getApiClient(accessToken).stripeCheckout;
        const request = tenantId
            ? client.hostCheckoutSuccessApiV1CheckoutsHostPaymentCancelPost({ tenantId })
            : client.tenantCheckoutCanceledApiV1CheckoutsTenantPaymentCancelPost();
        request.catch(() => undefined);
    }, [tenantId, userId, accessToken]);

    // Stripe always appends ?tenant_id= (host checkout) or ?user_id=
    // (tenant checkout) to the cancel_url (see billing_record_service).
    // Mirror the CheckoutSuccess guard from iteration 157: a visit with
    // neither parameter must not claim a payment was canceled — that is
    // a direct navigation, not a Stripe return.
    if (!tenantId && !userId) {
        return (
            <div>
                <h1>Checkout Return</h1>
                <p>We could not confirm a canceled payment from this link. If you just left a checkout, please check <Link to="/billing/checkouts">your billing page</Link> for its status.</p>
            </div>
        );
    }

    return (
        <div>
            <h1>Checkout Canceled</h1>
            <p>Your payment was canceled. You can try again or contact support if you need assistance.</p>
            <p><Link to="/billing/checkouts">View your checkouts</Link></p>
        </div>
    );
}