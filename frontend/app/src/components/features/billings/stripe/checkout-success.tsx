import { useEffect, useRef } from "react";
import { Link, useSearchParams } from "react-router";
import { useAuthContext } from "@/components/providers/auth-provider";
import { getApiClient } from "@/lib/utils";

export function CheckoutSuccess() {
    const [searchParams] = useSearchParams();
    const { accessToken } = useAuthContext();
    const sessionId = searchParams.get("session_id");
    const tenantId = searchParams.get("tenant_id");
    const userId = searchParams.get("user_id");
    const notifiedRef = useRef<string | null>(null);

    // Finalise the payment server-side, mirroring the cancel page (iteration
    // 163): until now this page was a static stub, so a payer returning
    // from Stripe never POSTed to the /checkouts/*/payment/success endpoint
    // and their billing record stayed "pending". The success handlers
    // verify the Stripe session's payment_status is "paid" and check the
    // tenant/user match server-side, and re-running one only re-sets the
    // record to "succeeded", so this cannot confirm another tenant's
    // payment. Skipped while no access token is held: this page is public
    // and the fetchUser effect skips it, so a fresh load has no in-memory
    // token yet — the effect re-runs when the worker refresh populates
    // one. Posting unauthenticated would only 401 and finalise nothing.
    // Failures are swallowed deliberately: the payment already happened
    // at Stripe, so a failed finalisation just leaves the record pending
    // (exactly as today) and must not turn this confirmation page into an
    // error page. The guard is assigned before the await so a StrictMode
    // double-invoke sends only once.
    useEffect(() => {
        if (!sessionId || (!tenantId && !userId) || !accessToken) return;
        const key = `${sessionId}:${tenantId ?? `user:${userId}`}`;
        if (notifiedRef.current === key) return;
        notifiedRef.current = key;
        const client = getApiClient(accessToken).stripeCheckout;
        const request = tenantId
            ? client.hostCheckoutSuccessApiV1CheckoutsHostPaymentSuccessPost({ sessionId, tenantId })
            : client.tenantCheckoutSuccessApiV1CheckoutsTenantPaymentSuccessPost({ sessionId });
        request.catch(() => undefined);
    }, [sessionId, tenantId, userId, accessToken]);

    // Stripe always appends ?session_id= to the success_url (see
    // billing_record_service). A visit without a session id must not claim
    // a payment succeeded — that is a direct navigation, not a Stripe
    // return. Stripe also always appends ?tenant_id= (host checkout) or
    // ?user_id= (tenant checkout), so a session id with neither is
    // likewise a hand-crafted link, not a Stripe return — mirror the
    // cancel-page guard from iteration 159.
    if (!sessionId || (!tenantId && !userId)) {
        return (
            <div>
                <h1>Checkout Return</h1>
                <p>We could not confirm a payment from this link. If you just completed a checkout, please check <Link to="/billing/checkouts">your billing page</Link> for its status.</p>
            </div>
        );
    }

    return (
        <div>
            <h1>Checkout Success</h1>
            <p>Your payment was successful. Thank you for your purchase!</p>
            <p><Link to="/billing/checkouts">View your checkouts</Link></p>
        </div>
    );
}
