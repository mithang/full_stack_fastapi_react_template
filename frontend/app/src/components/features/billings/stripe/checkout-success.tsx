import { useEffect, useRef, useState } from "react";
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
    // "confirming" while no token is held yet or the finalisation POST is
    // in flight, "confirmed" once it resolves, "unconfirmed" if it fails.
    // The page previously claimed success on query params alone, before
    // any finalisation had happened (or after it had failed) — see the
    // render below. A failed finalisation still shows no error page: the
    // payment already happened at Stripe, and the billing page is the
    // place to check its recorded status.
    const [finalisation, setFinalisation] = useState<"confirming" | "confirmed" | "unconfirmed">("confirming");

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
    // Failures are not turned into an error page: the payment already
    // happened at Stripe, so a failed finalisation just leaves the record
    // pending (exactly as today) — the render below shows a neutral
    // "couldn't confirm yet" notice instead. The guard is assigned before
    // the await so a StrictMode double-invoke sends only once.
    useEffect(() => {
        if (!sessionId || (!tenantId && !userId) || !accessToken) return;
        const key = `${sessionId}:${tenantId ?? `user:${userId}`}`;
        if (notifiedRef.current === key) return;
        notifiedRef.current = key;
        const client = getApiClient(accessToken).stripeCheckout;
        const request = tenantId
            ? client.hostCheckoutSuccessApiV1CheckoutsHostPaymentSuccessPost({ sessionId, tenantId })
            : client.tenantCheckoutSuccessApiV1CheckoutsTenantPaymentSuccessPost({ sessionId });
        // A failed POST clears the guard (but not after a confirmed one):
        // the token held at POST time may have been expired, and the
        // effect re-runs when the worker refresh populates a new token —
        // without this, a failed attempt would block any retry and the
        // page would sit on "couldn't confirm yet" even with a fresh
        // token. A confirmed POST keeps its guard, so a later token
        // rotation does not re-POST or regress the copy.
        request.then(() => setFinalisation("confirmed")).catch(() => {
            if (notifiedRef.current === key) notifiedRef.current = null;
            setFinalisation("unconfirmed");
        });
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

    // The success copy below is only shown once the finalisation POST has
    // resolved: before that (no token yet, or the POST in flight) the page
    // must not claim the payment succeeded, and after a failed POST it
    // must not claim it either — the record may still be pending.
    if (finalisation === "confirming") {
        return (
            <div>
                <h1>Checkout Success</h1>
                <p>We're confirming your payment. This only takes a moment — you can also check <Link to="/billing/checkouts">your billing page</Link> for its status.</p>
            </div>
        );
    }

    if (finalisation === "unconfirmed") {
        return (
            <div>
                <h1>Checkout Success</h1>
                <p>We couldn't confirm your payment just yet. If you completed the checkout, please check <Link to="/billing/checkouts">your billing page</Link> for its status.</p>
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
