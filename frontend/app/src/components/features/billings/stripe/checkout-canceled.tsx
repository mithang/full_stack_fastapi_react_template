import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useAuthContext } from "@/components/providers/auth-provider";
import { getApiClient } from "@/lib/utils";

export function CheckoutCanceled() {
    const [searchParams] = useSearchParams();
    const { accessToken } = useAuthContext();
    const tenantId = searchParams.get("tenant_id");
    const userId = searchParams.get("user_id");
    const notifiedRef = useRef<string | null>(null);
    // "confirming" while no token is held yet or the finalisation POST is
    // in flight, "confirmed" once it resolves, "unconfirmed" if it fails.
    // Mirrors the CheckoutSuccess finalisation-state copy from iteration
    // 165: this page previously claimed a cancellation on query params
    // alone, before any finalisation had happened (or after it had
    // failed) — see the render below. A failed finalisation still shows
    // no error page: the cancellation already happened at Stripe, and the
    // billing page is the place to check its recorded status.
    const [finalisation, setFinalisation] = useState<"confirming" | "confirmed" | "unconfirmed">("confirming");
    // Manual retry counter for a failed finalisation (see the
    // "unconfirmed" render below): a transient failure (network blip,
    // backend hiccup) does not change the access token, so the effect
    // would otherwise never re-run and the page would sit on
    // "couldn't confirm yet" with no way back except a full reload.
    // Mirrors the CheckoutSuccess manual retry from iteration 169.
    const [retryAttempt, setRetryAttempt] = useState(0);
    // A payer whose session is gone (no refresh cookie, or an expired
    // one) never receives a token, so the "confirming" copy below would
    // otherwise sit forever: the worker refresh 403s (ignored by the
    // provider) or 401s (no bounce on this public route), and no
    // finalisation POST can run. After a generous wait — the immediate
    // worker refresh plus the POST normally resolve in seconds — show
    // a way out instead of an endless "confirming" message. This only
    // adds copy; it never changes the finalisation flow, and the hint
    // renders solely in the "confirming" branch, so a late confirmation
    // still replaces it. Mirrors the CheckoutSuccess stall hint from
    // iteration 172.
    const [confirmingTimedOut, setConfirmingTimedOut] = useState(false);
    useEffect(() => {
        // The stall timer restarts whenever the page re-enters
        // "confirming": it previously started once on mount, so after a
        // manual retry (which re-enters "confirming" from "unconfirmed")
        // the already-fired flag showed the "session may have expired"
        // hint immediately, even though the retry had only just started.
        // Resetting the flag here and restarting the timer gives each
        // confirmation attempt its own full 30 s; leaving "confirming"
        // (confirmed, or a fresh failure) clears the timer via cleanup.
        // Mirrors the CheckoutSuccess stall-timer restart from iteration
        // 174.
        if (finalisation !== "confirming") return;
        setConfirmingTimedOut(false);
        const timer = setTimeout(() => setConfirmingTimedOut(true), 30000);
        return () => clearTimeout(timer);
    }, [finalisation]);

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
    // Failures are not turned into an error page: the cancellation already
    // happened at Stripe, so a failed finalisation just leaves the record
    // pending (exactly as today) — the render below shows a neutral
    // "couldn't confirm yet" notice instead. The guard is assigned before
    // the await so a
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
        // A failed POST clears the guard (but not after a confirmed one):
        // the token held at POST time may have been expired, and the
        // effect re-runs when the worker refresh populates a new token —
        // without this, a failed attempt would block any retry and the
        // page would sit on "couldn't confirm yet" even with a fresh
        // token. A confirmed POST keeps its guard, so a later token
        // rotation does not re-POST or regress the copy. Mirrors the
        // CheckoutSuccess retry fix from iteration 167.
        request.then(() => setFinalisation("confirmed")).catch(() => {
            if (notifiedRef.current === key) notifiedRef.current = null;
            setFinalisation("unconfirmed");
        });
    }, [tenantId, userId, accessToken, retryAttempt]);

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

    // The canceled copy below is only shown once the finalisation POST has
    // resolved: before that (no token yet, or the POST in flight) the page
    // must not claim the payment was canceled, and after a failed POST it
    // must not claim it either — the record may still be pending.
    if (finalisation === "confirming") {
        return (
            <div>
                <h1>Checkout Canceled</h1>
                <p>We're confirming your cancellation. This only takes a moment — you can also check <Link to="/billing/checkouts">your billing page</Link> for its status.</p>
                {confirmingTimedOut && (
                    <p>Still confirming? Your session may have expired since you checked out — please <Link to="/login">sign in again</Link>, then check your billing page for the cancellation status.</p>
                )}
            </div>
        );
    }

    if (finalisation === "unconfirmed") {
        return (
            <div>
                <h1>Checkout Canceled</h1>
                <p>We couldn't confirm your cancellation just yet. If you canceled the checkout, please check <Link to="/billing/checkouts">your billing page</Link> for its status.</p>
                <p><button type="button" onClick={() => {
                    // Clear the guard before bumping the counter: the
                    // effect re-runs on retryAttempt and must not see
                    // the failed attempt's key, or it would return
                    // early and never re-POST. If no token is held at
                    // click time the effect early-returns and the page
                    // stays "confirming" until the worker refresh
                    // populates one, when the effect re-runs on
                    // accessToken and posts — it cannot get stuck in
                    // "unconfirmed" from this click. Mirrors the
                    // CheckoutSuccess manual retry from iteration 169.
                    notifiedRef.current = null;
                    setFinalisation("confirming");
                    setRetryAttempt((attempt) => attempt + 1);
                }}>Try confirming again</button></p>
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
