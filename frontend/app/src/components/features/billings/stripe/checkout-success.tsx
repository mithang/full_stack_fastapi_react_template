import { Link, useSearchParams } from "react-router";

export function CheckoutSuccess() {
    const [searchParams] = useSearchParams();
    const sessionId = searchParams.get("session_id");

    // Stripe always appends ?session_id= to the success_url (see
    // billing_record_service), and the page is still a static stub: it does
    // not POST to the /checkouts/*/payment/success endpoint yet. Until that
    // finalisation step lands, a visit without a session id must not claim
    // a payment succeeded — that is a direct navigation, not a Stripe return.
    // Stripe also always appends ?tenant_id= (host checkout) or ?user_id=
    // (tenant checkout), so a session id with neither is likewise a
    // hand-crafted link, not a Stripe return — mirror the cancel-page guard
    // from iteration 159.
    if (!sessionId || (!searchParams.get("tenant_id") && !searchParams.get("user_id"))) {
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
