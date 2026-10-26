import { Link, useSearchParams } from "react-router";

export function CheckoutCanceled() {
    const [searchParams] = useSearchParams();

    // Stripe always appends ?tenant_id= (host checkout) or ?user_id=
    // (tenant checkout) to the cancel_url (see billing_record_service).
    // Mirror the CheckoutSuccess guard from iteration 157: a visit with
    // neither parameter must not claim a payment was canceled — that is
    // a direct navigation, not a Stripe return.
    if (!searchParams.get("tenant_id") && !searchParams.get("user_id")) {
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