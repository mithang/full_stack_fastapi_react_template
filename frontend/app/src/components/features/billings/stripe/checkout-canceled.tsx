import { Link } from "react-router";

export function CheckoutCanceled() {
    return (
        <div>
            <h1>Checkout Canceled</h1>
            <p>Your payment was canceled. You can try again or contact support if you need assistance.</p>
            <p><Link to="/billing/checkouts">View your checkouts</Link></p>
        </div>
    );
}