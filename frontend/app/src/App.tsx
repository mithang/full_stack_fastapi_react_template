import { Routes, Route, Navigate, useLocation } from "react-router";
import { DefaultLayout } from "@/components/layouts/default-layout";
import { Login } from "@/components/features/auth/login";
import { Dashboard } from "@/components/features/dashboard/dashboard";
import { DashboardLayout } from "@/components/layouts/dashboard-layout";
import { Profile } from "@/components/features/profile/profile";
import { Roles } from "@/components/features/roles/roles";
import { Users } from "@/components/features/users/users";
import Register from "@/components/features/auth/register";
import { UsersProvider } from "@/components/providers/users-provider";
import { RolesProvider } from "@/components/providers/roles-provider";
import { AIChat } from "@/components/features/ai-chat/ai-chat";
import { TenantsProvider } from "@/components/providers/tenant-provider";
import { Tenants } from "@/components/features/tenant/tenant";
import { SettingsProvider } from "@/components/providers/settings-provider";
import { Settings } from "@/components/features/settings/settings";
import { useAuthContext } from "./components/providers/auth-provider";
import { AIChatProvider } from "@/components/providers/ai-chat-provider";
import { PasswordResetRequest } from "@/components/features/auth/password-reset-request";
import { PasswordResetConfirmation } from "@/components/features/auth/password_reset_confirmation";
import { Activation } from "@/components/features/auth/activation";
import { TenantSetting } from "@/components/features/tenant/tenant-setting";
import { MagicLinkLoginValidate } from "@/components/features/auth/magic-link-login-validate";
import { NonActiveTenantView } from "@/components/shared/non-active-tenant-view";
import { StripeProvider } from "@/components/providers/stripe-provider";
import { ConfigureStripe } from "@/components/features/billings/stripe/configure-stripe";
import { BillingOverview } from "@/components/features/billings/stripe/billing-overview";
import { Billing } from "@/components/features/billings/stripe/billing";
import { Invoices } from "@/components/features/billings/stripe/invoices";
import { Products } from "@/components/features/billings/stripe/products";
import { CheckoutOverview } from "@/components/features/billings/stripe/checkout-overview";
import { CheckoutSuccess } from "@/components/features/billings/stripe/checkout-success";
import { CheckoutCanceled } from "@/components/features/billings/stripe/checkout-canceled";
import { AppSettings } from "@/components/features/settings/app-settings";
import { AuditLogProvider } from "@/components/providers/audit-log-provider";
import { AuditLogs } from "@/components/features/audit-logs/audit-logs";
import { SettingsLayout } from "./components/features/settings/settings-layout";
import { useAppConfig } from "./components/providers/app-config-provider";
import { useEffect } from "react";
import { updateThemeConfiguration } from "./lib/utils";
import { useTheme } from "@/components/providers/theme-provider"

// Every route previously kept the static index.html title ("Full Stack
// FastAPI React"), so screen-reader and tab users could not tell pages
// apart (WCAG 2.4.2 Page Titled). Set document.title from the current
// route on navigation; unknown paths keep the default title. Keys are
// matched exactly (trailing slashes stripped), so no route needs its
// own title effect and a new route only adds one map entry.
const PAGE_TITLES: Record<string, string> = {
  "/login": "Sign in",
  "/register": "Register",
  "/forgot-password": "Forgot password",
  "/password_reset_confirmation": "Reset password",
  "/activation": "Activate account",
  "/magic_link_login": "Magic link login",
  "/non-active": "Account inactive",
  "/checkout/success": "Checkout successful",
  "/checkout/cancel": "Checkout cancelled",
  "/dashboard": "Dashboard",
  "/users": "Users",
  "/roles": "Roles",
  "/tenants": "Tenants",
  "/audit-logs": "Audit logs",
  "/settings/storage": "Storage settings",
  "/settings/general": "General settings",
  "/settings/payment": "Payment settings",
  "/settings/notifications": "Notification settings",
  "/settings/sso": "SSO settings",
  "/billing": "Billing",
  "/billing/invoices": "Invoices",
  "/billing/products": "Products",
  "/billing/checkouts": "Checkouts",
  "/profile": "Profile",
  "/ai": "AI chat",
};

function PageTitle() {
  const { pathname } = useLocation();

  useEffect(() => {
    const page = PAGE_TITLES[pathname.replace(/\/+$/, "") || "/"];
    document.title = page ? `${page} | Full Stack FastAPI React` : "Full Stack FastAPI React";
  }, [pathname]);
  return null;
}

function App() {
  const { user } = useAuthContext();
  const { branding } = useAppConfig();
  const { theme } = useTheme()

  useEffect(() => {
    updateThemeConfiguration(branding);
  }, [branding, theme]);
  return (
    <>
    <PageTitle />
    <Routes>
      <Route element={<DefaultLayout />}>
        <Route index path="login" element={<Login />} />
        <Route path="register" element={<Register />} />
        <Route path="forgot-password" element={<PasswordResetRequest />} />
        <Route path="password_reset_confirmation" element={<PasswordResetConfirmation />} />
        <Route path="activation" element={<Activation />} />
        <Route path="magic_link_login" element={<MagicLinkLoginValidate />} />
        <Route path="non-active" element={<NonActiveTenantView />} />
        {/* Stripe returns here after checkout (see the success_url /
        cancel_url built in billing_record_service): without these routes
        the DashboardLayout catch-all below silently redirected a
        returning payer to /dashboard, so the confirmation pages never
        rendered. They are static pages under the public layout, so they
        render regardless of auth state; the success POST that finalises
        a session is still a separate, later step. */}
        <Route path="checkout/success" element={<CheckoutSuccess />} />
        <Route path="checkout/cancel" element={<CheckoutCanceled />} />
      </Route>

      <Route element={<DashboardLayout />}>
        <Route index path="dashboard" element={<Dashboard />} />
        <Route path="users" element={
          <UsersProvider>
            <Users />
          </UsersProvider>
        }
        />
        <Route path="roles" element={
          <RolesProvider>
            <Roles />
          </RolesProvider>
        }
        />
        {!user?.tenant_id && (
          <Route path="tenants" element={
            <TenantsProvider>
              <Tenants />
            </TenantsProvider>
          }
          />
        )}
        <Route path="audit-logs" element={
          <AuditLogProvider>
            <AuditLogs />
          </AuditLogProvider>
        }
        />

        <Route path="settings" element={<SettingsLayout />}>
          <Route index element={<Navigate to="/settings/storage" />} />
          <Route path="storage" element={
            <SettingsProvider>
              <Settings />
            </SettingsProvider>
          } />

          <Route path="general" element={
            <SettingsProvider>
              <TenantsProvider>
                <TenantSetting />
              </TenantsProvider>
            </SettingsProvider>
          } />

          <Route path="payment" element={
            <StripeProvider>
              <ConfigureStripe />
            </StripeProvider>
          } />

          <Route path="notifications" element={
            <AppSettings />
          } />
          <Route path="sso" element={
            <AppSettings />
          } />

        </Route>

        <Route path="billing" element={<Billing />}>
          <Route index element={<BillingOverview />} />
          <Route path="invoices" element={<Invoices />} />
          <Route path="products" element={<Products />} />
          <Route path="checkouts" element={<CheckoutOverview />} />
        </Route>

        <Route path="profile" element={<Profile />} />
        <Route path="ai" element={
          <AIChatProvider>
            <AIChat />
          </AIChatProvider>
        } />

        <Route path="*" element={<Navigate to="/dashboard" />} />
      </Route>
    </Routes>
    </>
  )
}

export default App
