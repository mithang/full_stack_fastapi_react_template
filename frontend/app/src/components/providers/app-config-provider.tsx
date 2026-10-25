import { AppConfigurationDto, NotificationBannerSettingDto, TenantDto } from "@/api";
import { getApiClient, setTenant } from "@/lib/utils";
import { createContext, useContext, useEffect, useState, useCallback } from "react"
import { useAuthContext } from "./auth-provider";


export const AppConfigMessage = {
    type: "RELOAD_APP_CONFIG"
}
interface Configuration extends AppConfigurationDto {
    reloadAppConfig: () => Promise<void>;
    shouldShowTenantSelection?: boolean;
    redirectToTenantDomain: (tenant: TenantDto) => void;
    notificationBannerSetting: NotificationBannerSettingDto
}
const appConfigContext = createContext<Configuration>({
    is_multi_tenant_enabled: false,
    multi_tenancy_strategy: "none",
    host_main_domain: "",
    is_user_logged_in: false,
    user_preferences: {
        preferences: {},
        user_id: ""
    },
    reloadAppConfig: async () => { },
    redirectToTenantDomain: () => { },
    environment: "development",
    notificationBannerSetting: {
        is_enabled: false,
        message: "",
    }

});


interface AppConfigProviderProps {
    children: React.ReactNode;
}

export function AppConfigProvider({ children }: AppConfigProviderProps) {
    const { accessToken } = useAuthContext();


    const [appConfig, setAppConfig] = useState<AppConfigurationDto>({
        is_multi_tenant_enabled: false,
        multi_tenancy_strategy: "none",
        host_main_domain: "",
        is_user_logged_in: false,
        user_preferences: {
            preferences: {},
            user_id: ""
        },
        current_tenant: null,
        environment: "development"
    });
    const [shouldShowTenantSelection, setShouldShowTenantSelection] = useState(false);
    const [notificationBannerSetting, setNotificationBannerSetting] = useState<NotificationBannerSettingDto>({
        is_enabled: false,
        message: "",
    });

    const reloadAppConfig = useCallback(async function reloadAppConfig() {
        // Fetch the two pieces independently: Promise.all meant a
        // failure of the notification-banner endpoint discarded a
        // successfully fetched app configuration, and callers that toast
        // success before reloading (branding, SSO, tenant DNS) then
        // reported failure for an action that had actually succeeded.
        // Apply each part that succeeded; only a failed configuration
        // fetch still throws, since callers depend on the config itself.
        const [configResult, notificationResult] = await Promise.allSettled([
            getApiClient(accessToken).appConfiguration.getAppConfigurationApiV1AppConfigurationGet(),
            getApiClient(accessToken).notifications.getNotificationBannerApiV1NotificationsBannerGet()
        ]);
        if (configResult.status === "rejected") {
            throw configResult.reason;
        }
        setAppConfig(configResult.value)
        if (notificationResult.status === "fulfilled") {
            setNotificationBannerSetting(notificationResult.value);
        }
    }, [accessToken]);




    useEffect(() => {
        const fetchConfig = async () => {
            // Same split as reloadAppConfig above: a banner-endpoint
            // failure must not discard the configuration (tenant
            // selection and redirects depend on it), and a rejected
            // fetch must not surface as an unhandled rejection from
            // this effect, which has no caller to catch it.
            const [configResult, notificationResult] = await Promise.allSettled([
                getApiClient(accessToken).appConfiguration.getAppConfigurationApiV1AppConfigurationGet(),
                getApiClient(accessToken).notifications.getNotificationBannerApiV1NotificationsBannerGet()
            ]);
            if (configResult.status === "rejected") {
                console.error("Failed to fetch app configuration", configResult.reason);
                return;
            }
            setAppConfig(configResult.value)
            if (notificationResult.status === "fulfilled") {
                setNotificationBannerSetting(notificationResult.value);
            }
            if (configResult.value.is_multi_tenant_enabled === false) {
                setTenant(null);
            }


        };
        fetchConfig();
    }, [accessToken]);

    useEffect(() => {
        if (appConfig.is_multi_tenant_enabled && !appConfig.current_tenant) {
            setShouldShowTenantSelection(true);
        }
        if (appConfig.current_tenant) {
            setTenant(appConfig.current_tenant);

        }


    }, [appConfig, accessToken, appConfig.current_tenant]);




    const redirectToTenantDomain = useCallback((tenant: TenantDto) => {
        // No tenant domain to redirect to: TenantDto.subdomain is
        // nullable and custom_domain is optional, so without this guard
        // a tenant with neither would build "https://null" (template
        // string of null) and the else branch below would navigate
        // there, since any hostname differs from null. Stay put instead.
        if (!tenant.custom_domain && !tenant.subdomain) {
            return;
        }
        // environment is a dependency, not []: the initial appConfig
        // hardcodes "development", so an empty dependency array would
        // capture http + :3000 forever and, in production, redirect a
        // tenant selection / login to http://<domain>:3000 instead of
        // https://<domain> even after the config fetch reports
        // environment "production".
        const protocol = appConfig.environment === "development" ? "http" : "https";
        const port = appConfig.environment === "development" ? ":3000" : "";
        console.debug("Redirecting to tenant domain if needed:", tenant.custom_domain);
        const url = `${protocol}://${tenant.custom_domain || tenant.subdomain}${port}`;
        const currentHostname = window.location.hostname;
        console.debug("Current hostname:", currentHostname);
        console.debug("Target URL:", url);
        if (tenant.custom_domain) {
            if (currentHostname !== tenant.custom_domain) {
                console.debug("Redirecting to custom domain:", url);
                window.location.href = url;
                return
            }
        } else {
            if (currentHostname !== tenant.subdomain) {
                console.debug("Redirecting to subdomain:", url);

                window.location.href = url;
            }
        }

    }, [appConfig.environment])

    const value = {
        ...appConfig,
        reloadAppConfig,
        shouldShowTenantSelection,
        redirectToTenantDomain,
        notificationBannerSetting
    }

    return (
        <appConfigContext.Provider value={value}>
            {children}
        </appConfigContext.Provider>
    )
}

export function useAppConfig() {
    const context = useContext(appConfigContext);
    if (!context) {
        throw new Error("useAppConfig must be used within an AppConfigProvider");
    }
    return context;
}
