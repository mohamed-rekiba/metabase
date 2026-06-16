import { AuthButton } from "metabase/auth/components/AuthButton";
import { SettingsOidcForm } from "metabase/admin/settings/auth/components/SettingsOidcForm";
import { OidcAuthCard } from "metabase/admin/settings/auth/containers/OidcAuthCard";
import {
  PLUGIN_AUTH_PROVIDERS,
  PLUGIN_IS_PASSWORD_USER,
} from "metabase/plugins";
import type { AuthProvider } from "metabase/plugins/types";
import MetabaseSettings from "metabase/utils/settings";
import type { OidcAuthProvider } from "metabase-types/api";

function loginUrl(entry: OidcAuthProvider, redirectUrl?: string): string {
  const base = entry["sso-url"];
  if (!redirectUrl) {
    return base;
  }
  const separator = base.includes("?") ? "&" : "?";
  return `${base}${separator}redirect=${encodeURIComponent(redirectUrl)}`;
}

function oidcLoginProvider(entry: OidcAuthProvider): AuthProvider {
  const label = entry["login-prompt"] ?? "Login with SSO";

  return {
    name: `oidc-${entry.key}`,
    Button: ({ isCard, redirectUrl }) => (
      <AuthButton
        isCard={isCard}
        onClick={() => window.location.assign(loginUrl(entry, redirectUrl))}
      >
        {label}
      </AuthButton>
    ),
  };
}

PLUGIN_AUTH_PROVIDERS.SettingsOIDCForm = SettingsOidcForm;

PLUGIN_AUTH_PROVIDERS.providers.push((providers) => {
  const entries: OidcAuthProvider[] =
    MetabaseSettings.get("oidc-login-providers") ?? [];

  if (entries.length === 0) {
    return providers;
  }

  return [...entries.map(oidcLoginProvider), ...providers];
});

PLUGIN_IS_PASSWORD_USER.push((user) => user.sso_source !== "oidc");

export { OidcAuthCard };
