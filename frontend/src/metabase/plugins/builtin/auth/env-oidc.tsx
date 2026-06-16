import { AuthButton } from "metabase/auth/components/AuthButton";
import {
  PLUGIN_AUTH_PROVIDERS,
  PLUGIN_IS_PASSWORD_USER,
} from "metabase/plugins";
import type { AuthProvider } from "metabase/plugins/types";
import MetabaseSettings from "metabase/utils/settings";
import type { OidcAuthProvider } from "metabase-types/api";

function startUrlFor(entry: OidcAuthProvider, redirectUrl?: string): string {
  const base = entry["sso-url"];
  if (!redirectUrl) {
    return base;
  }
  const joiner = base.includes("?") ? "&" : "?";
  return `${base}${joiner}redirect=${encodeURIComponent(redirectUrl)}`;
}

function envOidcProvider(entry: OidcAuthProvider): AuthProvider {
  const label = entry["login-prompt"] ?? "Login with SSO";

  return {
    name: `env-oidc-${entry.key}`,
    Button: ({ isCard, redirectUrl }) => (
      <AuthButton
        isCard={isCard}
        onClick={() => window.location.assign(startUrlFor(entry, redirectUrl))}
      >
        {label}
      </AuthButton>
    ),
  };
}

PLUGIN_AUTH_PROVIDERS.providers.push((providers) => {
  const entries: OidcAuthProvider[] =
    MetabaseSettings.get("oidc-login-providers") ?? [];

  if (entries.length === 0) {
    return providers;
  }

  return [...entries.map(envOidcProvider), ...providers];
});

PLUGIN_IS_PASSWORD_USER.push((user) => user.sso_source !== "oidc");
