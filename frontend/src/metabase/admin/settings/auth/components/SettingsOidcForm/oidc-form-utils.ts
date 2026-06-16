import { t } from "ttag";
import * as Yup from "yup";

import type { OidcProviderConfig } from "metabase/api/sso-oidc";

export interface OidcFormValues {
  "login-prompt": string;
  key: string;
  "issuer-uri": string;
  "client-id": string;
  "client-secret": string | null;
  scopes: string | null;
  "attribute-email": string | null;
  "attribute-firstname": string | null;
  "attribute-lastname": string | null;
  "group-sync-enabled": boolean;
  "group-attribute": string | null;
}

export function oidcFormSchema() {
  return Yup.object({
    "login-prompt": Yup.string().required(t`Login prompt is required`),
    key: Yup.string()
      .required(t`Key is required`)
      .matches(
        /^[a-z0-9][a-z0-9-]*$/,
        t`Must be lowercase letters, numbers, and hyphens only`,
      ),
    "issuer-uri": Yup.string().required(t`Issuer URI is required`),
    "client-id": Yup.string().required(t`Client ID is required`),
    "client-secret": Yup.string().nullable().default(null),
    scopes: Yup.string().nullable().default("openid, email, profile"),
    "attribute-email": Yup.string().nullable().default("email"),
    "attribute-firstname": Yup.string().nullable().default("given_name"),
    "attribute-lastname": Yup.string().nullable().default("family_name"),
    "group-sync-enabled": Yup.boolean().default(false),
    "group-attribute": Yup.string().nullable().default("groups"),
  });
}

export function providerToFormValues(
  provider: OidcProviderConfig | null,
): OidcFormValues {
  if (!provider) {
    return {
      "login-prompt": "",
      key: "",
      "issuer-uri": "",
      "client-id": "",
      "client-secret": null,
      scopes: "openid, email, profile",
      "attribute-email": "email",
      "attribute-firstname": "given_name",
      "attribute-lastname": "family_name",
      "group-sync-enabled": false,
      "group-attribute": "groups",
    };
  }

  const attributeMap = provider["attribute-map"] ?? {};
  const groupSync = provider["group-sync"] ?? {};

  return {
    "login-prompt": provider["login-prompt"] ?? "",
    key: provider.key ?? "",
    "issuer-uri": provider["issuer-uri"] ?? "",
    "client-id": provider["client-id"] ?? "",
    "client-secret": null,
    scopes: (provider.scopes ?? ["openid", "email", "profile"]).join(", "),
    "attribute-email": attributeMap.email ?? "email",
    "attribute-firstname": attributeMap.first_name ?? "given_name",
    "attribute-lastname": attributeMap.last_name ?? "family_name",
    "group-sync-enabled": groupSync.enabled ?? false,
    "group-attribute": groupSync["group-attribute"] ?? "groups",
  };
}

export function formValuesToProvider(
  values: OidcFormValues,
  groupMappings: Record<string, number[]>,
): Partial<OidcProviderConfig> {
  const scopes = values.scopes
    ? values.scopes
        .split(",")
        .map((scope) => scope.trim())
        .filter(Boolean)
    : ["openid", "email", "profile"];

  const attributeMap: Record<string, string> = {};
  if (values["attribute-email"]) {
    attributeMap.email = values["attribute-email"];
  }
  if (values["attribute-firstname"]) {
    attributeMap.first_name = values["attribute-firstname"];
  }
  if (values["attribute-lastname"]) {
    attributeMap.last_name = values["attribute-lastname"];
  }

  const provider: Partial<OidcProviderConfig> = {
    key: values.key,
    "login-prompt": values["login-prompt"],
    "issuer-uri": values["issuer-uri"],
    "client-id": values["client-id"],
    scopes,
    enabled: true,
    "attribute-map": attributeMap,
    "group-sync": {
      enabled: values["group-sync-enabled"],
      "group-attribute": values["group-attribute"] ?? undefined,
      "group-mappings": groupMappings,
    },
  };

  if (values["client-secret"]) {
    provider["client-secret"] = values["client-secret"];
  }

  return provider;
}
