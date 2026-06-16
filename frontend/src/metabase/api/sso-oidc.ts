import { invalidateTags, tag } from "metabase/api/tags";

import { Api } from "./api";

export interface OidcConnectionCheckRequest {
  "issuer-uri": string;
  "client-id": string;
  "client-secret"?: string | null;
  key?: string | null;
}

export interface OidcConnectionCheckStep {
  step: string;
  success: boolean;
  verified?: boolean;
  error?: string;
  "token-endpoint"?: string;
}

export interface OidcConnectionCheckResponse {
  ok: boolean;
  discovery: OidcConnectionCheckStep;
  credentials?: OidcConnectionCheckStep;
}

export interface OidcProviderConfig {
  key: string;
  "login-prompt": string;
  "issuer-uri": string;
  "client-id": string;
  "client-secret"?: string;
  scopes?: string[];
  enabled?: boolean;
  "attribute-map"?: Record<string, string>;
  "group-sync"?: {
    enabled?: boolean;
    "group-attribute"?: string;
    "group-mappings"?: Record<string, number[]>;
  };
}

export const ssoOidcApi = Api.injectEndpoints({
  endpoints: (builder) => ({
    listOidcProviders: builder.query<OidcProviderConfig[], void>({
      query: () => ({
        method: "GET",
        url: "/api/sso/oidc",
      }),
      providesTags: ["session-properties"],
    }),
    getOidcProvider: builder.query<OidcProviderConfig, string>({
      query: (key) => ({
        method: "GET",
        url: `/api/sso/oidc/${key}`,
      }),
      providesTags: ["session-properties"],
    }),
    createOidcProvider: builder.mutation<OidcProviderConfig, OidcProviderConfig>({
      query: (provider) => ({
        method: "POST",
        url: "/api/sso/oidc",
        body: provider,
      }),
      invalidatesTags: (_, error) =>
        invalidateTags(error, [tag("session-properties")]),
    }),
    updateOidcProvider: builder.mutation<
      OidcProviderConfig,
      { key: string; provider: Partial<OidcProviderConfig> }
    >({
      query: ({ key, provider }) => ({
        method: "PUT",
        url: `/api/sso/oidc/${key}`,
        body: provider,
      }),
      invalidatesTags: (_, error) =>
        invalidateTags(error, [tag("session-properties")]),
    }),
    deleteOidcProvider: builder.mutation<void, string>({
      query: (key) => ({
        method: "DELETE",
        url: `/api/sso/oidc/${key}`,
      }),
      invalidatesTags: (_, error) =>
        invalidateTags(error, [tag("session-properties")]),
    }),
    checkOidcConnection: builder.mutation<
      OidcConnectionCheckResponse,
      OidcConnectionCheckRequest
    >({
      query: (body) => ({
        method: "POST",
        url: "/api/sso/oidc/check",
        body,
      }),
    }),
  }),
});

export const {
  useListOidcProvidersQuery,
  useGetOidcProviderQuery,
  useCreateOidcProviderMutation,
  useUpdateOidcProviderMutation,
  useDeleteOidcProviderMutation,
  useCheckOidcConnectionMutation,
} = ssoOidcApi;
