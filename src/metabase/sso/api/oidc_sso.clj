(ns metabase.sso.api.oidc-sso
  "API routes for env-configured OIDC SSO (/auth/sso/:provider-key)."
  (:require
   [metabase.api.macros :as api.macros]
   [metabase.sso.integrations.env-oidc :as env-oidc-integration]
   [metabase.util.log :as log]))

(def ^:private ProviderKey
  [:string {:api/regex #"[a-z0-9][a-z0-9-]*"}])

;; GET /auth/sso/:provider-key
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/:key"
  "Start OIDC login for a provider from MB_OIDC_PROVIDERS."
  [{provider-key :key} :- [:map [:key ProviderKey]]
   _query-params _body request]
  (try
    (env-oidc-integration/sso-initiate provider-key request)
    (catch Throwable e
      (log/error e "Error initiating env OIDC SSO")
      (throw e))))

;; GET /auth/sso/:provider-key/callback
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/:key/callback"
  "OIDC callback for a provider from MB_OIDC_PROVIDERS."
  [{provider-key :key} :- [:map [:key ProviderKey]]
   _query-params _body request]
  (try
    (env-oidc-integration/sso-callback provider-key request)
    (catch Throwable e
      (log/error e "Error handling env OIDC callback")
      (throw e))))

(def ^{:arglists '([request respond raise])} routes
  "`/auth/sso/:provider-key` routes for env-configured OIDC."
  (api.macros/ns-handler *ns*))
