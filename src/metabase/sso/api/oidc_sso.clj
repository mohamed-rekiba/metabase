(ns metabase.sso.api.oidc-sso
  "Browser SSO routes at /auth/sso/:provider-key."
  (:require
   [metabase.api.macros :as api.macros]
   [metabase.sso.integrations.configured-oidc :as configured-oidc]
   [metabase.util.log :as log]))

(def ^:private ProviderKey
  [:string {:api/regex #"[a-z0-9][a-z0-9-]*"}])

;; GET /auth/sso/:provider-key
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/:key"
  "Start OIDC login for a configured provider."
  [{provider-key :key} :- [:map [:key ProviderKey]]
   _query-params _body request]
  (try
    (configured-oidc/sso-initiate provider-key request)
    (catch Throwable e
      (log/error e "Error initiating OIDC SSO")
      (throw e))))

;; GET /auth/sso/:provider-key/callback
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/:key/callback"
  "Handle the OIDC callback for a configured provider."
  [{provider-key :key} :- [:map [:key ProviderKey]]
   _query-params _body request]
  (try
    (configured-oidc/sso-callback provider-key request)
    (catch Throwable e
      (log/error e "Error handling OIDC callback")
      (throw e))))

(def ^{:arglists '([request respond raise])} routes
  "`/auth/sso/:provider-key` routes."
  (api.macros/ns-handler *ns*))
