(ns metabase.sso.integrations.env-oidc
  "GET handlers for MB_OIDC_PROVIDERS SSO at /auth/sso/:provider-key.

   Structured like metabase.sso.integrations.slack-connect."
  (:require
   [java-time.api :as t]
   [metabase.api.common :as api]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.request.core :as request]
   [metabase.sso.core :as sso]
   [metabase.sso.providers.slack-connect :as slack-connect.provider]
   [metabase.sso.settings :as sso-settings]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [ring.util.response :as response]))

(set! *warn-on-reflection* true)

(def ^:private blocked-provider-keys
  #{"slack-connect"})

(defn- callback-uri
  [provider-key]
  (str (system/site-url) "/auth/sso/" provider-key "/callback"))

(defn- ensure-ready!
  [provider-key]
  (api/check-400 (sso-settings/oidc-enabled) "OIDC is not enabled")
  (when (contains? blocked-provider-keys provider-key)
    (throw (ex-info (tru "OIDC provider key ''{0}'' is reserved" provider-key)
                    {:status-code 400})))
  (let [entry (sso-settings/lookup-env-oidc-provider provider-key)]
    (when-not entry
      (throw (ex-info (tru "OIDC provider ''{0}'' not found" provider-key)
                      {:status-code 404})))
    (when-not (sso-settings/env-oidc-provider-active? entry)
      (throw (ex-info (tru "OIDC provider ''{0}'' is not enabled" provider-key)
                      {:status-code 400})))))

(defn sso-initiate
  [provider-key request]
  (ensure-ready! provider-key)
  (let [{:keys [redirect]} (:params request)
        final-redirect (if redirect
                         (slack-connect.provider/check-sso-redirect redirect)
                         "/")
        auth-result (auth-identity/authenticate
                     :provider/env-oidc
                     (assoc request
                            :oidc-provider-key provider-key
                            :redirect-uri (callback-uri provider-key)
                            :final-redirect final-redirect))]
    (cond
      (= :redirect (:success? auth-result))
      (sso/wrap-oidc-redirect auth-result
                              request
                              (keyword (str "oidc-" provider-key))
                              final-redirect
                              {:browser-id (:browser-id request)})

      :else
      (throw (ex-info (or (:message auth-result) (tru "Failed to initiate OIDC authentication"))
                      {:status-code 500})))))

(defn sso-callback
  [provider-key request]
  (ensure-ready! provider-key)
  (let [{:keys [code state]} (:params request)
        login-result (auth-identity/login!
                      :provider/env-oidc
                      (assoc request
                             :oidc-provider-key provider-key
                             :code code
                             :state state
                             :oidc-provider (keyword (str "oidc-" provider-key))
                             :redirect-uri (callback-uri provider-key)
                             :device-info (request/device-info request)))]
    (cond
      (:success? login-result)
      (let [final-redirect (or (:redirect-url login-result) "/")
            base-response (-> (response/redirect final-redirect)
                              (sso/clear-oidc-state-cookie))]
        (log/infof "OIDC authentication successful for provider %s, user %s"
                   provider-key (get-in login-result [:user :email]))
        (if-let [session (:session login-result)]
          (request/set-session-cookies request
                                       base-response
                                       session
                                       (t/zoned-date-time (t/zone-id "GMT")))
          base-response))

      :else
      (let [error-msg (or (:message login-result) (tru "OIDC authentication failed"))]
        (log/errorf "OIDC authentication failed for provider %s: %s" provider-key error-msg)
        (throw (ex-info error-msg {:status-code 401}))))))
