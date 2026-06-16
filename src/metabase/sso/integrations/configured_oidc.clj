(ns metabase.sso.integrations.configured-oidc
  "Browser SSO endpoints at /auth/sso/:provider-key."
  (:require
   [java-time.api :as t]
   [metabase.api.common :as api]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.request.core :as request]
   [metabase.sso.core :as sso]
   [metabase.sso.oidc.util :as oidc.util]
   [metabase.sso.settings :as sso-settings]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [ring.util.response :as response]))

(set! *warn-on-reflection* true)

(def ^:private reserved-provider-keys
  #{"slack-connect"})

(defn- callback-uri
  [provider-key]
  (str (system/site-url) "/auth/sso/" provider-key "/callback"))

(defn- ensure-provider-ready!
  [provider-key]
  (api/check-400 (sso-settings/oidc-enabled) "OIDC is not enabled")
  (when (contains? reserved-provider-keys provider-key)
    (throw (ex-info (tru "OIDC provider key ''{0}'' is reserved" provider-key)
                    {:status-code 400})))
  (let [provider (sso-settings/get-oidc-provider provider-key)]
    (when-not provider
      (throw (ex-info (tru "OIDC provider ''{0}'' not found" provider-key)
                      {:status-code 404})))
    (when-not (oidc.util/provider-enabled? provider)
      (throw (ex-info (tru "OIDC provider ''{0}'' is not enabled" provider-key)
                      {:status-code 400})))))

(defn sso-initiate
  [provider-key request]
  (ensure-provider-ready! provider-key)
  (let [redirect-param (get-in request [:params :redirect])
        final-redirect (if redirect-param
                         (oidc.util/validate-login-redirect! redirect-param)
                         "/")
        auth-result    (auth-identity/authenticate
                        :provider/configured-oidc
                        (assoc request
                               :oidc-provider-key provider-key
                               :redirect-uri (callback-uri provider-key)
                               :final-redirect final-redirect))]
    (if (= :redirect (:success? auth-result))
      (sso/wrap-oidc-redirect auth-result
                              request
                              (keyword (str "oidc-" provider-key))
                              final-redirect
                              {:browser-id (:browser-id request)})
      (throw (ex-info (or (:message auth-result) (tru "Failed to initiate OIDC authentication"))
                      {:status-code 500})))))

(defn sso-callback
  [provider-key request]
  (ensure-provider-ready! provider-key)
  (let [{:keys [code state]} (:params request)
        login-result (auth-identity/login!
                      :provider/configured-oidc
                      (assoc request
                             :oidc-provider-key provider-key
                             :code code
                             :state state
                             :oidc-provider (keyword (str "oidc-" provider-key))
                             :redirect-uri (callback-uri provider-key)
                             :device-info (request/device-info request)))]
    (if (:success? login-result)
      (let [final-redirect (or (:redirect-url login-result) "/")
            base-response  (-> (response/redirect final-redirect)
                               (sso/clear-oidc-state-cookie))]
        (log/infof "OIDC authentication successful for provider %s, user %s"
                   provider-key (get-in login-result [:user :email]))
        (if-let [session (:session login-result)]
          (request/set-session-cookies request
                                       base-response
                                       session
                                       (t/zoned-date-time (t/zone-id "GMT")))
          base-response))
      (let [error-msg (or (:message login-result) (tru "OIDC authentication failed"))]
        (log/errorf "OIDC authentication failed for provider %s: %s" provider-key error-msg)
        (throw (ex-info error-msg {:status-code 401}))))))
