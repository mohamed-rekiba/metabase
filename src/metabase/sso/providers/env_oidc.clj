(ns metabase.sso.providers.env-oidc
  "OIDC login for IdPs declared in MB_OIDC_PROVIDERS.
   Same layering as Slack Connect: env-specific config, then :provider/oidc."
  (:require
   [clojure.string :as str]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.sso.settings :as sso-settings]
   [metabase.util.i18n :refer [tru]]
   [methodical.core :as methodical]))

(set! *warn-on-reflection* true)

(derive :provider/env-oidc :provider/oidc)

(defn- read-entry
  [entry field]
  (let [kw (keyword field)]
    (or (get entry kw) (get entry (name kw)) (get entry field))))

(defn- claim-mapping
  [attribute-map claim]
  (when attribute-map
    (or (get attribute-map claim)
        (get attribute-map (name claim))
        (get attribute-map (keyword claim)))))

(defn- runtime-oidc-options
  [entry request]
  (when (and (read-entry entry :client-id)
             (read-entry entry :client-secret)
             (read-entry entry :issuer-uri))
    (let [attrs (or (read-entry entry :attribute-map) {})]
      (cond-> {:client-id     (read-entry entry :client-id)
               :client-secret (read-entry entry :client-secret)
               :issuer-uri    (read-entry entry :issuer-uri)
               :scopes        (or (read-entry entry :scopes)
                                  ["openid" "email" "profile"])
               :redirect-uri  (:redirect-uri request)}
        (claim-mapping attrs :email)
        (assoc :attribute-email (claim-mapping attrs :email))

        (claim-mapping attrs :first_name)
        (assoc :attribute-firstname (claim-mapping attrs :first_name))

        (claim-mapping attrs :last_name)
        (assoc :attribute-lastname (claim-mapping attrs :last_name))))))

(defn- reject-missing-account!
  []
  (when-not (sso-settings/oidc-user-provisioning-enabled?)
    (throw (ex-info (tru "Sorry, but you''ll need a Metabase account to view this page. Please contact your administrator.")
                    {:status-code 401}))))

(methodical/defmethod auth-identity/authenticate :provider/env-oidc
  [_provider request]
  (cond
    (not (sso-settings/oidc-enabled))
    {:success? false
     :error :oidc-not-enabled
     :message (tru "OIDC authentication is not enabled")}

    (str/blank? (some-> (:oidc-provider-key request) str))
    {:success? false
     :error :missing-provider
     :message (tru "OIDC provider key is required")}

    :else
    (let [provider-key (:oidc-provider-key request)
          entry        (sso-settings/lookup-env-oidc-provider provider-key)]
      (cond
        (nil? entry)
        {:success? false
         :error :provider-not-found
         :message (tru "OIDC provider ''{0}'' not found" provider-key)}

        (not (sso-settings/env-oidc-provider-active? entry))
        {:success? false
         :error :provider-not-enabled
         :message (tru "OIDC provider ''{0}'' is not enabled" provider-key)}

        :else
        (if-let [runtime (runtime-oidc-options entry request)]
          (let [result (next-method _provider (assoc request :oidc-config runtime))]
            (if (and (:success? result) (:user-data result))
              (assoc-in result [:user-data :sso_source] :oidc)
              result))
          {:success? false
           :error :configuration-error
           :message (tru "Failed to build OIDC configuration for provider ''{0}''" provider-key)})))))

(methodical/defmethod auth-identity/login! :provider/env-oidc
  [provider {:keys [user] :as request}]
  (when-not user
    (reject-missing-account!))
  (next-method provider request))
